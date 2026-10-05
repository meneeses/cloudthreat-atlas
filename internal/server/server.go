package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/collector"
	"github.com/meneeses/cloudthreat-atlas/internal/comparison"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/simulation"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

const (
	pagesBasePath      = "/cloudthreat-atlas"
	maxFindingIDFilter = 200
)

// Analyzer is the analysis service contract needed by the HTTP API.
type Analyzer interface {
	Analyze(ctx context.Context, input model.Snapshot) (model.Snapshot, error)
}

// API serves one local snapshot and optionally a compiled single-page application.
type API struct {
	snapshot     model.Snapshot
	analyzer     Analyzer
	store        *workspace.Store
	secure       bool
	csrfToken    string
	sessionToken string
	staticFS     fs.FS
	static       http.Handler
	scanner      ScanCollector
	scans        *scanCoordinator
}

// New constructs the API and ensures the initial snapshot is fully analyzed.
func New(ctx context.Context, source model.Snapshot, analyzer Analyzer, webDir string) (*API, error) {
	snapshot, err := analyzer.Analyze(ctx, source)
	if err != nil {
		return nil, err
	}
	staticFS := embeddedWebFS()
	if webDir != "" {
		index := filepath.Join(webDir, "index.html")
		info, statErr := os.Stat(index)
		if statErr != nil {
			return nil, fmt.Errorf("open dashboard override %q: %w", webDir, statErr)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("open dashboard override %q: index.html is not a regular file", webDir)
		}
		staticFS = os.DirFS(webDir)
	}
	api := &API{
		snapshot: snapshot,
		analyzer: analyzer,
		staticFS: staticFS,
		static:   http.FileServer(http.FS(staticFS)),
	}
	return api, nil
}

// NewWorkspace constructs a multi-snapshot local API backed by a private workspace.
func NewWorkspace(store *workspace.Store, analyzer Analyzer, webDir string) (*API, error) {
	return NewWorkspaceWithCollector(store, analyzer, webDir, collector.AzureResourceGraph{})
}

// NewWorkspaceWithCollector allows tests and alternate read-only collectors to
// use the workspace job runner without changing its persistence contract.
func NewWorkspaceWithCollector(store *workspace.Store, analyzer Analyzer, webDir string, scanner ScanCollector) (*API, error) {
	if store == nil {
		return nil, errors.New("workspace store is required")
	}
	if analyzer == nil {
		return nil, errors.New("workspace analyzer is required")
	}
	if scanner == nil {
		return nil, errors.New("workspace scan collector is required")
	}
	if err := store.InterruptRunningJobs(context.Background()); err != nil {
		return nil, fmt.Errorf("recover interrupted scan jobs: %w", err)
	}
	staticFS, static, err := loadStatic(webDir)
	if err != nil {
		return nil, err
	}
	csrfToken, err := randomToken("CSRF")
	if err != nil {
		return nil, err
	}
	sessionToken, err := randomToken("workspace session")
	if err != nil {
		return nil, err
	}
	return &API{
		analyzer: analyzer, store: store, secure: true,
		csrfToken: csrfToken, sessionToken: sessionToken,
		staticFS: staticFS, static: static, scanner: scanner, scans: &scanCoordinator{},
	}, nil
}

func randomToken(label string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate %s token: %w", label, err)
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

// LaunchURL returns the authenticated browser entrypoint for a private local
// workspace. The credential is carried in the URL fragment so browsers never
// include it in an HTTP request, access log, or Referer header.
func (a *API) LaunchURL(baseURL string) (string, error) {
	if !a.secure || a.sessionToken == "" {
		return "", errors.New("workspace session is unavailable")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse workspace URL: %w", err)
	}
	if parsed.Scheme != "http" || parsed.Host == "" {
		return "", errors.New("workspace URL must be an absolute HTTP URL")
	}
	hostName := parsed.Hostname()
	if hostName != "localhost" {
		ip := net.ParseIP(hostName)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("workspace URL must use a loopback host")
		}
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		return "", fmt.Errorf("parse workspace URL fragment: %w", err)
	}
	fragment.Set("atlas-session", a.sessionToken)
	parsed.Fragment = fragment.Encode()
	return parsed.String(), nil
}

// Close stops background scan work and waits until it has written its final
// durable state. Call it before closing the workspace store.
func (a *API) Close() error {
	if a.scans == nil {
		return nil
	}
	a.scans.mu.Lock()
	a.scans.closed = true
	cancel := a.scans.cancel
	a.scans.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.scans.wg.Wait()
	a.scans.mu.Lock()
	defer a.scans.mu.Unlock()
	return a.scans.firstErr
}

func loadStatic(webDir string) (fs.FS, http.Handler, error) {
	staticFS := embeddedWebFS()
	if webDir != "" {
		index := filepath.Join(webDir, "index.html")
		info, statErr := os.Stat(index)
		if statErr != nil {
			return nil, nil, fmt.Errorf("open dashboard override %q: %w", webDir, statErr)
		}
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("open dashboard override %q: index.html is not a regular file", webDir)
		}
		staticFS = os.DirFS(webDir)
	}
	return staticFS, http.FileServer(http.FS(staticFS)), nil
}

// Handler returns the complete API and SPA handler.
func (a *API) Handler() http.Handler { return a }

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if a.secure && !a.acceptLocalRequest(w, r) {
		return
	}
	if r.URL.Path == "/healthz" {
		a.health(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		a.api(w, r)
		return
	}
	a.serveSPA(w, r)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id := a.snapshot.ID
	if a.store != nil {
		var err error
		id, err = a.store.LatestID(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "snapshotId": id})
}

func (a *API) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.store != nil {
		a.workspaceAPI(w, r)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/snapshots/"):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/snapshots/")
		if id == "" || id != a.snapshot.ID {
			writeError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		writeJSON(w, http.StatusOK, a.snapshot)
	case r.URL.Path == "/api/v1/findings":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if !a.validSnapshotQuery(r) {
			writeError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		findings, filtered, err := filterFindingsByID(r, a.snapshot.Findings)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !filtered {
			findings = a.snapshot.Findings
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": a.snapshot.ID, "findings": findings, "total": len(findings)})
	case r.URL.Path == "/api/v1/attack-paths":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if !a.validSnapshotQuery(r) {
			writeError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": a.snapshot.ID, "attackPaths": a.snapshot.AttackPaths})
	case r.URL.Path == "/api/v1/simulations":
		a.simulate(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (a *API) workspaceAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v1/session":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"csrfToken": a.csrfToken})
	case r.URL.Path == "/api/v1/bootstrap":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		catalog, err := a.store.Catalog(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		current, err := a.store.LatestID(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var currentValue any = current
		if current == "" {
			currentValue = nil
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"snapshots": catalog.Snapshots, "currentSnapshotId": currentValue,
			"capabilities": map[string]bool{"history": len(catalog.Snapshots) > 1, "comparison": true, "import": true, "triage": true, "azureScans": true},
		})
	case r.URL.Path == "/api/v1/snapshots":
		if r.Method == http.MethodGet {
			catalog, err := a.store.Catalog(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, catalog)
			return
		}
		if r.Method == http.MethodPost {
			a.importSnapshot(w, r)
			return
		}
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	case strings.HasPrefix(r.URL.Path, "/api/v1/snapshots/"):
		a.snapshotEndpoint(w, r)
	case r.URL.Path == "/api/v1/findings":
		a.findings(w, r)
	case r.URL.Path == "/api/v1/attack-paths":
		a.attackPaths(w, r)
	case r.URL.Path == "/api/v1/triage":
		a.triage(w, r)
	case r.URL.Path == "/api/v1/scans/azure":
		a.startAzureScan(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/scans/"):
		a.scanEndpoint(w, r)
	case r.URL.Path == "/api/v1/comparisons":
		a.compare(w, r)
	case r.URL.Path == "/api/v1/simulations":
		a.simulateWorkspace(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (a *API) snapshotEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, "/api/v1/snapshots/")
	parts := strings.Split(relative, "/")
	if len(parts) > 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if len(parts) == 2 && parts[1] == "summary" {
		metadata, err := a.store.Metadata(r.Context(), parts[0])
		if err != nil {
			writeWorkspaceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, metadata)
		return
	}
	if len(parts) == 2 && parts[1] != "graph" {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	err := a.store.WithSnapshot(r.Context(), parts[0], func(snapshot model.Snapshot) error {
		if len(parts) == 1 {
			writeJSON(w, http.StatusOK, snapshot)
		} else {
			a.graphSlice(w, r, snapshot)
		}
		return nil
	})
	if err != nil {
		writeWorkspaceError(w, err)
	}
}

func (a *API) graphSlice(w http.ResponseWriter, r *http.Request, snapshot model.Snapshot) {
	ids := make(map[string]struct{})
	for _, id := range r.URL.Query()["resource_id"] {
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	explicitIDs := len(ids) > 0
	requestedIDCount := len(ids)
	limit := queryInt(r, "limit", 200, 1, 500)
	relationshipLimit := queryInt(r, "relationship_limit", 2_000, 1, 2_000)
	offset := queryInt(r, "offset", 0, 0, len(snapshot.Resources))
	var nodes []model.ResourceNode
	if len(ids) > 0 {
		for _, node := range snapshot.Resources {
			if _, ok := ids[node.ID]; ok {
				nodes = append(nodes, node)
				if len(nodes) == limit {
					break
				}
			}
		}
		ids = make(map[string]struct{}, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = struct{}{}
		}
	} else {
		end := min(offset+limit, len(snapshot.Resources))
		if offset < len(snapshot.Resources) {
			nodes = snapshot.Resources[offset:end]
		}
		for _, node := range nodes {
			ids[node.ID] = struct{}{}
		}
	}
	priorityRelationshipIDs := make(map[string]struct{})
	for _, attackPath := range snapshot.AttackPaths {
		for _, relationshipID := range attackPath.RelationshipIDs {
			priorityRelationshipIDs[relationshipID] = struct{}{}
		}
	}
	var relationships []model.RelationshipEdge
	matchingRelationships := 0
	for _, edge := range snapshot.Relationships {
		_, source := ids[edge.Source]
		_, target := ids[edge.Target]
		if source && target {
			matchingRelationships++
			if _, priority := priorityRelationshipIDs[edge.ID]; priority && len(relationships) < relationshipLimit {
				relationships = append(relationships, edge)
			}
		}
	}
	for _, edge := range snapshot.Relationships {
		if len(relationships) == relationshipLimit {
			break
		}
		if _, priority := priorityRelationshipIDs[edge.ID]; priority {
			continue
		}
		_, source := ids[edge.Source]
		_, target := ids[edge.Target]
		if source && target {
			relationships = append(relationships, edge)
		}
	}
	nodesTruncated := (!explicitIDs && offset+len(nodes) < len(snapshot.Resources)) || (explicitIDs && requestedIDCount > len(nodes))
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshotId": snapshot.ID, "resources": nodes, "relationships": relationships,
		"offset": offset, "limit": limit, "totalResources": len(snapshot.Resources),
		"relationshipLimit": relationshipLimit, "totalRelationships": matchingRelationships,
		"truncated": nodesTruncated || matchingRelationships > len(relationships),
	})
}

func (a *API) findings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id, ok := a.querySnapshotID(w, r)
	if !ok {
		return
	}
	err := a.store.WithSnapshot(r.Context(), id, func(snapshot model.Snapshot) error {
		if findings, filtered, filterErr := filterFindingsByID(r, snapshot.Findings); filtered || filterErr != nil {
			if filterErr != nil {
				writeError(w, http.StatusBadRequest, filterErr.Error())
				return nil
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"snapshotId": snapshot.ID, "findings": findings,
				"page": 1, "pageSize": len(findings), "total": len(findings),
			})
			return nil
		}
		page, size, start, end := pagination(r, len(snapshot.Findings))
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": snapshot.ID, "findings": snapshot.Findings[start:end], "page": page, "pageSize": size, "total": len(snapshot.Findings)})
		return nil
	})
	if err != nil {
		writeWorkspaceError(w, err)
	}
	return
}

func filterFindingsByID(r *http.Request, findings []model.Finding) ([]model.Finding, bool, error) {
	values, filtered := r.URL.Query()["finding_id"]
	if !filtered {
		return nil, false, nil
	}
	if len(values) == 0 || len(values) > maxFindingIDFilter {
		return nil, true, fmt.Errorf("finding_id accepts between 1 and %d values", maxFindingIDFilter)
	}
	requested := make(map[string]struct{}, len(values))
	for _, id := range values {
		if id == "" {
			return nil, true, errors.New("finding_id must not be empty")
		}
		requested[id] = struct{}{}
	}
	selected := make([]model.Finding, 0, len(requested))
	for _, finding := range findings {
		if _, ok := requested[finding.ID]; ok {
			selected = append(selected, finding)
		}
	}
	return selected, true, nil
}

func (a *API) attackPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id, ok := a.querySnapshotID(w, r)
	if !ok {
		return
	}
	err := a.store.WithSnapshot(r.Context(), id, func(snapshot model.Snapshot) error {
		page, size, start, end := pagination(r, len(snapshot.AttackPaths))
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": snapshot.ID, "attackPaths": snapshot.AttackPaths[start:end], "page": page, "pageSize": size, "total": len(snapshot.AttackPaths), "analysis": snapshot.Analysis})
		return nil
	})
	if err != nil {
		writeWorkspaceError(w, err)
	}
}

func (a *API) querySnapshotID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.URL.Query().Get("snapshot_id")
	if id == "" {
		var err error
		id, err = a.store.LatestID(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return "", false
		}
	}
	if id == "" {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return "", false
	}
	return id, true
}

func (a *API) importSnapshot(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		EnvironmentID string          `json:"environmentId"`
		Snapshot      json.RawMessage `json:"snapshot"`
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20+1))
	if err != nil || len(data) > 64<<20 {
		writeError(w, http.StatusBadRequest, "invalid or oversized snapshot request")
		return
	}
	if err := json.Unmarshal(data, &payload); err == nil && len(payload.Snapshot) > 0 {
		data = payload.Snapshot
	} else {
		payload.EnvironmentID = r.URL.Query().Get("environment_id")
	}
	snapshot, err := analysis.DecodeSnapshotJSON(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid snapshot: "+err.Error())
		return
	}
	snapshot, err = a.analyzer.Analyze(r.Context(), snapshot)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	metadata, err := a.store.Import(r.Context(), snapshot, payload.EnvironmentID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, metadata)
}

func (a *API) compare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	baseID, targetID := r.URL.Query().Get("base"), r.URL.Query().Get("target")
	if baseID == "" {
		baseID = r.URL.Query().Get("base_snapshot_id")
	}
	if targetID == "" {
		targetID = r.URL.Query().Get("target_snapshot_id")
	}
	if baseID == "" || targetID == "" {
		writeError(w, http.StatusBadRequest, "base and target are required")
		return
	}
	err := a.store.WithSnapshot(r.Context(), baseID, func(base model.Snapshot) error {
		return a.store.WithSnapshot(r.Context(), targetID, func(target model.Snapshot) error {
			writeJSON(w, http.StatusOK, comparison.Compare(base, target))
			return nil
		})
	})
	if err != nil {
		writeWorkspaceError(w, err)
	}
}

func (a *API) simulateWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var request struct {
		SnapshotID string                   `json:"snapshotId"`
		Changes    []model.SimulationChange `json:"changes"`
		Compact    bool                     `json:"compact,omitempty"`
	}
	if err := decodeJSONBody(r.Body, 1<<20, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid simulation request: "+err.Error())
		return
	}
	if request.SnapshotID == "" || len(request.Changes) == 0 {
		writeError(w, http.StatusBadRequest, "snapshotId and at least one simulation change are required")
		return
	}
	var result model.SimulationResult
	var simulationErr error
	err := a.store.WithSnapshot(r.Context(), request.SnapshotID, func(snapshot model.Snapshot) error {
		result, simulationErr = simulation.Apply(r.Context(), a.analyzer, snapshot, request.Changes)
		return nil
	})
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	if simulationErr != nil {
		writeError(w, http.StatusUnprocessableEntity, simulationErr.Error())
		return
	}
	if request.Compact {
		writeJSON(w, http.StatusOK, result.Delta())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func pagination(r *http.Request, total int) (page, size, start, end int) {
	page = queryInt(r, "page", 1, 1, 1_000_000)
	size = queryInt(r, "page_size", 50, 1, 200)
	start = min((page-1)*size, total)
	end = min(start+size, total)
	return
}

func queryInt(r *http.Request, name string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func writeWorkspaceError(w http.ResponseWriter, err error) {
	if errors.Is(err, workspace.ErrSnapshotNotFound) {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (a *API) acceptLocalRequest(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	hostName := host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		hostName = parsed
	}
	hostName = strings.Trim(hostName, "[]")
	if hostName != "localhost" {
		ip := net.ParseIP(hostName)
		if ip == nil || !ip.IsLoopback() {
			writeError(w, http.StatusForbidden, "local requests only")
			return false
		}
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(remoteHost) == nil || !net.ParseIP(remoteHost).IsLoopback() {
		writeError(w, http.StatusForbidden, "local requests only")
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !strings.EqualFold(parsed.Host, host) {
			writeError(w, http.StatusForbidden, "origin not allowed")
			return false
		}
	}
	if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/api/") {
		provided := r.Header.Get("X-Atlas-Session-Token")
		validToken := len(provided) == len(a.sessionToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(a.sessionToken)) == 1
		if !validToken {
			writeError(w, http.StatusUnauthorized, "invalid workspace session")
			return false
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		provided := r.Header.Get("X-Atlas-CSRF-Token")
		validToken := len(provided) == len(a.csrfToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(a.csrfToken)) == 1
		if !validToken {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return false
		}
	}
	return true
}

func (a *API) validSnapshotQuery(r *http.Request) bool {
	id := r.URL.Query().Get("snapshot_id")
	return id == "" || id == a.snapshot.ID
}

func (a *API) simulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var request struct {
		SnapshotID string                   `json:"snapshotId"`
		Changes    []model.SimulationChange `json:"changes"`
	}
	if err := decodeJSONBody(r.Body, 1<<20, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid simulation request: "+err.Error())
		return
	}
	if request.SnapshotID != "" && request.SnapshotID != a.snapshot.ID {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if len(request.Changes) == 0 {
		writeError(w, http.StatusBadRequest, "at least one simulation change is required")
		return
	}
	result, err := simulation.Apply(r.Context(), a.analyzer, a.snapshot, request.Changes)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) serveSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	staticPath := normalizeStaticPath(r.URL.Path)
	if strings.HasSuffix(strings.ToLower(staticPath), ".map") {
		http.NotFound(w, r)
		return
	}
	clean := path.Clean(strings.TrimPrefix(staticPath, "/"))
	if clean == "." {
		clean = "index.html"
	}
	if !fs.ValidPath(clean) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	if info, err := fs.Stat(a.staticFS, clean); err == nil && !info.IsDir() {
		staticRequest := r.Clone(r.Context())
		if clean == "index.html" {
			staticRequest.URL.Path = "/"
		} else {
			staticRequest.URL.Path = "/" + clean
		}
		a.static.ServeHTTP(w, staticRequest)
		return
	}
	// Missing files with an extension are assets, not client-side routes. A
	// strict 404 keeps an accidentally generated source map from falling
	// through to index.html and avoids serving HTML as JavaScript.
	if path.Ext(clean) != "" {
		http.NotFound(w, r)
		return
	}
	indexRequest := r.Clone(r.Context())
	indexRequest.URL.Path = "/"
	a.static.ServeHTTP(w, indexRequest)
}

func normalizeStaticPath(path string) string {
	if path == pagesBasePath || path == pagesBasePath+"/" {
		return "/"
	}
	if strings.HasPrefix(path, pagesBasePath+"/") {
		return strings.TrimPrefix(path, pagesBasePath)
	}
	return path
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSONBody(body io.Reader, limit int64, target any) error {
	decoder := json.NewDecoder(io.LimitReader(body, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request contains trailing JSON content")
		}
		return fmt.Errorf("request contains trailing content: %w", err)
	}
	return nil
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// ListenAndServe exposes the local demo until ctx is cancelled.
func ListenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	server := &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
