package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/simulation"
)

const pagesBasePath = "/cloudthreat-atlas"

// Analyzer is the analysis service contract needed by the HTTP API.
type Analyzer interface {
	Analyze(ctx context.Context, input model.Snapshot) (model.Snapshot, error)
}

// API serves one local snapshot and optionally a compiled single-page application.
type API struct {
	snapshot model.Snapshot
	analyzer Analyzer
	staticFS fs.FS
	static   http.Handler
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

// Handler returns the complete API and SPA handler.
func (a *API) Handler() http.Handler { return a }

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "snapshotId": a.snapshot.ID})
}

func (a *API) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
		writeJSON(w, http.StatusOK, map[string]any{"snapshotId": a.snapshot.ID, "findings": a.snapshot.Findings})
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
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
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

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// ListenAndServe exposes the local demo until ctx is cancelled.
func ListenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
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
