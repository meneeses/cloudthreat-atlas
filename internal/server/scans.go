package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

// ScanCollector is the read-only collector used by asynchronous scan jobs.
type ScanCollector interface {
	Collect(context.Context, model.Scope) (model.Snapshot, error)
}

type scanCoordinator struct {
	mu       sync.Mutex
	activeID string
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
	firstErr error
}

var secretLike = regexp.MustCompile(`(?i)((?:access[_ -]?token|bearer)\s*[:=]?\s*)\S+`)
var azureSubscriptionID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (a *API) startAzureScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var request struct {
		SubscriptionID string `json:"subscriptionId"`
		ResourceGroup  string `json:"resourceGroup,omitempty"`
	}
	if err := decodeJSONBody(r.Body, 64<<10, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid scan request: "+err.Error())
		return
	}
	request.SubscriptionID = strings.TrimSpace(request.SubscriptionID)
	request.ResourceGroup = strings.TrimSpace(request.ResourceGroup)
	if request.SubscriptionID == "" {
		writeError(w, http.StatusBadRequest, "subscriptionId is required")
		return
	}
	if !azureSubscriptionID.MatchString(request.SubscriptionID) {
		writeError(w, http.StatusBadRequest, "subscriptionId must be a UUID")
		return
	}
	scope := model.Scope{SubscriptionID: request.SubscriptionID, ResourceGroup: request.ResourceGroup}
	a.scans.mu.Lock()
	if a.scans.closed {
		a.scans.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "scan service is shutting down")
		return
	}
	if a.scans.activeID != "" {
		active := a.scans.activeID
		a.scans.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already active", "jobId": active})
		return
	}
	job, err := a.store.CreateScanJob(r.Context(), scope)
	if err != nil {
		a.scans.mu.Unlock()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scanCtx, cancel := context.WithCancel(context.Background())
	a.scans.activeID, a.scans.cancel = job.ID, cancel
	a.scans.wg.Add(1)
	a.scans.mu.Unlock()
	go a.runAzureScan(scanCtx, job.ID, scope)
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID, "status": job.Status})
}

func (a *API) runAzureScan(ctx context.Context, jobID string, scope model.Scope) {
	defer func() {
		a.scans.mu.Lock()
		if a.scans.activeID == jobID {
			a.scans.activeID = ""
			a.scans.cancel = nil
		}
		a.scans.mu.Unlock()
		a.scans.wg.Done()
	}()
	update := func(status, phase, message, snapshotID string) bool {
		if _, err := a.store.UpdateScanJob(context.Background(), jobID, status, phase, message, snapshotID); err != nil {
			a.scans.recordError(fmt.Errorf("update scan job %q: %w", jobID, err))
			return false
		}
		return true
	}
	phase := func(name string) bool {
		if err := ctx.Err(); err != nil {
			_ = update("cancelled", "cancelled", "scan cancelled", "")
			return false
		}
		return update("running", name, "starting "+name, "")
	}
	if !phase("authentication") || !phase("resources") {
		return
	}
	snapshot, err := a.scanner.Collect(ctx, scope)
	if err != nil {
		if ctx.Err() != nil {
			_ = update("cancelled", "cancelled", "scan cancelled", "")
		} else {
			_ = update("failed", scanFailurePhase(err), safeScanError(err), "")
		}
		return
	}
	if !phase("RBAC") || !phase("normalization") || !phase("analysis") {
		return
	}
	snapshot, err = a.analyzer.Analyze(ctx, snapshot)
	if err != nil {
		if ctx.Err() != nil {
			_ = update("cancelled", "cancelled", "scan cancelled", "")
		} else {
			_ = update("failed", "analysis", safeScanError(err), "")
		}
		return
	}
	if !phase("save") {
		return
	}
	metadata, err := a.store.Import(ctx, snapshot, workspace.AzureEnvironmentID(scope))
	if err != nil {
		if ctx.Err() != nil {
			_ = update("cancelled", "cancelled", "scan cancelled", "")
		} else {
			_ = update("failed", "save", safeScanError(err), "")
		}
		return
	}
	_ = update("completed", "complete", "scan completed", metadata.ID)
}

func (c *scanCoordinator) recordError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstErr == nil {
		c.firstErr = err
	}
}

func (a *API) scanEndpoint(w http.ResponseWriter, r *http.Request) {
	relative := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(relative, "/")
	if parts[0] == "" || len(parts) > 2 {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	if len(parts) == 2 {
		if parts[1] != "events" || r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		a.scanEvents(w, r, parts[0])
		return
	}
	switch r.Method {
	case http.MethodGet:
		job, err := a.store.ScanJob(r.Context(), parts[0])
		if err != nil {
			writeError(w, http.StatusNotFound, "scan job not found")
			return
		}
		writeJSON(w, http.StatusOK, job)
	case http.MethodDelete:
		job, err := a.store.ScanJob(r.Context(), parts[0])
		if err != nil {
			writeError(w, http.StatusNotFound, "scan job not found")
			return
		}
		if workspace.IsTerminalJob(job.Status) {
			writeError(w, http.StatusConflict, "scan job is already complete")
			return
		}
		a.scans.mu.Lock()
		cancel := a.scans.cancel
		active := a.scans.activeID
		a.scans.mu.Unlock()
		if active != job.ID || cancel == nil {
			writeError(w, http.StatusConflict, "scan job is not active in this process")
			return
		}
		cancel()
		writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID, "status": "cancelling"})
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodDelete)
	}
}

func (a *API) scanEvents(w http.ResponseWriter, r *http.Request, jobID string) {
	if _, err := a.store.ScanJob(r.Context(), jobID); err != nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	afterValue := r.URL.Query().Get("after")
	if afterValue == "" {
		afterValue = r.Header.Get("Last-Event-ID")
	}
	after, _ := strconv.ParseInt(afterValue, 10, 64)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := a.store.ScanJobEvents(r.Context(), jobID, after)
		if err != nil {
			return
		}
		for _, event := range events {
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "id: %d\nevent: progress\ndata: %s\n\n", event.Sequence, data)
			after = event.Sequence
			flusher.Flush()
		}
		job, err := a.store.ScanJob(r.Context(), jobID)
		if err != nil || workspace.IsTerminalJob(job.Status) {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func safeScanError(err error) string {
	message := secretLike.ReplaceAllString(err.Error(), "$1[redacted]")
	if len(message) > 2000 {
		message = message[:2000]
	}
	return message
}

func scanFailurePhase(err error) string {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "auth") || strings.Contains(message, "credential") {
		return "authentication"
	}
	if strings.Contains(message, "role") || strings.Contains(message, "rbac") {
		return "RBAC"
	}
	return "resources"
}
