package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

const testSubscription = "00000000-0000-0000-0000-000000000001"

type fakeScanner struct {
	collect func(context.Context, model.Scope) (model.Snapshot, error)
}

func (f fakeScanner) Collect(ctx context.Context, scope model.Scope) (model.Snapshot, error) {
	return f.collect(ctx, scope)
}

func TestAzureScanJobCompletesAndStreamsNamedPhases(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scanner := fakeScanner{collect: func(context.Context, model.Scope) (model.Snapshot, error) {
		snapshot := demodata.ContosoHealth()
		snapshot.ID = "azure-source"
		return snapshot, nil
	}}
	api, err := server.NewWorkspaceWithCollector(store, analysis.NewDefault(), "", scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	token := sessionToken(t, api)
	invalid := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"not-a-uuid"}`), token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid subscription = %d", invalid.Code)
	}
	withToken := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"`+testSubscription+`","accessToken":"never-store-this"}`), token)
	if withToken.Code != http.StatusBadRequest {
		t.Fatalf("token-bearing request = %d", withToken.Code)
	}
	response := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"`+testSubscription+`"}`), token)
	if response.Code != http.StatusAccepted {
		t.Fatalf("start = %d: %s", response.Code, response.Body.String())
	}
	var started map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	job := waitForJob(t, api, started["jobId"], "completed")
	if job.SnapshotID == "" {
		t.Fatalf("completed job = %+v", job)
	}
	if _, err := store.Load(context.Background(), job.SnapshotID); err != nil {
		t.Fatal(err)
	}
	events := serveLocal(api, http.MethodGet, "/api/v1/scans/"+job.ID+"/events", nil, "")
	if events.Code != http.StatusOK {
		t.Fatalf("events = %d: %s", events.Code, events.Body.String())
	}
	for _, phase := range []string{"authentication", "resources", "RBAC", "normalization", "analysis", "save", "complete"} {
		if !strings.Contains(events.Body.String(), `"phase":"`+phase+`"`) {
			t.Fatalf("events missing %s: %s", phase, events.Body.String())
		}
	}
}

func TestAzureScanEnforcesSingleFlightAndCancellation(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entered := make(chan struct{})
	scanner := fakeScanner{collect: func(ctx context.Context, _ model.Scope) (model.Snapshot, error) {
		close(entered)
		<-ctx.Done()
		return model.Snapshot{}, ctx.Err()
	}}
	api, err := server.NewWorkspaceWithCollector(store, analysis.NewDefault(), "", scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	token := sessionToken(t, api)
	payload := `{"subscriptionId":"` + testSubscription + `"}`
	first := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(payload), token)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first = %d", first.Code)
	}
	var started map[string]string
	_ = json.Unmarshal(first.Body.Bytes(), &started)
	<-entered
	second := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(payload), token)
	if second.Code != http.StatusConflict {
		t.Fatalf("second = %d: %s", second.Code, second.Body.String())
	}
	cancelled := serveLocal(api, http.MethodDelete, "/api/v1/scans/"+started["jobId"], nil, token)
	if cancelled.Code != http.StatusAccepted {
		t.Fatalf("cancel = %d: %s", cancelled.Code, cancelled.Body.String())
	}
	waitForJob(t, api, started["jobId"], "cancelled")
}

func TestAzureScanFailureIsDurableAndRedactsTokenLikeText(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scanner := fakeScanner{collect: func(context.Context, model.Scope) (model.Snapshot, error) {
		return model.Snapshot{}, errors.New("authentication failed access_token=TOPSECRET")
	}}
	api, err := server.NewWorkspaceWithCollector(store, analysis.NewDefault(), "", scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	token := sessionToken(t, api)
	response := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"`+testSubscription+`"}`), token)
	var started map[string]string
	_ = json.Unmarshal(response.Body.Bytes(), &started)
	job := waitForJob(t, api, started["jobId"], "failed")
	if strings.Contains(job.Error, "TOPSECRET") || !strings.Contains(job.Error, "redacted") {
		t.Fatalf("error = %q", job.Error)
	}
	catalog, err := store.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Snapshots) != 0 {
		t.Fatalf("failed scan saved %d snapshots", len(catalog.Snapshots))
	}
}

func TestWorkspaceCloseCancelsAndDrainsActiveScan(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entered := make(chan struct{})
	exited := make(chan struct{})
	scanner := fakeScanner{collect: func(ctx context.Context, _ model.Scope) (model.Snapshot, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return model.Snapshot{}, ctx.Err()
	}}
	api, err := server.NewWorkspaceWithCollector(store, analysis.NewDefault(), "", scanner)
	if err != nil {
		t.Fatal(err)
	}
	token := sessionToken(t, api)
	response := serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"`+testSubscription+`"}`), token)
	if response.Code != http.StatusAccepted {
		t.Fatalf("start = %d: %s", response.Code, response.Body.String())
	}
	var started map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := api.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("collector was not drained before Close returned")
	}
	job, err := store.ScanJob(context.Background(), started["jobId"])
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "cancelled" {
		t.Fatalf("status after close = %q, want cancelled", job.Status)
	}
	response = serveLocal(api, http.MethodPost, "/api/v1/scans/azure", strings.NewReader(`{"subscriptionId":"`+testSubscription+`"}`), token)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("start after close = %d: %s", response.Code, response.Body.String())
	}
}

func waitForJob(t *testing.T, api http.Handler, id, status string) workspace.ScanJob {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response := serveLocal(api, http.MethodGet, "/api/v1/scans/"+id, nil, "")
		var job workspace.ScanJob
		if response.Code == http.StatusOK {
			_ = json.Unmarshal(response.Body.Bytes(), &job)
			if job.Status == status {
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach %s", id, status)
	return workspace.ScanJob{}
}
