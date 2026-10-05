package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestTriageAPIReadsAndPatchesPersistentState(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	get := serveLocal(api, http.MethodGet, "/api/v1/triage?snapshot_id="+metadata.ID, nil, "")
	if get.Code != http.StatusOK {
		t.Fatalf("get = %d: %s", get.Code, get.Body.String())
	}
	payload := fmt.Sprintf(`{"snapshotId":%q,"findingId":%q,"status":"acknowledged","notes":"owner notified"}`, metadata.ID, snapshot.Findings[0].ID)
	denied := serveLocal(api, http.MethodPatch, "/api/v1/triage", strings.NewReader(payload), "")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unprotected patch = %d", denied.Code)
	}
	patch := serveLocal(api, http.MethodPatch, "/api/v1/triage", strings.NewReader(payload), sessionToken(t, api))
	if patch.Code != http.StatusOK {
		t.Fatalf("patch = %d: %s", patch.Code, patch.Body.String())
	}
	var record workspace.TriageRecord
	if err := json.Unmarshal(patch.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Status != workspace.TriageAcknowledged || record.Notes != "owner notified" {
		t.Fatalf("record = %+v", record)
	}
	get = serveLocal(api, http.MethodGet, "/api/v1/triage?snapshot_id="+metadata.ID, nil, "")
	if !strings.Contains(get.Body.String(), "owner notified") {
		t.Fatalf("persisted response = %s", get.Body.String())
	}
}
