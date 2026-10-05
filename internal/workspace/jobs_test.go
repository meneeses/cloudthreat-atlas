package workspace_test

import (
	"context"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestScanJobEventsAndRestartInterruption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := workspace.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateScanJob(ctx, model.Scope{SubscriptionID: "00000000-0000-0000-0000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateScanJob(ctx, job.ID, "running", "resources", "querying resources", ""); err != nil {
		t.Fatal(err)
	}
	events, err := store.ScanJobEvents(ctx, job.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Phase != "resources" {
		t.Fatalf("events = %+v", events)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := workspace.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.InterruptRunningJobs(ctx); err != nil {
		t.Fatal(err)
	}
	interrupted, err := reopened.ScanJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.Status != "interrupted" || interrupted.CompletedAt == nil || !strings.Contains(interrupted.Error, "restarted") {
		t.Fatalf("interrupted = %+v", interrupted)
	}
	events, err = reopened.ScanJobEvents(ctx, job.ID, events[len(events)-1].Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Status != "interrupted" {
		t.Fatalf("restart event = %+v", events)
	}
}

func TestAzureEnvironmentIDSeparatesResourceGroupScopes(t *testing.T) {
	subscription := "00000000-0000-0000-0000-000000000001"
	whole := workspace.AzureEnvironmentID(model.Scope{SubscriptionID: subscription})
	groupA := workspace.AzureEnvironmentID(model.Scope{SubscriptionID: subscription, ResourceGroup: "group-a"})
	groupB := workspace.AzureEnvironmentID(model.Scope{SubscriptionID: subscription, ResourceGroup: "group-b"})
	if whole == groupA || groupA == groupB {
		t.Fatalf("environment ids are not scope-specific: %q %q %q", whole, groupA, groupB)
	}
}
