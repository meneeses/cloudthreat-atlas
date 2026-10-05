package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestHelpAndDefaultReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "atlas demo") {
		t.Fatal("help is missing demo command")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"report", "--format", "markdown"}, &stdout, &stderr); code != 0 {
		t.Fatalf("report exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Risk score") || !strings.Contains(stdout.String(), "Attack paths") {
		t.Fatal("markdown report is missing expected sections")
	}
}

func TestWorkspaceImportListCompareAndDoctor(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "workspace")
	inputDir := t.TempDir()
	first := demodata.ContosoHealth()
	first.ID = "cli-first"
	second := first
	second.ID = "cli-second"
	second.GeneratedAt = second.GeneratedAt.Add(time.Minute)
	second.Resources = append(second.Resources, model.ResourceNode{ID: "later-node", Name: "Later", Type: "test", Category: "test"})
	for _, item := range []struct {
		name  string
		value any
	}{{"first.json", first}, {"second.json", second}} {
		data, err := json.Marshal(item.value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(inputDir, item.name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"first.json", "second.json"} {
		var stdout, stderr bytes.Buffer
		code := run(ctx, []string{"import", "--input", filepath.Join(inputDir, name), "--environment", "test", "--data-dir", dataDir}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("import %s = %d: %s", name, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"snapshots", "list", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("list = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cli-first") || !strings.Contains(stdout.String(), "cli-second") {
		t.Fatalf("list = %s", stdout.String())
	}
	var catalog workspace.Catalog
	if err := json.Unmarshal(stdout.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	var firstID, secondID string
	for _, metadata := range catalog.Snapshots {
		switch metadata.SourceSnapshotID {
		case "cli-first":
			firstID = metadata.ID
		case "cli-second":
			secondID = metadata.ID
		}
	}
	if firstID == "" || secondID == "" {
		t.Fatalf("catalog metadata = %+v", catalog.Snapshots)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"compare", firstID, secondID, "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("compare = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "riskScoreDelta") {
		t.Fatalf("compare = %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	bundlePath := filepath.Join(t.TempDir(), "remediation.zip")
	if code := run(ctx, []string{"bundle", "--snapshot", firstID, "--output", bundlePath, "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("bundle = %d: %s", code, stderr.String())
	}
	if info, err := os.Stat(bundlePath); err != nil || info.Size() == 0 {
		t.Fatalf("bundle output: info=%v err=%v", info, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"doctor", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("doctor = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "sqlite-integrity") {
		t.Fatalf("doctor = %s", stdout.String())
	}
}

func TestAppRejectsNonLoopbackAddress(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"app", "--addr", "0.0.0.0:8080", "--data-dir", t.TempDir()}, &stdout, &stderr); code != 1 {
		t.Fatalf("app exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestDemoRejectsNonLoopbackAddress(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"demo", "--addr", "0.0.0.0:8080"}, &stdout, &stderr); code != 1 {
		t.Fatalf("demo exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

type cliFakeCollector struct{ snapshot model.Snapshot }

func (collector cliFakeCollector) Collect(context.Context, model.Scope) (model.Snapshot, error) {
	return collector.snapshot, nil
}

func TestAzureScanSavePreservesJSONOutputAndPersists(t *testing.T) {
	original := azureScanner
	defer func() { azureScanner = original }()
	snapshot := demodata.ContosoHealth()
	snapshot.ID = "azure-00000000000000000000000000000001"
	azureScanner = cliFakeCollector{snapshot: snapshot}
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"scan", "azure", "--subscription", "00000000-0000-0000-0000-000000000001", "--save", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("scan = %d: %s", code, stderr.String())
	}
	var output model.Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("stdout is not snapshot JSON: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "saved workspace snapshot") {
		t.Fatalf("stderr = %s", stderr.String())
	}
	store, err := workspace.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	catalog, err := store.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Snapshots) != 1 || catalog.Snapshots[0].SourceSnapshotID != snapshot.ID {
		t.Fatalf("catalog = %+v", catalog.Snapshots)
	}
	expectedEnvironment := workspace.AzureEnvironmentID(model.Scope{SubscriptionID: "00000000-0000-0000-0000-000000000001"})
	if catalog.Snapshots[0].EnvironmentID != expectedEnvironment || output.Scope == nil || output.Scope.SubscriptionID == "" {
		t.Fatalf("scope/environment = %#v / %q", output.Scope, catalog.Snapshots[0].EnvironmentID)
	}
}

func TestAzureRedactedScanSaveMatchesReimportedEnvironment(t *testing.T) {
	original := azureScanner
	defer func() { azureScanner = original }()
	snapshot := demodata.ContosoHealth()
	snapshot.ID = "azure-00000000000000000000000000000001"
	azureScanner = cliFakeCollector{snapshot: snapshot}
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"scan", "azure",
		"--subscription", "00000000-0000-0000-0000-000000000001",
		"--resource-group", "Clinical-Prod",
		"--redact", "--save", "--data-dir", dataDir,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("scan = %d: %s", code, stderr.String())
	}
	var output model.Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.Scope == nil || strings.Contains(output.Scope.SubscriptionID, "00000000") || strings.Contains(strings.ToLower(output.Scope.ResourceGroup), "clinical-prod") {
		t.Fatalf("redacted scope = %#v", output.Scope)
	}
	store, err := workspace.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	catalog, err := store.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Snapshots) != 1 {
		t.Fatalf("catalog snapshots = %d", len(catalog.Snapshots))
	}
	reimported, err := store.Import(context.Background(), output, "")
	if err != nil {
		t.Fatal(err)
	}
	if reimported.EnvironmentID != catalog.Snapshots[0].EnvironmentID {
		t.Fatalf("saved environment %q != reimported environment %q", catalog.Snapshots[0].EnvironmentID, reimported.EnvironmentID)
	}
}

func TestAppNoOpenCanShutdownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"app", "--addr", "127.0.0.1:0", "--data-dir", t.TempDir(), "--no-open"}, &stdout, &stderr); code != 0 {
		t.Fatalf("app = %d: %s", code, stderr.String())
	}
}

func TestAnalyzeRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"analyze"}, &stdout, &stderr); code != 1 {
		t.Fatalf("analyze exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--input is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAzureScanRequiresSubscriptionBeforeAuthentication(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"scan", "azure"}, &stdout, &stderr); code != 1 {
		t.Fatalf("scan exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--subscription is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
