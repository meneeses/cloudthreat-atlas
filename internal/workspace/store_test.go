package workspace_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestStoreImportLoadCatalogAndDiagnostics(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "private-workspace")
	store, err := workspace.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	snapshot, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Import(ctx, snapshot, "azure-prod")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.EnvironmentID != "azure-prod" || metadata.SourceSnapshotID != snapshot.ID || metadata.ID == snapshot.ID || metadata.ResourceCount != len(snapshot.Resources) || metadata.SHA256 == "" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	loaded, err := store.Load(ctx, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != metadata.ID || len(loaded.AttackPaths) != len(snapshot.AttackPaths) {
		t.Fatalf("loaded snapshot = %+v", loaded)
	}

	catalog, err := store.Catalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Environments) != 1 || len(catalog.Snapshots) != 1 || catalog.Environments[0].LatestSnapshotID != metadata.ID {
		t.Fatalf("unexpected catalog: %+v", catalog)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("workspace permissions: info=%v err=%v", info, err)
	}
	files, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if err != nil || len(files) != 1 {
		t.Fatalf("snapshot files: %v, %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "snapshots", files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		t.Fatal("snapshot is not gzip compressed")
	}
	if strings.Contains(string(data), "Contoso") {
		t.Fatal("snapshot file contains uncompressed JSON")
	}
	for _, check := range store.Diagnose(ctx) {
		if !check.OK {
			t.Fatalf("diagnostic failed: %+v", check)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := workspace.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(ctx, metadata.ID); err != nil {
		t.Fatalf("load after reopen: %v", err)
	}
}

func TestStoreAssignsUniqueIDsForRepeatedSourceSnapshots(t *testing.T) {
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
	first, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatalf("repeat import: %v", err)
	}
	if first.ID == second.ID || first.SourceSnapshotID != second.SourceSnapshotID {
		t.Fatalf("ids: first=%+v second=%+v", first, second)
	}
	catalog, err := store.Catalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Snapshots) != 2 {
		t.Fatalf("snapshots = %d", len(catalog.Snapshots))
	}
}

func TestStoreConcurrentLoadsReturnIndependentSnapshots(t *testing.T) {
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

	const readers = 32
	start := make(chan struct{})
	errorsFound := make(chan error, readers)
	var wait sync.WaitGroup
	for index := range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			loaded, loadErr := store.Load(ctx, metadata.ID)
			if loadErr != nil {
				errorsFound <- loadErr
				return
			}
			loaded.Resources[0].Name = "mutated"
			loaded.Resources[0].Properties["reader"] = fmt.Sprintf("%d", index)
			if len(loaded.AttackPaths) > 0 && len(loaded.AttackPaths[0].ResourceIDs) > 0 {
				loaded.AttackPaths[0].ResourceIDs[0] = "mutated"
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for loadErr := range errorsFound {
		t.Fatalf("concurrent load: %v", loadErr)
	}

	loaded, err := store.Load(ctx, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Resources[0].Name == "mutated" || loaded.Resources[0].Properties["reader"] != "" {
		t.Fatalf("caller mutation poisoned cached snapshot: %#v", loaded.Resources[0])
	}
	if len(loaded.AttackPaths) > 0 && loaded.AttackPaths[0].ResourceIDs[0] == "mutated" {
		t.Fatal("caller mutation poisoned cached attack path")
	}
}

func TestStoreCacheDoesNotBypassCompressedFileIntegrity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := workspace.Open(ctx, dir)
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
	if _, err := store.Load(ctx, metadata.ID); err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if err != nil || len(files) != 1 {
		t.Fatalf("snapshot files: %v, %v", files, err)
	}
	path := filepath.Join(dir, "snapshots", files[0].Name())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compressed[len(compressed)/2] ^= 0xff
	if err := os.WriteFile(path, compressed, 0o600); err != nil {
		t.Fatal(err)
	}
	// Restore size and mtime to prove cache validation is content-based rather
	// than trusting weak file metadata.
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, metadata.ID); err == nil {
		t.Fatal("cached load accepted a modified compressed snapshot")
	}
}

func TestStoreDerivesStableEnvironmentAcrossPointInTimeSnapshotIDs(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.ID = "contoso-health-next-scan"
	second.GeneratedAt = second.GeneratedAt.Add(time.Hour)
	firstMetadata, err := store.Import(ctx, first, "")
	if err != nil {
		t.Fatal(err)
	}
	secondMetadata, err := store.Import(ctx, second, "")
	if err != nil {
		t.Fatal(err)
	}
	if firstMetadata.EnvironmentID != secondMetadata.EnvironmentID {
		t.Fatalf("environment changed across scans: %q != %q", firstMetadata.EnvironmentID, secondMetadata.EnvironmentID)
	}
}

func TestStoreKeepsResourceGroupAndSubscriptionScanHistoriesSeparate(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const subscriptionID = "11111111-2222-3333-4444-555555555555"
	whole, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	whole.Scope = &model.Scope{SubscriptionID: subscriptionID}
	group := model.CloneSnapshot(whole)
	group.ID = "resource-group-export"
	group.Scope = &model.Scope{SubscriptionID: subscriptionID, ResourceGroup: "clinical-prod"}
	wholeMetadata, err := store.Import(ctx, whole, "")
	if err != nil {
		t.Fatal(err)
	}
	groupMetadata, err := store.Import(ctx, group, "")
	if err != nil {
		t.Fatal(err)
	}
	if wholeMetadata.EnvironmentID == groupMetadata.EnvironmentID {
		t.Fatalf("subscription and resource-group imports shared environment %q", wholeMetadata.EnvironmentID)
	}
	if groupMetadata.EnvironmentID != workspace.AzureEnvironmentID(*group.Scope) {
		t.Fatalf("resource-group environment = %q, want %q", groupMetadata.EnvironmentID, workspace.AzureEnvironmentID(*group.Scope))
	}
}

func TestStoreSeparatesLegacyRedactedAzureSubscriptions(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	base.Name = "Redacted Azure environment"
	base.Scope = nil
	base.Resources = append(base.Resources, model.ResourceNode{ID: "resource-subscription-a", Name: "scope a", Type: "Microsoft.Resources/subscriptions", Category: "scope", Provider: "azure"})
	other := model.CloneSnapshot(base)
	other.ID = "legacy-redacted-other"
	other.Resources[len(other.Resources)-1].ID = "resource-subscription-b"

	first, err := store.Import(ctx, base, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Import(ctx, other, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.EnvironmentID == second.EnvironmentID {
		t.Fatalf("unrelated legacy redacted subscriptions shared environment %q", first.EnvironmentID)
	}
}

func TestImportRejectsUnsupportedSchema(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := demodata.ContosoHealth()
	snapshot.SchemaVersion = "2.0"
	if _, err := store.Import(context.Background(), snapshot, ""); err == nil || !strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("error = %v", err)
	}
}

func TestImportRejectsEmptyPortableScope(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := demodata.ContosoHealth()
	snapshot.Scope = &model.Scope{ResourceGroup: "clinical-prod"}
	if _, err := store.Import(context.Background(), snapshot, ""); err == nil || !strings.Contains(err.Error(), "scope subscriptionId") {
		t.Fatalf("error = %v", err)
	}
}

func TestDefaultDirUsesDataDirectoryAndOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "override")
	t.Setenv("CLOUDTHREAT_ATLAS_HOME", override)
	got, err := workspace.DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != override {
		t.Fatalf("override = %q, want %q", got, override)
	}
	if runtime.GOOS == "linux" {
		t.Setenv("CLOUDTHREAT_ATLAS_HOME", "")
		dataHome := filepath.Join(t.TempDir(), "xdg-data")
		t.Setenv("XDG_DATA_HOME", dataHome)
		got, err = workspace.DefaultDir()
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(dataHome, "cloudthreat-atlas") {
			t.Fatalf("data dir = %q", got)
		}
	}
}
