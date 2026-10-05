package workspace_test

import (
	"context"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestTriageCarriesForwardByEnvironmentAndFingerprint(t *testing.T) {
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
	firstMetadata, err := store.Import(ctx, first, "production")
	if err != nil {
		t.Fatal(err)
	}
	findingID := first.Findings[0].ID
	record, err := store.UpdateTriage(ctx, firstMetadata.ID, findingID, workspace.TriageAcceptedRisk, "Approved until the next architecture review.")
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != workspace.TriageAcceptedRisk || record.Notes == "" {
		t.Fatalf("record = %+v", record)
	}

	second := first
	second.ID = "collector-second"
	second.GeneratedAt = second.GeneratedAt.Add(time.Hour)
	// Finding identifiers may change while the evidence fingerprint remains stable.
	oldFindingID := second.Findings[0].ID
	second.Findings[0].ID = "renamed-finding"
	for i := range second.AttackPaths {
		for j := range second.AttackPaths[i].FindingIDs {
			if second.AttackPaths[i].FindingIDs[j] == oldFindingID {
				second.AttackPaths[i].FindingIDs[j] = "renamed-finding"
			}
		}
	}
	secondMetadata, err := store.Import(ctx, second, "production")
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Triage(ctx, secondMetadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	var carried *workspace.TriageRecord
	for i := range records {
		if records[i].FindingID == "renamed-finding" {
			carried = &records[i]
			break
		}
	}
	if carried == nil || carried.Status != workspace.TriageAcceptedRisk || carried.Notes != record.Notes {
		t.Fatalf("carried triage = %+v", carried)
	}
	if carried.FirstSeenSnapshotID != firstMetadata.ID || carried.LastSeenSnapshotID != secondMetadata.ID {
		t.Fatalf("history = %+v", carried)
	}
}

func TestFindingFingerprintIgnoresOrderingAndFindingID(t *testing.T) {
	first := model.Finding{ID: "one", RuleID: "rule", ResourceIDs: []string{"b", "a"}, RelationshipIDs: []string{"r2", "r1"}}
	second := model.Finding{ID: "two", RuleID: "rule", ResourceIDs: []string{"a", "b"}, RelationshipIDs: []string{"r1", "r2"}}
	if workspace.FindingFingerprint(first) != workspace.FindingFingerprint(second) {
		t.Fatal("equivalent findings produced different fingerprints")
	}
	second.RuleID = "other"
	if workspace.FindingFingerprint(first) == workspace.FindingFingerprint(second) {
		t.Fatal("different rules produced the same fingerprint")
	}
}

func TestTriageFirstAndLastSeenFollowSnapshotTimeNotImportOrder(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	older, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	newer := older
	newer.ID = "newer-source"
	newer.GeneratedAt = older.GeneratedAt.Add(2 * time.Hour)
	newerMetadata, err := store.Import(ctx, newer, "production")
	if err != nil {
		t.Fatal(err)
	}
	olderMetadata, err := store.Import(ctx, older, "production")
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Triage(ctx, newerMetadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("expected triage records")
	}
	if records[0].FirstSeenSnapshotID != olderMetadata.ID || records[0].LastSeenSnapshotID != newerMetadata.ID {
		t.Fatalf("out-of-order history = %+v", records[0])
	}
}
