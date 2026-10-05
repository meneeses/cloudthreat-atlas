package analysis_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestContosoHealthAnalysisIsDeterministic(t *testing.T) {
	engine := analysis.NewDefault()
	first, err := engine.Analyze(context.Background(), demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Analyze(context.Background(), demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same topology produced different analysis results")
	}
	if len(first.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(first.Findings))
	}
	if len(first.AttackPaths) != 3 {
		t.Fatalf("got %d attack paths, want 3", len(first.AttackPaths))
	}
	wantPaths := map[string]bool{demodata.PathPublicApp: true, demodata.PathPublicVM: true, demodata.PathPipeline: true}
	for _, path := range first.AttackPaths {
		if !wantPaths[path.ID] {
			t.Errorf("unexpected attack path %q", path.ID)
		}
		if len(path.FindingIDs) != 1 {
			t.Errorf("path %q has %d linked findings, want 1", path.ID, len(path.FindingIDs))
		}
	}
}

func TestCommittedFixtureMatchesEngineOutput(t *testing.T) {
	data, err := os.ReadFile("../../demo/contoso-health.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture model.Snapshot
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	want, err := analysis.NewDefault().Analyze(context.Background(), demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture, want) {
		t.Fatal("demo/contoso-health.json is stale; regenerate it from demodata.ContosoHealth")
	}
}

func TestAnalyzeDoesNotMutateSource(t *testing.T) {
	source := demodata.ContosoHealth()
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analysis.NewDefault().Analyze(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("analysis mutated source")
	}
}
