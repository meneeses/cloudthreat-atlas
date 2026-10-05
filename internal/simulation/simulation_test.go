package simulation_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/simulation"
)

func TestEachPresetRemovesOnlyItsAttackPath(t *testing.T) {
	source := demodata.ContosoHealth()
	engine := analysis.NewDefault()
	for _, preset := range source.Simulations {
		preset := preset
		t.Run(preset.ID, func(t *testing.T) {
			result, err := simulation.Apply(context.Background(), engine, source, preset.Changes)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.RemovedAttackPathIDs, preset.RemovedAttackPaths) {
				t.Fatalf("removed paths = %v, want %v", result.RemovedAttackPathIDs, preset.RemovedAttackPaths)
			}
			if len(result.RemainingAttackPaths) != 2 {
				t.Fatalf("remaining paths = %d, want 2", len(result.RemainingAttackPaths))
			}
			if result.RiskScoreAfter >= result.RiskScoreBefore {
				t.Fatalf("risk did not decrease: before=%d after=%d", result.RiskScoreBefore, result.RiskScoreAfter)
			}
		})
	}
}

func TestApplyNeverMutatesOriginal(t *testing.T) {
	source := demodata.ContosoHealth()
	before, _ := json.Marshal(source)
	_, err := simulation.Apply(context.Background(), analysis.NewDefault(), source, source.Simulations[0].Changes)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(source)
	if string(before) != string(after) {
		t.Fatal("simulation mutated original snapshot")
	}
}

func TestRejectsUnknownTarget(t *testing.T) {
	_, err := simulation.Apply(context.Background(), analysis.NewDefault(), demodata.ContosoHealth(), []model.SimulationChange{{Type: "remove-edge", TargetID: "missing"}})
	if err == nil {
		t.Fatal("expected an unknown-target error")
	}
}

func TestRejectsTooManyChangesBeforeAnalysis(t *testing.T) {
	changes := make([]model.SimulationChange, simulation.MaxChanges+1)
	analyzer := &recordingAnalyzer{}

	_, err := simulation.Apply(context.Background(), analyzer, model.Snapshot{ID: "snapshot"}, changes)
	if !errors.Is(err, simulation.ErrTooManyChanges) {
		t.Fatalf("change limit error = %v", err)
	}
	if analyzer.calls != 0 {
		t.Fatalf("analyzer calls = %d, want 0", analyzer.calls)
	}
}

func TestChecksContextBeforeApplyingEachChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	analyzer := &recordingAnalyzer{cancel: cancel}
	source := model.Snapshot{
		ID:        "snapshot",
		Resources: []model.ResourceNode{{ID: "resource"}},
	}

	_, err := simulation.Apply(ctx, analyzer, source, []model.SimulationChange{{Type: "disable-node", TargetID: "resource"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if analyzer.calls != 1 {
		t.Fatalf("analyzer calls = %d, want 1", analyzer.calls)
	}
}

type recordingAnalyzer struct {
	calls  int
	cancel context.CancelFunc
}

func (a *recordingAnalyzer) Analyze(_ context.Context, input model.Snapshot) (model.Snapshot, error) {
	a.calls++
	if a.cancel != nil && a.calls == 1 {
		a.cancel()
	}
	return input, nil
}
