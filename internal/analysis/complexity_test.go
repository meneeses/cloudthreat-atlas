package analysis

import (
	"context"
	"errors"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestAnalyzeRejectsExcessiveCardinalityBeforeGraphCloning(t *testing.T) {
	snapshot := model.Snapshot{
		ID:        "oversized",
		Resources: make([]model.ResourceNode, defaultSnapshotComplexityLimits.maxResources+1),
	}

	_, err := NewDefault().Analyze(context.Background(), snapshot)
	if !errors.Is(err, ErrSnapshotComplexityExceeded) {
		t.Fatalf("Analyze error = %v, want ErrSnapshotComplexityExceeded", err)
	}
}

func TestValidateSnapshotComplexityCountsNestedCollections(t *testing.T) {
	limits := snapshotComplexityLimits{
		maxResources: 2, maxRelationships: 2, maxPropertyEntries: 2,
		maxEvidenceRecords: 2, maxSimulations: 2, maxSimulationChanges: 2,
		maxRemovedAttackPathRefs: 2,
	}
	tests := []struct {
		name     string
		snapshot model.Snapshot
	}{
		{
			name: "properties",
			snapshot: model.Snapshot{Resources: []model.ResourceNode{
				{Properties: map[string]string{"a": "1", "b": "2", "c": "3"}},
			}},
		},
		{
			name: "evidence",
			snapshot: model.Snapshot{Relationships: []model.RelationshipEdge{
				{Evidence: make([]model.EvidenceRecord, 3)},
			}},
		},
		{
			name: "simulation changes",
			snapshot: model.Snapshot{Simulations: []model.SimulationPreset{
				{Changes: make([]model.SimulationChange, 3)},
			}},
		},
		{
			name: "removed path references",
			snapshot: model.Snapshot{Simulations: []model.SimulationPreset{
				{RemovedAttackPaths: []string{"a", "b", "c"}},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSnapshotComplexity(context.Background(), test.snapshot, limits); !errors.Is(err, ErrSnapshotComplexityExceeded) {
				t.Fatalf("error = %v, want ErrSnapshotComplexityExceeded", err)
			}
		})
	}
}

func TestValidateSnapshotComplexityHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := validateSnapshotComplexity(ctx, model.Snapshot{Resources: []model.ResourceNode{{}}}, defaultSnapshotComplexityLimits)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
