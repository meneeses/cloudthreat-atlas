package simulation

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Analyzer is the subset of the analysis engine required by the simulator.
type Analyzer interface {
	Analyze(ctx context.Context, input model.Snapshot) (model.Snapshot, error)
}

// Apply analyzes hypothetical changes on a clone and never mutates source.
func Apply(ctx context.Context, analyzer Analyzer, source model.Snapshot, changes []model.SimulationChange) (model.SimulationResult, error) {
	before, err := analyzer.Analyze(ctx, source)
	if err != nil {
		return model.SimulationResult{}, fmt.Errorf("analyze original snapshot: %w", err)
	}
	changed := model.CloneSnapshot(source)
	for _, change := range changes {
		if err := applyChange(&changed, change); err != nil {
			return model.SimulationResult{}, err
		}
	}
	after, err := analyzer.Analyze(ctx, changed)
	if err != nil {
		return model.SimulationResult{}, fmt.Errorf("analyze simulated snapshot: %w", err)
	}

	remaining := make(map[string]bool, len(after.AttackPaths))
	for _, path := range after.AttackPaths {
		remaining[path.ID] = true
	}
	var removed []string
	for _, path := range before.AttackPaths {
		if !remaining[path.ID] {
			removed = append(removed, path.ID)
		}
	}
	sort.Strings(removed)
	return model.SimulationResult{
		SnapshotID:           before.ID,
		Changes:              slices.Clone(changes),
		RemovedAttackPathIDs: removed,
		RemainingAttackPaths: slices.Clone(after.AttackPaths),
		RiskScoreBefore:      before.RiskScore,
		RiskScoreAfter:       after.RiskScore,
		ResultingSnapshot:    after,
	}, nil
}

func applyChange(snapshot *model.Snapshot, change model.SimulationChange) error {
	switch change.Type {
	case "remove-edge":
		for i, edge := range snapshot.Relationships {
			if edge.ID == change.TargetID {
				snapshot.Relationships = append(snapshot.Relationships[:i:i], snapshot.Relationships[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("simulation target relationship %q was not found", change.TargetID)
	case "disable-node":
		found := false
		for i, node := range snapshot.Resources {
			if node.ID == change.TargetID {
				snapshot.Resources = append(snapshot.Resources[:i:i], snapshot.Resources[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("simulation target resource %q was not found", change.TargetID)
		}
		filtered := snapshot.Relationships[:0]
		for _, edge := range snapshot.Relationships {
			if edge.Source != change.TargetID && edge.Target != change.TargetID {
				filtered = append(filtered, edge)
			}
		}
		snapshot.Relationships = filtered
		return nil
	case "set-property":
		if change.Property == "" {
			return fmt.Errorf("set-property change requires property")
		}
		for i := range snapshot.Resources {
			if snapshot.Resources[i].ID == change.TargetID {
				if snapshot.Resources[i].Properties == nil {
					snapshot.Resources[i].Properties = make(map[string]string)
				}
				snapshot.Resources[i].Properties[change.Property] = change.Value
				return nil
			}
		}
		return fmt.Errorf("simulation target resource %q was not found", change.TargetID)
	default:
		return fmt.Errorf("unsupported simulation change type %q", change.Type)
	}
}
