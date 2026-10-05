// Package comparison computes deterministic changes between analyzed snapshots.
package comparison

import (
	"sort"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Result summarizes risk and graph changes from BaseSnapshotID to TargetSnapshotID.
type Result struct {
	BaseSnapshotID     string   `json:"baseSnapshotId"`
	TargetSnapshotID   string   `json:"targetSnapshotId"`
	RiskScoreBefore    int      `json:"riskScoreBefore"`
	RiskScoreAfter     int      `json:"riskScoreAfter"`
	RiskScoreDelta     int      `json:"riskScoreDelta"`
	ResourceDelta      int      `json:"resourceDelta"`
	FindingDelta       int      `json:"findingDelta"`
	AttackPathDelta    int      `json:"attackPathDelta"`
	AddedResourceIDs   []string `json:"addedResourceIds"`
	RemovedResourceIDs []string `json:"removedResourceIds"`
	Resources          Change   `json:"resources"`
	Relationships      Change   `json:"relationships"`
	Findings           Change   `json:"findings"`
	AttackPaths        Change   `json:"attackPaths"`
}

// Change contains stable sorted identifier sets.
type Change struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Compare returns an identifier-level comparison suitable for CLI and API use.
func Compare(base, target model.Snapshot) Result {
	result := Result{
		BaseSnapshotID: base.ID, TargetSnapshotID: target.ID,
		RiskScoreBefore: base.RiskScore, RiskScoreAfter: target.RiskScore,
		RiskScoreDelta:  target.RiskScore - base.RiskScore,
		ResourceDelta:   len(target.Resources) - len(base.Resources),
		FindingDelta:    len(target.Findings) - len(base.Findings),
		AttackPathDelta: len(target.AttackPaths) - len(base.AttackPaths),
		Resources:       diff(idsResources(base.Resources), idsResources(target.Resources)),
		Relationships:   diff(idsRelationships(base.Relationships), idsRelationships(target.Relationships)),
		Findings:        diff(idsFindings(base.Findings), idsFindings(target.Findings)),
		AttackPaths:     diff(idsPaths(base.AttackPaths), idsPaths(target.AttackPaths)),
	}
	result.AddedResourceIDs = result.Resources.Added
	result.RemovedResourceIDs = result.Resources.Removed
	return result
}

func diff(before, after map[string]struct{}) Change {
	var result Change
	for id := range after {
		if _, ok := before[id]; !ok {
			result.Added = append(result.Added, id)
		}
	}
	for id := range before {
		if _, ok := after[id]; !ok {
			result.Removed = append(result.Removed, id)
		}
	}
	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	return result
}

func idsResources(values []model.ResourceNode) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value.ID] = struct{}{}
	}
	return result
}
func idsRelationships(values []model.RelationshipEdge) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value.ID] = struct{}{}
	}
	return result
}
func idsFindings(values []model.Finding) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value.ID] = struct{}{}
	}
	return result
}
func idsPaths(values []model.AttackPath) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value.ID] = struct{}{}
	}
	return result
}
