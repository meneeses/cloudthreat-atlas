package analysis

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/rules"
)

// ErrSnapshotComplexityExceeded means a portable snapshot is structurally too
// large to analyze safely. Byte limits alone do not prevent a compact JSON file
// from containing enough tiny objects to amplify memory during indexing.
var ErrSnapshotComplexityExceeded = errors.New("snapshot complexity limit exceeded")

type snapshotComplexityLimits struct {
	maxResources             int
	maxRelationships         int
	maxPropertyEntries       int
	maxEvidenceRecords       int
	maxSimulations           int
	maxSimulationChanges     int
	maxRemovedAttackPathRefs int
}

var defaultSnapshotComplexityLimits = snapshotComplexityLimits{
	maxResources:             100_000,
	maxRelationships:         500_000,
	maxPropertyEntries:       2_000_000,
	maxEvidenceRecords:       1_000_000,
	maxSimulations:           1_000,
	maxSimulationChanges:     10_000,
	maxRemovedAttackPathRefs: 100_000,
}

// Engine evaluates native rules, discovers attack paths, and computes a risk score.
type Engine struct {
	rules    []model.Rule
	analyzer model.PathAnalyzer
}

// New constructs an analysis engine from explicitly supplied components.
func New(ruleset []model.Rule, analyzer model.PathAnalyzer) *Engine {
	return &Engine{rules: slices.Clone(ruleset), analyzer: analyzer}
}

// NewDefault constructs the deterministic built-in analysis engine.
func NewDefault() *Engine {
	return New(rules.Default(), graph.NewPathAnalyzer())
}

// Analyze returns a new analyzed snapshot and never mutates input.
func (e *Engine) Analyze(ctx context.Context, input model.Snapshot) (model.Snapshot, error) {
	if input.ID == "" {
		return model.Snapshot{}, fmt.Errorf("snapshot id must not be empty")
	}
	if err := validateSnapshotComplexity(ctx, input, defaultSnapshotComplexityLimits); err != nil {
		return model.Snapshot{}, err
	}
	// Findings, paths, and analysis metadata are derived below. Do not deep-copy
	// attacker-supplied stale results only to discard them immediately.
	input.Findings = nil
	input.AttackPaths = nil
	input.Analysis = nil
	result := model.CloneSnapshot(input)
	g, err := graph.New(result.Resources, result.Relationships)
	if err != nil {
		return model.Snapshot{}, err
	}

	result.Findings = nil
	for _, rule := range e.rules {
		findings, evaluateErr := rule.Evaluate(ctx, g)
		if evaluateErr != nil {
			return model.Snapshot{}, fmt.Errorf("evaluate rule %s: %w", rule.ID(), evaluateErr)
		}
		result.Findings = append(result.Findings, findings...)
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].ID < result.Findings[j].ID })

	if bounded, ok := e.analyzer.(interface {
		AnalyzeWithMetadata(context.Context, model.Graph) (graph.PathResult, error)
	}); ok {
		pathResult, pathErr := bounded.AnalyzeWithMetadata(ctx, g)
		if pathErr != nil {
			return model.Snapshot{}, fmt.Errorf("analyze attack paths: %w", pathErr)
		}
		result.AttackPaths = pathResult.Paths
		if pathResult.Metadata.Truncated {
			result.Analysis = &model.AnalysisMetadata{PathSearch: pathResult.Metadata}
		} else {
			result.Analysis = nil
		}
	} else {
		result.AttackPaths, err = e.analyzer.Analyze(ctx, g)
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("analyze attack paths: %w", err)
		}
	}
	attachFindings(result.AttackPaths, result.Findings)
	result.RiskScore = riskScore(result.Findings, result.AttackPaths)
	if result.SchemaVersion == "" {
		result.SchemaVersion = "1.0"
	}
	return result, nil
}

func validateSnapshotComplexity(ctx context.Context, snapshot model.Snapshot, limits snapshotComplexityLimits) error {
	check := func(label string, value, limit int) error {
		if value > limit {
			return fmt.Errorf("%w: %s has %d entries (limit %d)", ErrSnapshotComplexityExceeded, label, value, limit)
		}
		return nil
	}
	if err := check("resources", len(snapshot.Resources), limits.maxResources); err != nil {
		return err
	}
	if err := check("relationships", len(snapshot.Relationships), limits.maxRelationships); err != nil {
		return err
	}
	if err := check("simulations", len(snapshot.Simulations), limits.maxSimulations); err != nil {
		return err
	}

	propertyEntries := 0
	evidenceRecords := 0
	for i := range snapshot.Resources {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		propertyEntries += len(snapshot.Resources[i].Properties)
		if err := check("resource and relationship properties", propertyEntries, limits.maxPropertyEntries); err != nil {
			return err
		}
	}
	for i := range snapshot.Relationships {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		propertyEntries += len(snapshot.Relationships[i].Properties)
		evidenceRecords += len(snapshot.Relationships[i].Evidence)
		if err := check("resource and relationship properties", propertyEntries, limits.maxPropertyEntries); err != nil {
			return err
		}
		if err := check("relationship evidence records", evidenceRecords, limits.maxEvidenceRecords); err != nil {
			return err
		}
	}

	simulationChanges := 0
	removedAttackPathRefs := 0
	for i := range snapshot.Simulations {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		simulationChanges += len(snapshot.Simulations[i].Changes)
		removedAttackPathRefs += len(snapshot.Simulations[i].RemovedAttackPaths)
		if err := check("simulation changes", simulationChanges, limits.maxSimulationChanges); err != nil {
			return err
		}
		if err := check("removed attack-path references", removedAttackPathRefs, limits.maxRemovedAttackPathRefs); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func attachFindings(paths []model.AttackPath, findings []model.Finding) {
	byRelationship := make(map[string][]int)
	for i := range paths {
		paths[i].FindingIDs = nil
		for _, relationshipID := range paths[i].RelationshipIDs {
			byRelationship[relationshipID] = append(byRelationship[relationshipID], i)
		}
	}
	for _, finding := range findings {
		if len(finding.RelationshipIDs) == 0 {
			continue
		}
		candidates := byRelationship[finding.RelationshipIDs[0]]
		for _, pathIndex := range candidates {
			if isSubset(finding.RelationshipIDs, paths[pathIndex].RelationshipIDs) {
				paths[pathIndex].FindingIDs = append(paths[pathIndex].FindingIDs, finding.ID)
			}
		}
	}
	for i := range paths {
		sort.Strings(paths[i].FindingIDs)
	}
}

func isSubset(needles, haystack []string) bool {
	if len(needles) == 0 {
		return false
	}
	for _, needle := range needles {
		if !slices.Contains(haystack, needle) {
			return false
		}
	}
	return true
}

func riskScore(findings []model.Finding, paths []model.AttackPath) int {
	count := len(findings) + len(paths)
	if count == 0 {
		return 0
	}
	total := 0
	for _, finding := range findings {
		total += finding.Score
	}
	for _, path := range paths {
		total += path.Score
	}
	average := float64(total) / float64(count)
	exposureUnits := min(count, 6)
	exposureFactor := 0.5 + (0.5 * float64(exposureUnits) / 6.0)
	return int(math.Round(average * exposureFactor))
}
