package analysis

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/rules"
)

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

	result.AttackPaths, err = e.analyzer.Analyze(ctx, g)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("analyze attack paths: %w", err)
	}
	attachFindings(result.AttackPaths, result.Findings)
	result.RiskScore = riskScore(result.Findings, result.AttackPaths)
	if result.SchemaVersion == "" {
		result.SchemaVersion = "1.0"
	}
	return result, nil
}

func attachFindings(paths []model.AttackPath, findings []model.Finding) {
	for i := range paths {
		for _, finding := range findings {
			if isSubset(finding.RelationshipIDs, paths[i].RelationshipIDs) {
				paths[i].FindingIDs = append(paths[i].FindingIDs, finding.ID)
			}
		}
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
