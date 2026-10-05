// Package atlas exposes the stable data contracts used by collectors, rules,
// analysis engines, simulations, and reporters.
package atlas

import "github.com/meneeses/cloudthreat-atlas/internal/model"

// Severity describes the impact assigned to a finding, resource, or attack path.
type Severity = model.Severity

const (
	SeverityCritical = model.SeverityCritical
	SeverityHigh     = model.SeverityHigh
	SeverityMedium   = model.SeverityMedium
	SeverityLow      = model.SeverityLow
	SeverityInfo     = model.SeverityInfo
)

type (
	ResourceNode     = model.ResourceNode
	RelationshipEdge = model.RelationshipEdge
	Remediation      = model.Remediation
	Finding          = model.Finding
	AttackStep       = model.AttackStep
	AttackPath       = model.AttackPath
	SimulationChange = model.SimulationChange
	SimulationPreset = model.SimulationPreset
	SimulationResult = model.SimulationResult
	Snapshot         = model.Snapshot
	Scope            = model.Scope

	Graph        = model.Graph
	Collector    = model.Collector
	Rule         = model.Rule
	PathAnalyzer = model.PathAnalyzer
	Reporter     = model.Reporter
	ReportFormat = model.ReportFormat
)

const (
	ReportJSON     = model.ReportJSON
	ReportHTML     = model.ReportHTML
	ReportMarkdown = model.ReportMarkdown
	ReportSARIF    = model.ReportSARIF
)
