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

const (
	RelationshipObserved  = model.RelationshipObserved
	RelationshipDerived   = model.RelationshipDerived
	RelationshipHeuristic = model.RelationshipHeuristic

	ConfidenceHigh   = model.ConfidenceHigh
	ConfidenceMedium = model.ConfidenceMedium
	ConfidenceLow    = model.ConfidenceLow
)

type (
	ResourceNode       = model.ResourceNode
	EvidenceRecord     = model.EvidenceRecord
	RelationshipOrigin = model.RelationshipOrigin
	Confidence         = model.Confidence
	RelationshipEdge   = model.RelationshipEdge
	Remediation        = model.Remediation
	Finding            = model.Finding
	AttackStep         = model.AttackStep
	AttackPath         = model.AttackPath
	SimulationChange   = model.SimulationChange
	SimulationPreset   = model.SimulationPreset
	SimulationResult   = model.SimulationResult
	SimulationDelta    = model.SimulationDelta
	Snapshot           = model.Snapshot
	AnalysisMetadata   = model.AnalysisMetadata
	PathSearchMetadata = model.PathSearchMetadata
	Scope              = model.Scope

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
