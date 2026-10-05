package model

import (
	"maps"
	"slices"
	"time"
)

// Severity represents the impact assigned to a finding, resource, or attack path.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ResourceNode is an Azure resource, identity, external actor, or delivery-system node.
type ResourceNode struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Category    string            `json:"category"`
	Provider    string            `json:"provider,omitempty"`
	Location    string            `json:"location,omitempty"`
	Criticality Severity          `json:"criticality,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// EvidenceRecord links a normalized fact to the non-secret Azure metadata that
// supports it. All fields are optional so snapshots produced before evidence
// tracking continue to decode and re-encode without synthetic values.
type EvidenceRecord struct {
	Source     string `json:"source,omitempty"`
	ResourceID string `json:"resourceId,omitempty"`
	Field      string `json:"field,omitempty"`
	Value      string `json:"value,omitempty"`
}

// RelationshipOrigin distinguishes facts returned by Azure from conclusions
// made by deterministic normalization and lower-certainty security hypotheses.
type RelationshipOrigin string

const (
	RelationshipObserved  RelationshipOrigin = "observed"
	RelationshipDerived   RelationshipOrigin = "derived"
	RelationshipHeuristic RelationshipOrigin = "heuristic"
)

// Confidence is the collector's confidence in a normalized relationship.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// RelationshipEdge describes a directed relationship that can participate in an attack path.
type RelationshipEdge struct {
	ID          string             `json:"id"`
	Source      string             `json:"source"`
	Target      string             `json:"target"`
	Type        string             `json:"type"`
	Label       string             `json:"label"`
	Description string             `json:"description,omitempty"`
	Exploitable bool               `json:"exploitable"`
	Properties  map[string]string  `json:"properties,omitempty"`
	Origin      RelationshipOrigin `json:"origin,omitempty"`
	Confidence  Confidence         `json:"confidence,omitempty"`
	Evidence    []EvidenceRecord   `json:"evidence,omitempty"`
}

// Remediation explains a safe defensive change. CloudThreat Atlas never applies it automatically.
type Remediation struct {
	Summary string   `json:"summary"`
	Steps   []string `json:"steps"`
}

// Finding is a deterministic result emitted by a native Go rule.
type Finding struct {
	ID              string           `json:"id"`
	RuleID          string           `json:"ruleId"`
	Title           string           `json:"title"`
	Description     string           `json:"description"`
	Severity        Severity         `json:"severity"`
	Score           int              `json:"score"`
	ResourceIDs     []string         `json:"resourceIds"`
	RelationshipIDs []string         `json:"relationshipIds,omitempty"`
	Evidence        []string         `json:"evidence"`
	EvidenceDetails []EvidenceRecord `json:"evidenceDetails,omitempty"`
	Remediation     Remediation      `json:"remediation"`
}

// AttackStep is one explainable hop in an attack path.
type AttackStep struct {
	Order          int    `json:"order"`
	Source         string `json:"source"`
	Target         string `json:"target"`
	RelationshipID string `json:"relationshipId"`
	Narrative      string `json:"narrative"`
}

// AttackPath is an ordered path from an entry point to a critical resource.
type AttackPath struct {
	ID              string       `json:"id"`
	Title           string       `json:"title"`
	Description     string       `json:"description"`
	Severity        Severity     `json:"severity"`
	Score           int          `json:"score"`
	EntryPoint      string       `json:"entryPoint"`
	Target          string       `json:"target"`
	ResourceIDs     []string     `json:"resourceIds"`
	RelationshipIDs []string     `json:"relationshipIds"`
	FindingIDs      []string     `json:"findingIds,omitempty"`
	Steps           []AttackStep `json:"steps"`
}

// SimulationChange is a hypothetical graph change. Supported types are remove-edge,
// disable-node, and set-property.
type SimulationChange struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"`
	TargetID    string `json:"targetId"`
	Property    string `json:"property,omitempty"`
	Value       string `json:"value,omitempty"`
	Description string `json:"description,omitempty"`
}

// SimulationPreset is a safe, pre-calculated remediation scenario for the static demo.
type SimulationPreset struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	Changes            []SimulationChange `json:"changes"`
	RiskScoreAfter     int                `json:"riskScoreAfter"`
	RemovedAttackPaths []string           `json:"removedAttackPaths"`
}

// Snapshot is a complete and portable view of a cloud environment and its analysis.
type Snapshot struct {
	SchemaVersion string             `json:"schemaVersion"`
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Provider      string             `json:"provider"`
	Scope         *Scope             `json:"scope,omitempty"`
	GeneratedAt   time.Time          `json:"generatedAt"`
	Description   string             `json:"description,omitempty"`
	Resources     []ResourceNode     `json:"resources"`
	Relationships []RelationshipEdge `json:"relationships"`
	Findings      []Finding          `json:"findings"`
	AttackPaths   []AttackPath       `json:"attackPaths"`
	RiskScore     int                `json:"riskScore"`
	Simulations   []SimulationPreset `json:"simulations,omitempty"`
	Analysis      *AnalysisMetadata  `json:"analysis,omitempty"`
}

// AnalysisMetadata reports safety bounds applied while deriving attack paths.
// It is optional so existing schema 1.0 snapshots remain byte-for-byte compatible.
type AnalysisMetadata struct {
	PathSearch PathSearchMetadata `json:"pathSearch"`
}

// PathSearchMetadata makes bounded search explicit instead of silently returning
// an incomplete set for very large or highly connected graphs.
type PathSearchMetadata struct {
	MaxDepth          int    `json:"maxDepth"`
	MaxPaths          int    `json:"maxPaths"`
	MaxPathsPerTarget int    `json:"maxPathsPerTarget"`
	MaxExpansions     int    `json:"maxExpansions"`
	Expansions        int    `json:"expansions"`
	Truncated         bool   `json:"truncated"`
	Reason            string `json:"reason,omitempty"`
}

// SimulationResult contains the non-destructive result of applying hypothetical changes.
type SimulationResult struct {
	SnapshotID           string             `json:"snapshotId"`
	Changes              []SimulationChange `json:"changes"`
	RemovedAttackPathIDs []string           `json:"removedAttackPathIds"`
	RemainingAttackPaths []AttackPath       `json:"remainingAttackPaths"`
	RiskScoreBefore      int                `json:"riskScoreBefore"`
	RiskScoreAfter       int                `json:"riskScoreAfter"`
	ResultingSnapshot    Snapshot           `json:"resultingSnapshot"`
}

// SimulationDelta is the compact form used by workspace clients that do not
// need a complete duplicate snapshot in the response.
type SimulationDelta struct {
	SnapshotID               string             `json:"snapshotId"`
	Changes                  []SimulationChange `json:"changes"`
	RemovedAttackPathIDs     []string           `json:"removedAttackPathIds"`
	RemainingAttackPathCount int                `json:"remainingAttackPathCount"`
	RiskScoreBefore          int                `json:"riskScoreBefore"`
	RiskScoreAfter           int                `json:"riskScoreAfter"`
	RiskScoreDelta           int                `json:"riskScoreDelta"`
}

// Delta returns a compact, immutable summary of a simulation.
func (result SimulationResult) Delta() SimulationDelta {
	return SimulationDelta{
		SnapshotID: result.SnapshotID, Changes: slices.Clone(result.Changes),
		RemovedAttackPathIDs:     slices.Clone(result.RemovedAttackPathIDs),
		RemainingAttackPathCount: len(result.RemainingAttackPaths),
		RiskScoreBefore:          result.RiskScoreBefore, RiskScoreAfter: result.RiskScoreAfter,
		RiskScoreDelta: result.RiskScoreAfter - result.RiskScoreBefore,
	}
}

// CloneSnapshot returns a deep-enough copy for analysis and simulation. Mutating the
// returned graph, findings, or properties cannot mutate the source snapshot.
func CloneSnapshot(source Snapshot) Snapshot {
	clone := source
	if source.Scope != nil {
		scope := *source.Scope
		clone.Scope = &scope
	}
	clone.Resources = slices.Clone(source.Resources)
	for i := range clone.Resources {
		clone.Resources[i].Properties = maps.Clone(source.Resources[i].Properties)
	}
	clone.Relationships = slices.Clone(source.Relationships)
	for i := range clone.Relationships {
		clone.Relationships[i].Properties = maps.Clone(source.Relationships[i].Properties)
		clone.Relationships[i].Evidence = slices.Clone(source.Relationships[i].Evidence)
	}
	clone.Findings = slices.Clone(source.Findings)
	for i := range clone.Findings {
		clone.Findings[i].ResourceIDs = slices.Clone(source.Findings[i].ResourceIDs)
		clone.Findings[i].RelationshipIDs = slices.Clone(source.Findings[i].RelationshipIDs)
		clone.Findings[i].Evidence = slices.Clone(source.Findings[i].Evidence)
		clone.Findings[i].EvidenceDetails = slices.Clone(source.Findings[i].EvidenceDetails)
		clone.Findings[i].Remediation.Steps = slices.Clone(source.Findings[i].Remediation.Steps)
	}
	clone.AttackPaths = slices.Clone(source.AttackPaths)
	for i := range clone.AttackPaths {
		clone.AttackPaths[i].ResourceIDs = slices.Clone(source.AttackPaths[i].ResourceIDs)
		clone.AttackPaths[i].RelationshipIDs = slices.Clone(source.AttackPaths[i].RelationshipIDs)
		clone.AttackPaths[i].FindingIDs = slices.Clone(source.AttackPaths[i].FindingIDs)
		clone.AttackPaths[i].Steps = slices.Clone(source.AttackPaths[i].Steps)
	}
	clone.Simulations = slices.Clone(source.Simulations)
	for i := range clone.Simulations {
		clone.Simulations[i].Changes = slices.Clone(source.Simulations[i].Changes)
		clone.Simulations[i].RemovedAttackPaths = slices.Clone(source.Simulations[i].RemovedAttackPaths)
	}
	if source.Analysis != nil {
		analysis := *source.Analysis
		clone.Analysis = &analysis
	}
	return clone
}
