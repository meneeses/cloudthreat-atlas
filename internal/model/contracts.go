package model

import "context"

// Scope limits collection to an explicitly selected subscription or resource group.
type Scope struct {
	SubscriptionID string `json:"subscriptionId"`
	ResourceGroup  string `json:"resourceGroup,omitempty"`
}

// Graph is the read-only view consumed by rules and path analyzers.
type Graph interface {
	Resources() []ResourceNode
	Relationships() []RelationshipEdge
	Node(id string) (ResourceNode, bool)
	Outgoing(id string) []RelationshipEdge
}

// Collector reads cloud metadata without changing the source environment.
type Collector interface {
	Collect(ctx context.Context, scope Scope) (Snapshot, error)
}

// Rule evaluates a graph and emits deterministic defensive findings.
type Rule interface {
	ID() string
	Evaluate(ctx context.Context, graph Graph) ([]Finding, error)
}

// PathAnalyzer identifies explainable paths from entry points to critical assets.
type PathAnalyzer interface {
	Analyze(ctx context.Context, graph Graph) ([]AttackPath, error)
}

// ReportFormat is a supported portable report representation.
type ReportFormat string

const (
	ReportJSON     ReportFormat = "json"
	ReportHTML     ReportFormat = "html"
	ReportMarkdown ReportFormat = "markdown"
	ReportSARIF    ReportFormat = "sarif"
)

// Reporter serializes a snapshot without mutating it.
type Reporter interface {
	Render(snapshot Snapshot, format ReportFormat) ([]byte, error)
}
