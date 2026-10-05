package atlas_test

import (
	"fmt"

	atlas "github.com/meneeses/cloudthreat-atlas"
)

func ExampleSnapshot() {
	snapshot := atlas.Snapshot{
		SchemaVersion: "1.0",
		ID:            "example",
		Name:          "Example environment",
		Provider:      "azure",
	}

	fmt.Printf("%s: %s", snapshot.Provider, snapshot.Name)
	// Output: azure: Example environment
}

func ExampleRelationshipEdge() {
	edge := atlas.RelationshipEdge{
		ID:         "public-app",
		Source:     "internet",
		Target:     "app",
		Type:       "public_exposure",
		Label:      "public endpoint",
		Origin:     atlas.RelationshipDerived,
		Confidence: atlas.ConfidenceHigh,
		Evidence: []atlas.EvidenceRecord{{
			Source: "azure-resource-graph",
			Field:  "properties.publicNetworkAccess",
			Value:  "Enabled",
		}},
	}

	fmt.Printf("%s (%s)", edge.Origin, edge.Confidence)
	// Output: derived (high)
}
