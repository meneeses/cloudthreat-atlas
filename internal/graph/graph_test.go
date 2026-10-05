package graph_test

import (
	"context"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestGraphSortsOutgoingAndRejectsBrokenTopology(t *testing.T) {
	nodes := []model.ResourceNode{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	edges := []model.RelationshipEdge{{ID: "z", Source: "a", Target: "c"}, {ID: "a", Source: "a", Target: "b"}}
	g, err := graph.New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	outgoing := g.Outgoing("a")
	if len(outgoing) != 2 || outgoing[0].ID != "a" || outgoing[1].ID != "z" {
		t.Fatalf("outgoing edges are not deterministic: %#v", outgoing)
	}
	if _, err := graph.New(nodes, []model.RelationshipEdge{{ID: "broken", Source: "a", Target: "missing"}}); err == nil {
		t.Fatal("graph accepted an edge with an unknown target")
	}
	if _, err := graph.New(nodes, []model.RelationshipEdge{{ID: "duplicate", Source: "a", Target: "b"}, {ID: "duplicate", Source: "b", Target: "c"}}); err == nil {
		t.Fatal("graph accepted duplicate relationship identifiers")
	}
}

func TestPathAnalyzerUsesCapabilityEdgesAndIgnoresContainment(t *testing.T) {
	nodes := []model.ResourceNode{
		{ID: "internet", Name: "Internet", Type: "external.internet", Category: "entry_point"},
		{ID: "app", Name: "API", Type: "Microsoft.Web/sites", Category: "compute"},
		{ID: "identity", Name: "API identity", Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity"},
		{ID: "rg", Name: "Production", Type: "Microsoft.Resources/resourceGroups", Category: "scope"},
		{ID: "storage", Name: "Patient storage", Type: "Microsoft.Storage/storageAccounts", Category: "data", Criticality: model.SeverityCritical},
	}
	base := []model.RelationshipEdge{
		{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
		{ID: "identity", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
		{ID: "role", Source: "identity", Target: "rg", Type: "role_management", Exploitable: true},
		{ID: "contains", Source: "rg", Target: "storage", Type: "contains", Exploitable: false},
	}
	g, err := graph.New(nodes, base)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := graph.NewPathAnalyzer().Analyze(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("non-exploitable containment created paths: %#v", paths)
	}

	capability := append([]model.RelationshipEdge{}, base...)
	capability = append(capability, model.RelationshipEdge{ID: "data", Source: "identity", Target: "storage", Type: "data_access", Exploitable: true, Label: "Storage Blob Data Contributor"})
	g, err = graph.New(nodes, capability)
	if err != nil {
		t.Fatal(err)
	}
	paths, err = graph.NewPathAnalyzer().Analyze(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("capability graph produced %d paths, want 1", len(paths))
	}
	wantEdges := []string{"public", "identity", "data"}
	if len(paths[0].RelationshipIDs) != len(wantEdges) {
		t.Fatalf("path edges = %v", paths[0].RelationshipIDs)
	}
	for i, edgeID := range wantEdges {
		if paths[0].RelationshipIDs[i] != edgeID {
			t.Fatalf("path edges = %v, want %v", paths[0].RelationshipIDs, wantEdges)
		}
	}
}

func TestPathAnalyzerIsDeterministic(t *testing.T) {
	nodes := []model.ResourceNode{
		{ID: "internet", Type: "external.internet", Category: "entry_point"},
		{ID: "critical-b", Type: "b", Criticality: model.SeverityCritical},
		{ID: "critical-a", Type: "a", Criticality: model.SeverityCritical},
	}
	edges := []model.RelationshipEdge{
		{ID: "b", Source: "internet", Target: "critical-b", Exploitable: true},
		{ID: "a", Source: "internet", Target: "critical-a", Exploitable: true},
	}
	g, err := graph.New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := graph.NewPathAnalyzer().Analyze(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].ID > paths[1].ID {
		t.Fatalf("paths are not deterministically sorted: %#v", paths)
	}
}
