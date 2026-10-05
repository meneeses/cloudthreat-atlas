package graph_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestPathAnalyzerReportsDeterministicTruncation(t *testing.T) {
	resources := []model.ResourceNode{{ID: "entry", Category: "entry_point"}, {ID: "target", Criticality: model.SeverityCritical}}
	var relationships []model.RelationshipEdge
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("middle-%02d", i)
		resources = append(resources, model.ResourceNode{ID: id})
		relationships = append(relationships,
			model.RelationshipEdge{ID: "to-" + id, Source: "entry", Target: id, Exploitable: true},
			model.RelationshipEdge{ID: "from-" + id, Source: id, Target: "target", Exploitable: true})
	}
	g, err := graph.New(resources, relationships)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &graph.PathAnalyzer{MaxDepth: 8, MaxPaths: 100, MaxPathsPerTarget: 3, MaxExpansions: 100}
	first, err := analyzer.AnalyzeWithMetadata(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	second, err := analyzer.AnalyzeWithMetadata(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("bounded analysis is not deterministic")
	}
	if len(first.Paths) != 3 || !first.Metadata.Truncated || first.Metadata.Reason != "max_paths_per_target" {
		t.Fatalf("result = %+v", first)
	}
}

func TestParallelRelationshipsRemainDistinctAttackPaths(t *testing.T) {
	resources := []model.ResourceNode{
		{ID: "entry", Category: "entry_point"},
		{ID: "target", Criticality: model.SeverityCritical},
	}
	relationships := []model.RelationshipEdge{
		{ID: "grant-a", Source: "entry", Target: "target", Exploitable: true},
		{ID: "grant-b", Source: "entry", Target: "target", Exploitable: true},
	}
	g, err := graph.New(resources, relationships)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := graph.NewPathAnalyzer().Analyze(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].ID == paths[1].ID {
		t.Fatalf("parallel-edge paths = %#v, want two distinct identities", paths)
	}
	got := map[string]bool{paths[0].RelationshipIDs[0]: true, paths[1].RelationshipIDs[0]: true}
	if !got["grant-a"] || !got["grant-b"] {
		t.Fatalf("relationship evidence = %v", got)
	}
}

func TestPathAnalyzerReportsDepthTruncationOnlyWhenTraversalCanContinue(t *testing.T) {
	resources := []model.ResourceNode{{ID: "entry", Category: "entry_point"}}
	relationships := make([]model.RelationshipEdge, 0, 9)
	previous := "entry"
	for index := 1; index <= 8; index++ {
		id := fmt.Sprintf("node-%d", index)
		resources = append(resources, model.ResourceNode{ID: id})
		relationships = append(relationships, model.RelationshipEdge{ID: fmt.Sprintf("edge-%d", index), Source: previous, Target: id, Exploitable: true})
		previous = id
	}
	resources = append(resources, model.ResourceNode{ID: "target", Criticality: model.SeverityCritical})
	relationships = append(relationships, model.RelationshipEdge{ID: "edge-target", Source: previous, Target: "target", Exploitable: true})
	g, err := graph.New(resources, relationships)
	if err != nil {
		t.Fatal(err)
	}
	result, err := graph.NewPathAnalyzer().AnalyzeWithMetadata(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 0 || !result.Metadata.Truncated || result.Metadata.Reason != "max_depth" {
		t.Fatalf("depth-bounded result = %+v", result)
	}
}

func TestPathAnalyzerCountsTerminalDepthInspectionAgainstExpansionBudget(t *testing.T) {
	resources := []model.ResourceNode{
		{ID: "entry", Category: "entry_point"},
		{ID: "terminal"},
	}
	relationships := []model.RelationshipEdge{
		{ID: "00-enter-terminal", Source: "entry", Target: "terminal", Exploitable: true},
	}
	for index := 0; index < 20; index++ {
		relationships = append(relationships, model.RelationshipEdge{
			ID:          fmt.Sprintf("terminal-cycle-%02d", index),
			Source:      "terminal",
			Target:      "entry",
			Exploitable: true,
		})
	}
	g, err := graph.New(resources, relationships)
	if err != nil {
		t.Fatal(err)
	}

	result, err := (&graph.PathAnalyzer{MaxDepth: 1, MaxPaths: 10, MaxPathsPerTarget: 10, MaxExpansions: 5}).AnalyzeWithMetadata(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Expansions != 5 || !result.Metadata.Truncated || result.Metadata.Reason != "max_expansions" {
		t.Fatalf("terminal inspection result = %+v", result.Metadata)
	}
	if len(result.Paths) != 0 {
		t.Fatalf("paths = %#v, want none", result.Paths)
	}
}

func BenchmarkBoundedPathAnalysis(b *testing.B) {
	resources := []model.ResourceNode{{ID: "entry", Category: "entry_point"}, {ID: "target", Criticality: model.SeverityCritical}}
	var relationships []model.RelationshipEdge
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("middle-%04d", i)
		resources = append(resources, model.ResourceNode{ID: id})
		relationships = append(relationships, model.RelationshipEdge{ID: "a-" + id, Source: "entry", Target: id, Exploitable: true}, model.RelationshipEdge{ID: "b-" + id, Source: id, Target: "target", Exploitable: true})
	}
	g, err := graph.New(resources, relationships)
	if err != nil {
		b.Fatal(err)
	}
	analyzer := graph.NewPathAnalyzer()
	b.ResetTimer()
	for range b.N {
		if _, err := analyzer.AnalyzeWithMetadata(context.Background(), g); err != nil {
			b.Fatal(err)
		}
	}
}
