package analysis

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func scaleFixture(resourceCount, relationshipCount int) model.Snapshot {
	resources := make([]model.ResourceNode, resourceCount)
	for index := range resources {
		resources[index] = model.ResourceNode{
			ID: fmt.Sprintf("scale-resource-%05d", index), Name: fmt.Sprintf("Scale resource %d", index),
			Type: "scale.resource", Category: "resource", Provider: "synthetic", Criticality: model.SeverityMedium,
		}
	}
	if len(resources) > 0 {
		resources[0].Type = "external.internet"
		resources[0].Category = "entry_point"
		resources[0].Criticality = model.SeverityInfo
	}
	relationships := make([]model.RelationshipEdge, relationshipCount)
	for index := range relationships {
		source := index % resourceCount
		target := (index*7919 + 17) % resourceCount
		if target == source {
			target = (target + 1) % resourceCount
		}
		relationships[index] = model.RelationshipEdge{
			ID: fmt.Sprintf("scale-edge-%05d", index), Source: resources[source].ID, Target: resources[target].ID,
			Type: "dependency", Label: "depends on", Exploitable: false,
		}
	}
	return model.Snapshot{
		SchemaVersion: "1.0", ID: "scale-fixture", Name: "Deterministic scale fixture", Provider: "synthetic",
		GeneratedAt: time.Unix(0, 0).UTC(), Resources: resources, Relationships: relationships,
		Findings: []model.Finding{}, AttackPaths: []model.AttackPath{},
	}
}

func TestScaleFixture5KResources20KRelationshipsIsDeterministic(t *testing.T) {
	fixture := scaleFixture(5_000, 20_000)
	engine := NewDefault()
	started := time.Now()
	first, err := engine.Analyze(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Analyze(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("scale analysis is not deterministic")
	}
	if len(first.Resources) != 5_000 || len(first.Relationships) != 20_000 || len(first.AttackPaths) != 0 {
		t.Fatalf("unexpected scale result: resources=%d relationships=%d paths=%d", len(first.Resources), len(first.Relationships), len(first.AttackPaths))
	}
	t.Logf("two deterministic 5k/20k analyses completed in %s", time.Since(started))
}

func BenchmarkAnalyzeScaleFixture5K20K(b *testing.B) {
	fixture := scaleFixture(5_000, 20_000)
	engine := NewDefault()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := engine.Analyze(context.Background(), fixture); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAttachFindingsUsesRelationshipIntersection(t *testing.T) {
	paths := []model.AttackPath{{ID: "a", RelationshipIDs: []string{"r1", "r2"}}, {ID: "b", RelationshipIDs: []string{"r2", "r3"}}}
	findings := []model.Finding{{ID: "both", RelationshipIDs: []string{"r2"}}, {ID: "only-a", RelationshipIDs: []string{"r1", "r2"}}, {ID: "none"}}
	attachFindings(paths, findings)
	if fmt.Sprint(paths[0].FindingIDs) != "[both only-a]" || fmt.Sprint(paths[1].FindingIDs) != "[both]" {
		t.Fatalf("attachments = %+v", paths)
	}
}

func BenchmarkAttachFindingsIndexed(b *testing.B) {
	paths := make([]model.AttackPath, 500)
	for i := range paths {
		paths[i] = model.AttackPath{ID: fmt.Sprint(i), RelationshipIDs: []string{fmt.Sprintf("shared-%d", i%25), fmt.Sprintf("unique-%d", i)}}
	}
	findings := make([]model.Finding, 5000)
	for i := range findings {
		findings[i] = model.Finding{ID: fmt.Sprint(i), RelationshipIDs: []string{fmt.Sprintf("shared-%d", i%25)}}
	}
	b.ResetTimer()
	for range b.N {
		attachFindings(paths, findings)
	}
}
