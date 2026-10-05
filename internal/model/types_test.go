package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelationshipEvidenceIsBackwardCompatibleAndOptional(t *testing.T) {
	legacy := `{"id":"rel","source":"a","target":"b","type":"contains","label":"contains","exploitable":false}`
	var edge RelationshipEdge
	if err := json.Unmarshal([]byte(legacy), &edge); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(edge)
	if err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range []string{`"origin"`, `"confidence"`, `"evidence"`} {
		if strings.Contains(string(encoded), unexpected) {
			t.Fatalf("legacy relationship gained optional field %s: %s", unexpected, encoded)
		}
	}

	edge.Origin = RelationshipDerived
	edge.Confidence = ConfidenceHigh
	edge.Evidence = []EvidenceRecord{{Source: "azure-resource-graph", ResourceID: "b", Field: "properties.publicNetworkAccess", Value: "Enabled"}}
	encoded, err = json.Marshal(edge)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"origin":"derived"`, `"confidence":"high"`, `"evidence":[`} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("enriched relationship lacks %s: %s", expected, encoded)
		}
	}
}

func TestCloneSnapshotCopiesStructuredEvidence(t *testing.T) {
	source := Snapshot{
		Scope:         &Scope{SubscriptionID: "11111111-2222-3333-4444-555555555555", ResourceGroup: "clinical-prod"},
		Relationships: []RelationshipEdge{{ID: "edge", Evidence: []EvidenceRecord{{Value: "original"}}}},
		Findings:      []Finding{{ID: "finding", EvidenceDetails: []EvidenceRecord{{Value: "original"}}}},
	}
	clone := CloneSnapshot(source)
	clone.Scope.ResourceGroup = "changed"
	clone.Relationships[0].Evidence[0].Value = "changed"
	clone.Findings[0].EvidenceDetails[0].Value = "changed"
	if source.Scope.ResourceGroup != "clinical-prod" || source.Relationships[0].Evidence[0].Value != "original" || source.Findings[0].EvidenceDetails[0].Value != "original" {
		t.Fatal("snapshot pointers or structured evidence were not cloned")
	}
}
