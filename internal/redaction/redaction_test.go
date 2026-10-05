package redaction

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestRedactRemovesTenantIdentifiersWithoutMutatingSource(t *testing.T) {
	const resourceID = "/subscriptions/real-sub/resourceGroups/patient-prod/providers/Microsoft.Web/sites/acme-api"
	source := model.Snapshot{
		SchemaVersion: "1.0", ID: "azure-subscription-123", Name: "Acme Production",
		GeneratedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		Resources: []model.ResourceNode{
			{ID: resourceID, Name: "prod-db", Type: "Microsoft.Web/sites", Category: "compute", Provider: "azure", Properties: map[string]string{"subscriptionId": "real-sub", "principalId": "secret-principal", "resourceGroup": "patient-prod", "publicNetworkAccess": "enabled"}},
			{ID: "internet-public", Name: "Public Internet", Type: "external.internet", Category: "entry_point", Provider: "external"},
		},
		Relationships: []model.RelationshipEdge{{ID: "rel-real-id", Source: "internet-public", Target: resourceID, Type: "role_assignment", Label: "Azure role abcdef12", Description: "prod-db is assigned the custom role.", Exploitable: false, Properties: map[string]string{"roleDefinitionId": "/subscriptions/real-sub/providers/Microsoft.Authorization/roleDefinitions/abcdef12-3456-7890-abcd-ef1234567890"}}},
		AttackPaths:   []model.AttackPath{{ID: "path-real-id", Title: "Public path to prod-db", EntryPoint: "internet-public", Target: resourceID, ResourceIDs: []string{"internet-public", resourceID}, RelationshipIDs: []string{"rel-real-id"}}},
	}
	original := model.CloneSnapshot(source)

	first := Redact(source)
	second := Redact(source)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("redaction must be deterministic")
	}
	if !reflect.DeepEqual(source, original) {
		t.Fatal("redaction mutated the source snapshot")
	}
	encodedBytes, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal redacted snapshot: %v", err)
	}
	encoded := string(encodedBytes)
	for _, forbidden := range []string{"real-sub", "patient-prod", "acme-api", "prod-db", "secret-principal", "abcdef12", "path-real-id", "rel-real-id"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("redacted snapshot still contains %q", forbidden)
		}
	}
	if first.Relationships[0].Source != "internet-public" {
		t.Fatal("synthetic public entry point should remain stable")
	}
	if first.Relationships[0].Target != first.Resources[0].ID {
		t.Fatal("redaction broke graph references")
	}
}
