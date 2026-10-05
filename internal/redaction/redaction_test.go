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
		Scope:       &model.Scope{SubscriptionID: "real-sub", ResourceGroup: "patient-prod"},
		GeneratedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		Resources: []model.ResourceNode{
			{ID: resourceID, Name: "prod-db", Type: "Microsoft.Web/sites", Category: "compute", Provider: "azure", Properties: map[string]string{"subscriptionId": "real-sub", "principalId": "secret-principal", "resourceGroup": "patient-prod", "publicNetworkAccess": "enabled"}},
			{ID: "internet-public", Name: "Public Internet", Type: "external.internet", Category: "entry_point", Provider: "external"},
		},
		Relationships: []model.RelationshipEdge{{
			ID: "rel-real-id", Source: "internet-public", Target: resourceID, Type: "role_assignment",
			Label: "Acme Emergency Operator", Description: "prod-db in PATIENT-PROD is assigned the Acme Emergency Operator custom role.", Exploitable: false,
			Properties: map[string]string{"customRole": "true", "targetType": "Microsoft.Storage/storageAccounts", "roleName": "Acme Emergency Operator", "roleDefinitionId": "/subscriptions/real-sub/providers/Microsoft.Authorization/roleDefinitions/abcdef12-3456-7890-abcd-ef1234567890"},
			Evidence:   []model.EvidenceRecord{{Source: "azure-resource-graph", ResourceID: resourceID, Field: "properties.scope", Value: "/subscriptions/real-sub/resourceGroups/patient-prod"}},
		}},
		Findings: []model.Finding{{
			ID: "finding-real", RuleID: "CTA-AZ-004", Title: "Acme Emergency Operator reaches prod-db", Description: "Acme Emergency Operator is assigned.",
			ResourceIDs: []string{resourceID}, RelationshipIDs: []string{"rel-real-id"}, Evidence: []string{"Acme Emergency Operator applies to prod-db in REAL-SUB."},
			EvidenceDetails: []model.EvidenceRecord{{Source: "azure-resource-graph", ResourceID: resourceID, Field: "properties.principalId", Value: "secret-principal"}},
		}},
		AttackPaths: []model.AttackPath{{ID: "path-real-id", Title: "Public path to prod-db", EntryPoint: "internet-public", Target: resourceID, ResourceIDs: []string{"internet-public", resourceID}, RelationshipIDs: []string{"rel-real-id"}}},
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
	for _, forbidden := range []string{"real-sub", "patient-prod", "acme-api", "prod-db", "secret-principal", "abcdef12", "path-real-id", "rel-real-id", "Acme Emergency Operator"} {
		if strings.Contains(strings.ToLower(encoded), strings.ToLower(forbidden)) {
			t.Fatalf("redacted snapshot still contains %q", forbidden)
		}
	}
	if first.Relationships[0].Source != "internet-public" {
		t.Fatal("synthetic public entry point should remain stable")
	}
	if first.Relationships[0].Target != first.Resources[0].ID {
		t.Fatal("redaction broke graph references")
	}
	if len(first.Relationships[0].Evidence) != 0 || len(first.Findings[0].EvidenceDetails) != 0 {
		t.Fatal("redacted snapshot retained structured tenant evidence")
	}
	if first.Relationships[0].Label != "Custom Azure role" {
		t.Fatalf("custom role label = %q", first.Relationships[0].Label)
	}
	if first.Scope == nil || first.Scope.SubscriptionID == "real-sub" || first.Scope.ResourceGroup == "patient-prod" {
		t.Fatalf("scope was not redacted: %#v", first.Scope)
	}
	if first.Scope.ResourceGroup == "resource-group-"+digest("patient-prod") {
		t.Fatal("resource-group alias must not be a generic unkeyed dictionary target")
	}
	if first.Resources[0].Properties["resourceGroup"] != first.Scope.ResourceGroup {
		t.Fatalf("resource property and scope must share the protected alias: resource=%q scope=%q", first.Resources[0].Properties["resourceGroup"], first.Scope.ResourceGroup)
	}
	if first.Resources[0].Properties["resourceGroup"] == "resource-group-"+digest("patient-prod") {
		t.Fatal("resource property must not retain the generic unkeyed alias")
	}
	otherSubscription := model.CloneSnapshot(source)
	otherSubscription.Scope.SubscriptionID = "different-subscription"
	otherRedacted := Redact(otherSubscription)
	if otherRedacted.Scope.ResourceGroup == first.Scope.ResourceGroup {
		t.Fatal("resource-group aliases must be isolated between subscriptions")
	}
	if otherRedacted.Resources[0].Properties["resourceGroup"] == first.Resources[0].Properties["resourceGroup"] {
		t.Fatal("resource property aliases must be isolated between subscriptions")
	}
	if first.Relationships[0].Properties["targetType"] != "Microsoft.Storage/storageAccounts" || first.Relationships[0].Properties["customRole"] != "true" {
		t.Fatalf("safe role semantics were removed: %#v", first.Relationships[0].Properties)
	}
}
