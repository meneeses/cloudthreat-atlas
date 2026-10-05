package rules

import (
	"context"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestAzureExposureRuleSupportsBothManagedIdentityKinds(t *testing.T) {
	for _, identityType := range []string{"Microsoft.ManagedIdentity/systemAssignedIdentities", "Microsoft.ManagedIdentity/userAssignedIdentities"} {
		t.Run(identityType, func(t *testing.T) {
			g := mustGraph(t,
				[]model.ResourceNode{
					{ID: "internet", Name: "Internet", Type: "external.internet", Category: "entry_point"},
					{ID: "app", Name: "API", Type: "Microsoft.Web/sites", Category: "compute"},
					{ID: "identity", Name: "Identity", Type: identityType, Category: "identity"},
					{ID: "storage", Name: "Storage", Type: "Microsoft.Storage/storageAccounts", Category: "data", Criticality: model.SeverityCritical},
				},
				[]model.RelationshipEdge{
					{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
					{ID: "identity", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
					{ID: "data", Source: "identity", Target: "storage", Type: "data_access", Label: "Storage Blob Data Contributor", Exploitable: true},
				},
			)
			findings, err := ruleByID(t, "CTA-AZ-004").Evaluate(context.Background(), g)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].RelationshipIDs[2] != "data" {
				t.Fatalf("findings = %#v", findings)
			}
		})
	}
}

func TestAzureExposureRuleIgnoresGenericRoleAssignments(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app", Type: "Microsoft.Web/sites"},
			{ID: "identity", Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity"},
			{ID: "storage", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
			{ID: "identity", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "generic", Source: "identity", Target: "storage", Type: "role_assignment", Exploitable: true},
		},
	)
	findings, err := ruleByID(t, "CTA-AZ-004").Evaluate(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("generic role assignment created findings: %#v", findings)
	}
}

func TestAzureExposureRuleKeepsDistinctPublicWorkloadsSharingIdentity(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Name: "Internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app-a", Name: "API A", Type: "Microsoft.Web/sites"},
			{ID: "app-b", Name: "API B", Type: "Microsoft.Web/sites"},
			{ID: "identity", Name: "Shared identity", Type: "Microsoft.ManagedIdentity/userAssignedIdentities", Category: "identity"},
			{ID: "storage", Name: "Storage", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public-a", Source: "internet", Target: "app-a", Type: "public_exposure", Exploitable: true},
			{ID: "public-b", Source: "internet", Target: "app-b", Type: "public_exposure", Exploitable: true},
			{ID: "identity-a", Source: "app-a", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "identity-b", Source: "app-b", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "data", Source: "identity", Target: "storage", Type: "data_access", Exploitable: true},
		},
	)
	findings, err := ruleByID(t, "CTA-AZ-004").Evaluate(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].ID == findings[1].ID {
		t.Fatalf("shared identity findings = %#v, want one per exposed workload", findings)
	}
}

func TestAzureExposureRuleFindsDirectCriticalExposure(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{{ID: "internet", Name: "Internet", Type: "external.internet", Category: "entry_point"}, {ID: "storage", Name: "Storage", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical}},
		[]model.RelationshipEdge{{ID: "public", Source: "internet", Target: "storage", Type: "public_exposure", Exploitable: true}},
	)
	findings, err := ruleByID(t, "CTA-AZ-004").Evaluate(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID != "finding-direct-public-public" {
		t.Fatalf("direct exposure findings = %#v", findings)
	}
}

func TestRoleManagementRuleDoesNotTreatContainmentAsPrivilege(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{{ID: "principal", Name: "Principal"}, {ID: "rg", Name: "RG"}, {ID: "storage", Name: "Storage", Criticality: model.SeverityCritical}},
		[]model.RelationshipEdge{{ID: "role", Source: "principal", Target: "rg", Type: "role_management", Label: "User Access Administrator", Exploitable: true}, {ID: "contains", Source: "rg", Target: "storage", Type: "contains", Exploitable: false}},
	)
	findings, err := ruleByID(t, "CTA-AZ-005").Evaluate(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(findings[0].RelationshipIDs) != 1 || findings[0].RelationshipIDs[0] != "role" {
		t.Fatalf("role-management findings = %#v", findings)
	}
}

func ruleByID(t *testing.T, id string) model.Rule {
	t.Helper()
	for _, rule := range Default() {
		if rule.ID() == id {
			return rule
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}

func mustGraph(t *testing.T, nodes []model.ResourceNode, edges []model.RelationshipEdge) *graph.Graph {
	t.Helper()
	g, err := graph.New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
