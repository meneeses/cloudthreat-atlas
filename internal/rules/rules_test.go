package rules

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/graph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestChainRuleFailsClosedWhenTraversalWorkBudgetIsExceeded(t *testing.T) {
	nodes := []model.ResourceNode{{ID: "00-start", Type: "start"}}
	edges := make([]model.RelationshipEdge, 0, 32)
	for index := 0; index < 32; index++ {
		id := fmt.Sprintf("wrong-%02d", index)
		nodes = append(nodes, model.ResourceNode{ID: id, Type: "wrong"})
		edges = append(edges, model.RelationshipEdge{
			ID:          fmt.Sprintf("edge-%02d", index),
			Source:      "00-start",
			Target:      id,
			Type:        "next",
			Exploitable: true,
		})
	}
	rule := chainRule{id: "CTA-TEST", nodeTypes: []string{"start", "end"}, edgeTypes: []string{"next"}, maxWork: 8}

	findings, err := rule.Evaluate(context.Background(), mustGraph(t, nodes, edges))
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("budget error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
	}
}

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

func TestAzureExposureRuleResolvesScopedGrantThroughContainment(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Name: "Internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app", Name: "API", Type: "Microsoft.Web/sites", Category: "compute"},
			{ID: "identity", Name: "Identity", Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity"},
			{ID: "subscription", Name: "Subscription", Type: "Microsoft.Resources/subscriptions", Category: "scope"},
			{ID: "rg", Name: "RG", Type: "Microsoft.Resources/resourceGroups", Category: "scope"},
			{ID: "storage", Name: "Storage", Type: "Microsoft.Storage/storageAccounts", Category: "data", Criticality: model.SeverityCritical},
			{ID: "sql", Name: "SQL", Type: "Microsoft.Sql/servers", Category: "data", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
			{ID: "identity-edge", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "grant", Source: "identity", Target: "subscription", Type: "data_access", Label: "Blob role", Exploitable: true, Properties: map[string]string{"targetType": "Microsoft.Storage/storageAccounts"}},
			{ID: "subscription-rg", Source: "subscription", Target: "rg", Type: "contains"},
			{ID: "rg-storage", Source: "rg", Target: "storage", Type: "contains"},
			{ID: "rg-sql", Source: "rg", Target: "sql", Type: "contains"},
		},
	)
	findings, err := ruleByID(t, "CTA-AZ-004").Evaluate(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ResourceIDs[3] != "storage" {
		t.Fatalf("scoped grant findings = %#v", findings)
	}
	if len(findings[0].RelationshipIDs) != 5 {
		t.Fatalf("containment evidence = %v", findings[0].RelationshipIDs)
	}
}

func TestAzureExposureRuleFailsClosedOnContainmentDepthLimit(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app", Type: "Microsoft.Web/sites"},
			{ID: "identity", Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity"},
			{ID: "scope-0", Category: "scope"},
			{ID: "scope-1", Category: "scope"},
			{ID: "scope-2", Category: "scope"},
			{ID: "storage", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
			{ID: "identity-edge", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "grant", Source: "identity", Target: "scope-0", Type: "data_access", Exploitable: true},
			{ID: "contains-1", Source: "scope-0", Target: "scope-1", Type: "contains"},
			{ID: "contains-2", Source: "scope-1", Target: "scope-2", Type: "contains"},
			{ID: "contains-storage", Source: "scope-2", Target: "storage", Type: "contains"},
		},
	)
	rule := azureExposureRule{limits: azureExposureLimits{maxContainmentDepth: 2}}

	findings, err := rule.Evaluate(context.Background(), g)
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("depth limit error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
	}
}

func TestAzureExposureRuleFailsClosedOnCapabilityTargetLimit(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app", Type: "Microsoft.Web/sites"},
			{ID: "identity", Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity"},
			{ID: "scope", Category: "scope"},
			{ID: "storage-a", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical},
			{ID: "storage-b", Type: "Microsoft.Storage/storageAccounts", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public", Source: "internet", Target: "app", Type: "public_exposure", Exploitable: true},
			{ID: "identity-edge", Source: "app", Target: "identity", Type: "managed_identity", Exploitable: true},
			{ID: "grant", Source: "identity", Target: "scope", Type: "data_access", Exploitable: true},
			{ID: "contains-a", Source: "scope", Target: "storage-a", Type: "contains"},
			{ID: "contains-b", Source: "scope", Target: "storage-b", Type: "contains"},
		},
	)
	rule := azureExposureRule{limits: azureExposureLimits{maxCapabilityTargets: 1}}

	findings, err := rule.Evaluate(context.Background(), g)
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("target limit error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
	}
}

func TestAzureExposureRuleFailsClosedOnFindingLimit(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "internet", Type: "external.internet", Category: "entry_point"},
			{ID: "critical-a", Name: "A", Criticality: model.SeverityCritical},
			{ID: "critical-b", Name: "B", Criticality: model.SeverityCritical},
		},
		[]model.RelationshipEdge{
			{ID: "public-a", Source: "internet", Target: "critical-a", Type: "public_exposure", Exploitable: true},
			{ID: "public-b", Source: "internet", Target: "critical-b", Type: "public_exposure", Exploitable: true},
		},
	)
	rule := azureExposureRule{limits: azureExposureLimits{maxFindings: 1}}

	findings, err := rule.Evaluate(context.Background(), g)
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("finding limit error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
	}
}

func TestAzureExposureRuleFailsClosedOnWorkLimit(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{
			{ID: "00-internet", Type: "external.internet", Category: "entry_point"},
			{ID: "app", Type: "Microsoft.Web/sites"},
		},
		[]model.RelationshipEdge{{ID: "public", Source: "00-internet", Target: "app", Type: "public_exposure", Exploitable: true}},
	)

	findings, err := (azureExposureRule{limits: azureExposureLimits{maxWork: 2}}).Evaluate(context.Background(), g)
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("work limit error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
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

func TestRoleManagementRuleCapsFindingsBeforeAppend(t *testing.T) {
	g := mustGraph(t,
		[]model.ResourceNode{{ID: "principal", Name: "Principal"}, {ID: "scope-a", Name: "A"}, {ID: "scope-b", Name: "B"}},
		[]model.RelationshipEdge{
			{ID: "role-a", Source: "principal", Target: "scope-a", Type: "role_management", Exploitable: true},
			{ID: "role-b", Source: "principal", Target: "scope-b", Type: "role_management", Exploitable: true},
		},
	)

	findings, err := (roleManagementRule{maxFindings: 1}).Evaluate(context.Background(), g)
	if !errors.Is(err, ErrRuleEvaluationBudgetExceeded) {
		t.Fatalf("finding limit error = %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want no partial result", findings)
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
