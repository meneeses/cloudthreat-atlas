package collector

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const (
	testSubscription = "11111111-2222-3333-4444-555555555555"
	testPrincipal    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	ownerRole        = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	storageDataRole  = "/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)

func TestNormalizeThenAnalyzeProducesCapabilityPathAndFinding(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	appID := rgID + "/providers/Microsoft.Web/sites/api"
	storageID := rgID + "/providers/Microsoft.Storage/storageAccounts/patientarchive"
	rows := []resourceRow{
		{ID: appID, Name: "api", Type: "microsoft.web/sites", Location: "westeurope", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, PublicNetworkAccess: "Enabled", SystemPrincipalID: testPrincipal, Kind: "app", SKUName: "B1"},
		{ID: storageID, Name: "patientarchive", Type: "microsoft.storage/storageaccounts", Location: "westeurope", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, PublicNetworkAccess: "Disabled"},
	}
	roles := []roleRow{{ID: "role-1", Scope: rgID, PrincipalID: testPrincipal, PrincipalType: "ServicePrincipal", RoleDefinitionID: storageDataRole}}
	stamp := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, stamp)
	if len(snapshot.Resources) != 5 {
		t.Fatalf("resources = %d, want 5", len(snapshot.Resources))
	}
	if len(snapshot.Relationships) != 5 {
		t.Fatalf("relationships = %d, want 5", len(snapshot.Relationships))
	}
	if snapshot.GeneratedAt != stamp {
		t.Fatalf("generatedAt = %v, want %v", snapshot.GeneratedAt, stamp)
	}
	assertEdge(t, snapshot, "contains", rgID, appID, false)
	assertEdge(t, snapshot, "public_exposure", "internet-public", appID, true)
	assertEdge(t, snapshot, "managed_identity", appID, "identity:"+testPrincipal, true)
	assertEdge(t, snapshot, "data_access", "identity:"+testPrincipal, storageID, true)

	analyzed, err := analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzed.AttackPaths) != 1 {
		t.Fatalf("attack paths = %d, want 1: %#v", len(analyzed.AttackPaths), analyzed.AttackPaths)
	}
	if len(analyzed.Findings) != 1 || analyzed.Findings[0].RuleID != "CTA-AZ-004" {
		t.Fatalf("findings = %#v, want one CTA-AZ-004 finding", analyzed.Findings)
	}
	if len(analyzed.AttackPaths[0].FindingIDs) != 1 || analyzed.AttackPaths[0].FindingIDs[0] != analyzed.Findings[0].ID {
		t.Fatalf("path finding links = %v", analyzed.AttackPaths[0].FindingIDs)
	}
}

func TestUserAssignedIdentityProducesSameCapabilitySemantics(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	appID := rgID + "/providers/Microsoft.Web/sites/api"
	storageID := rgID + "/providers/Microsoft.Storage/storageAccounts/patientarchive"
	identityID := rgID + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/api-id"
	rows := []resourceRow{
		{ID: appID, Name: "api", Type: "microsoft.web/sites", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, PublicNetworkAccess: "Enabled", UserAssignedIdentities: map[string]userAssignedIdentityRow{identityID: {PrincipalID: testPrincipal, ClientID: "client-id"}}},
		{ID: identityID, Name: "api-id", Type: "microsoft.managedidentity/userassignedidentities", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, ManagedIdentityPrincipalID: testPrincipal},
		{ID: storageID, Name: "patientarchive", Type: "microsoft.storage/storageaccounts", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription},
	}
	roles := []roleRow{{ID: "role-1", Scope: storageID, PrincipalID: testPrincipal, PrincipalType: "ServicePrincipal", RoleDefinitionID: storageDataRole}}
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, time.Unix(0, 0))
	assertEdge(t, snapshot, "managed_identity", appID, identityID, true)
	assertEdge(t, snapshot, "data_access", identityID, storageID, true)
	analyzed, err := analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzed.AttackPaths) != 1 || len(analyzed.Findings) != 1 {
		t.Fatalf("user-assigned identity analysis paths=%d findings=%d", len(analyzed.AttackPaths), len(analyzed.Findings))
	}
}

func TestNormalizationIsIndependentOfRowOrder(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	identityID := rgID + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/api-id"
	rows := []resourceRow{
		{ID: rgID + "/providers/Microsoft.Web/sites/api", Name: "api", Type: "microsoft.web/sites", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, UserAssignedIdentities: map[string]userAssignedIdentityRow{identityID: {PrincipalID: testPrincipal, ClientID: "client-id"}}},
		{ID: identityID, Name: "api-id", Type: "microsoft.managedidentity/userassignedidentities", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, ManagedIdentityPrincipalID: testPrincipal},
		{ID: rgID + "/providers/Microsoft.Storage/storageAccounts/patientarchive", Name: "patientarchive", Type: "microsoft.storage/storageaccounts", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription},
	}
	roles := []roleRow{
		{ID: "z-role", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: ownerRole},
		{ID: "a-role", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: storageDataRole},
	}
	stamp := time.Unix(123, 0)
	first := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, stamp)
	reversedRows := []resourceRow{rows[2], rows[1], rows[0]}
	reversedRoles := []roleRow{roles[1], roles[0]}
	second := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, reversedRows, reversedRoles, stamp)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("normalization depends on input order\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestUnknownAndRoleManagementAssignmentsDoNotCreateGenericResourcePaths(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	appID := rgID + "/providers/Microsoft.Web/sites/api"
	storageID := rgID + "/providers/Microsoft.Storage/storageAccounts/patientarchive"
	rows := []resourceRow{
		{ID: appID, Name: "api", Type: "microsoft.web/sites", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, PublicNetworkAccess: "Enabled", SystemPrincipalID: testPrincipal},
		{ID: storageID, Name: "patientarchive", Type: "microsoft.storage/storageaccounts", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription},
	}
	unknown := []roleRow{{ID: "unknown", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: "/roleDefinitions/unknown"}}
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, unknown, time.Unix(0, 0))
	assertEdge(t, snapshot, "role_assignment", "identity:"+testPrincipal, rgID, false)
	analyzed, err := analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzed.AttackPaths) != 0 || len(analyzed.Findings) != 0 {
		t.Fatalf("unknown role created paths/findings: paths=%d findings=%d", len(analyzed.AttackPaths), len(analyzed.Findings))
	}

	userAccessAdmin := []roleRow{{ID: "uaa", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: "/roleDefinitions/18d7d88d-d35e-4fb8-a5c7-7773c20a72d9"}}
	snapshot = normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, userAccessAdmin, time.Unix(0, 0))
	analyzed, err = analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzed.AttackPaths) != 0 {
		t.Fatalf("role management created generic attack paths: %d", len(analyzed.AttackPaths))
	}
	if len(analyzed.Findings) != 1 || analyzed.Findings[0].RuleID != "CTA-AZ-005" {
		t.Fatalf("role-management findings = %#v", analyzed.Findings)
	}
}

func TestOwnerCapabilityTargetsExactScopeAndDescendantsOnly(t *testing.T) {
	base := "/subscriptions/" + testSubscription + "/resourceGroups/prod"
	other := "/subscriptions/" + testSubscription + "/resourceGroups/production"
	resources := map[string]model.ResourceNode{
		base:                 {ID: base, Provider: "azure", Category: "scope"},
		base + "/child":      {ID: base + "/child", Provider: "azure", Category: "data"},
		other + "/not-child": {ID: other + "/not-child", Provider: "azure", Category: "data"},
	}
	targets := capabilityTargets(base, roleDetails(ownerRole), resources)
	if len(targets) != 1 || targets[0] != base+"/child" {
		t.Fatalf("owner capability targets = %v", targets)
	}
	if withinScope(other+"/not-child", base) {
		t.Fatal("similarly prefixed resource group was treated as a descendant")
	}
}

func TestScopedRoleQueryUsesExactBoundary(t *testing.T) {
	query, err := scopedQuery(roleQuery, testSubscription, "patient-data", true)
	if err != nil {
		t.Fatal(err)
	}
	base := "/subscriptions/" + testSubscription + "/resourcegroups/patient-data"
	subscriptionScope := "/subscriptions/" + testSubscription
	if !strings.Contains(query, "tolower(scope) == '"+subscriptionScope+"'") || !strings.Contains(query, "tolower(scope) == '"+base+"'") || !strings.Contains(query, "tolower(scope) startswith '"+base+"/'") {
		t.Fatalf("role query does not use exact-or-descendant boundary: %s", query)
	}
	if strings.Contains(strings.ToLower(query), " contains ") {
		t.Fatalf("role query uses substring containment: %s", query)
	}
}

func TestScopeValidationRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"patient/data", "patient's-data", "trailing.", "contains space"} {
		if err := validateResourceGroupName(name); err == nil {
			t.Errorf("resource group %q was accepted", name)
		}
	}
	if err := validateResourceGroupName("produção-(01)_blue"); err != nil {
		t.Fatalf("valid Unicode resource-group name rejected: %v", err)
	}
	if err := validateScope(model.Scope{SubscriptionID: "not-a-uuid"}); err == nil {
		t.Fatal("invalid subscription id was accepted")
	}
}

func TestKnownAndUnknownRoleCapabilities(t *testing.T) {
	tests := []struct {
		roleID   string
		edgeType string
	}{
		{ownerRole, "control_plane_access"},
		{"/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c", "control_plane_access"},
		{storageDataRole, "data_access"},
		{"/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6", "secret_access"},
		{"/roleDefinitions/18d7d88d-d35e-4fb8-a5c7-7773c20a72d9", "role_management"},
	}
	for _, test := range tests {
		capability := roleDetails(test.roleID)
		if !capability.Exploitable || capability.EdgeType != test.edgeType {
			t.Errorf("role %q = %#v, want edge %q", test.roleID, capability, test.edgeType)
		}
	}
	unknown := roleDetails("/roleDefinitions/unknown")
	if unknown.Exploitable || unknown.EdgeType != "" || !strings.Contains(unknown.Name, "unknown") {
		t.Fatalf("unknown role = %#v, want conservative non-exploitable result", unknown)
	}
}

func assertEdge(t *testing.T, snapshot model.Snapshot, edgeType, source, target string, exploitable bool) {
	t.Helper()
	for _, edge := range snapshot.Relationships {
		if edge.Type == edgeType && edge.Source == source && edge.Target == target {
			if edge.Exploitable != exploitable {
				t.Fatalf("edge %s exploitability = %v, want %v", edge.ID, edge.Exploitable, exploitable)
			}
			return
		}
	}
	t.Fatalf("missing %s edge %s -> %s; got %#v", edgeType, source, target, snapshot.Relationships)
}
