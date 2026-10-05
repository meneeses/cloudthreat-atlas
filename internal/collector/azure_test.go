package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
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
	if snapshot.GeneratedAt != stamp {
		t.Fatalf("generatedAt = %v, want %v", snapshot.GeneratedAt, stamp)
	}
	if snapshot.Scope == nil || snapshot.Scope.SubscriptionID != testSubscription || snapshot.Scope.ResourceGroup != "" {
		t.Fatalf("snapshot scope = %#v", snapshot.Scope)
	}
	assertEdge(t, snapshot, "contains", rgID, appID, false)
	assertEdge(t, snapshot, "contains", "/subscriptions/"+testSubscription, rgID, false)
	assertEdge(t, snapshot, "public_exposure", "internet-public", appID, true)
	assertEdge(t, snapshot, "managed_identity", appID, "identity:"+testPrincipal, true)
	assertEdge(t, snapshot, "data_access", "identity:"+testPrincipal, rgID, true)

	analyzed, err := analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyzed.AttackPaths) != 0 {
		t.Fatalf("scope-based RBAC should not create roles x resources path edges: %#v", analyzed.AttackPaths)
	}
	if len(analyzed.Findings) != 1 || analyzed.Findings[0].RuleID != "CTA-AZ-004" {
		t.Fatalf("findings = %#v, want one CTA-AZ-004 finding", analyzed.Findings)
	}
	if len(analyzed.Findings[0].RelationshipIDs) != 4 {
		t.Fatalf("finding should include exposure, identity, grant, and containment evidence: %v", analyzed.Findings[0].RelationshipIDs)
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

func TestDistinctRoleAssignmentsAtSameScopeArePreserved(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	rows := []resourceRow{{
		ID: rgID + "/providers/Microsoft.Web/sites/api", Name: "api", Type: "microsoft.web/sites",
		ResourceGroup: "clinical-prod", SubscriptionID: testSubscription, SystemPrincipalID: testPrincipal,
	}}
	contributorRole := "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	roles := []roleRow{
		{ID: "assignment-owner", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: ownerRole},
		{ID: "assignment-contributor", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: contributorRole},
	}
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, time.Unix(0, 0))
	assignments := make(map[string]bool)
	for _, relationship := range snapshot.Relationships {
		if relationship.Source == "identity:"+testPrincipal && relationship.Target == rgID && relationship.Type == "control_plane_access" {
			assignments[relationship.Properties["roleAssignmentId"]] = true
		}
	}
	if !assignments["assignment-owner"] || !assignments["assignment-contributor"] || len(assignments) != 2 {
		t.Fatalf("control-plane assignments = %v, want both distinct grants", assignments)
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

func TestNetworkAndServiceDefaultsNormalizeFromFixtureRows(t *testing.T) {
	encoded, err := os.ReadFile("testdata/azure_network_rows.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []resourceRow
	if err := json.Unmarshal(encoded, &rows); err != nil {
		t.Fatal(err)
	}
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, nil, time.Unix(0, 0))
	base := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod/providers/"
	nsgID := base + "Microsoft.Network/networkSecurityGroups/app-nsg"
	nicID := base + "Microsoft.Network/networkInterfaces/vm-nic"
	vmID := base + "Microsoft.Compute/virtualMachines/vm"
	pipID := base + "Microsoft.Network/publicIPAddresses/vm-pip"
	subnetID := base + "Microsoft.Network/virtualNetworks/core/subnets/app"
	peID := base + "Microsoft.Network/privateEndpoints/storage-pe"
	storageID := base + "Microsoft.Storage/storageAccounts/archive"
	assertEdge(t, snapshot, "public_ingress_candidate", "internet-public", nsgID, false)
	assertEdge(t, snapshot, "network_filter", nsgID, nicID, false)
	assertEdge(t, snapshot, "public_ip_association", pipID, nicID, false)
	assertEdge(t, snapshot, "network_access", nicID, vmID, true)
	assertEdge(t, snapshot, "network_segment", subnetID, peID, false)
	assertEdge(t, snapshot, "private_endpoint", peID, storageID, false)
	for _, id := range []string{storageID} {
		assertEdge(t, snapshot, "public_exposure", "internet-public", id, true)
	}
	for _, id := range []string{pipID, base + "Microsoft.Sql/servers/sql", base + "Microsoft.Web/sites/api"} {
		assertEdge(t, snapshot, "public_endpoint", "internet-public", id, false)
	}
	for _, id := range []string{base + "Microsoft.KeyVault/vaults/vault", base + "Microsoft.DBforPostgreSQL/flexibleServers/pg"} {
		if hasEdge(snapshot, "public_exposure", "internet-public", id) {
			t.Fatalf("disabled service %s was marked publicly exposed", id)
		}
	}
	for _, edge := range snapshot.Relationships {
		if edge.Origin == "" || edge.Confidence == "" {
			t.Fatalf("relationship %s lacks provenance: %#v", edge.ID, edge)
		}
	}
	analyzed, err := analysis.NewDefault().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range analyzed.AttackPaths {
		if path.Target == vmID {
			t.Fatalf("raw NSG allow/attachment facts created an effective VM path: %#v", path)
		}
	}
}

func TestPublicExposureRequiresInternetWideNetworkSettings(t *testing.T) {
	tests := []struct {
		name         string
		row          resourceRow
		resourceType string
		edgeType     string
		exploitable  bool
	}{
		{name: "storage allow", row: resourceRow{PublicNetworkAccess: "Enabled", NetworkDefaultAction: "Allow"}, resourceType: "Microsoft.Storage/storageAccounts", edgeType: "public_exposure", exploitable: true},
		{name: "storage deny", row: resourceRow{PublicNetworkAccess: "Enabled", NetworkDefaultAction: "Deny"}, resourceType: "Microsoft.Storage/storageAccounts", edgeType: "public_endpoint"},
		{name: "restricted app", row: resourceRow{PublicNetworkAccess: "Enabled", IPSecurityRestrictionCount: 1, IPSecurityDefaultAction: "Deny"}, resourceType: "Microsoft.Web/sites", edgeType: "public_endpoint"},
		{name: "unrestricted app default", row: resourceRow{PublicNetworkAccess: "Enabled"}, resourceType: "Microsoft.Web/sites", edgeType: "public_exposure", exploitable: true},
		{name: "SQL firewall unknown", row: resourceRow{PublicNetworkAccess: "Enabled"}, resourceType: "Microsoft.Sql/servers", edgeType: "public_endpoint"},
		{name: "disabled", row: resourceRow{PublicNetworkAccess: "Disabled"}, resourceType: "Microsoft.KeyVault/vaults"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyPublicExposure(test.row, test.resourceType)
			if got.edgeType != test.edgeType || got.exploitable != test.exploitable {
				t.Fatalf("classification = %+v", got)
			}
		})
	}
}

func TestCustomRoleActionsAreConservativeAndHonorExclusions(t *testing.T) {
	definitionID := "/subscriptions/" + testSubscription + "/providers/Microsoft.Authorization/roleDefinitions/custom-role"
	definitions := indexRoleDefinitions([]roleDefinitionRow{{
		ID: definitionID, RoleName: "Scoped data operator", RoleType: "CustomRole",
		Permissions: []permissionRow{{
			DataActions:    []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*", "Microsoft.KeyVault/vaults/secrets/getSecret/action"},
			NotDataActions: []string{"Microsoft.KeyVault/vaults/secrets/*"},
		}},
	}})
	capabilities := roleCapabilities(definitionID, definitions)
	if len(capabilities) != 1 || capabilities[0].EdgeType != "data_access" || capabilities[0].TargetType != "Microsoft.Storage/storageAccounts" || !capabilities[0].Custom {
		t.Fatalf("custom role capabilities = %#v", capabilities)
	}
	if permissionAllows([]string{"*"}, []string{"Microsoft.Authorization/*/write"}, "Microsoft.Authorization/roleAssignments/write") {
		t.Fatal("NotActions exclusion was ignored")
	}
}

func TestCustomRoleRecognizesSecretValueActionButNotMetadataOnly(t *testing.T) {
	secretID := "/subscriptions/" + testSubscription + "/providers/Microsoft.Authorization/roleDefinitions/secret-reader"
	metadataID := "/subscriptions/" + testSubscription + "/providers/Microsoft.Authorization/roleDefinitions/metadata-reader"
	definitions := indexRoleDefinitions([]roleDefinitionRow{
		{ID: secretID, RoleName: "Secret value reader", RoleType: "CustomRole", Permissions: []permissionRow{{DataActions: []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}}}},
		{ID: metadataID, RoleName: "Secret metadata reader", RoleType: "CustomRole", Permissions: []permissionRow{{DataActions: []string{"Microsoft.KeyVault/vaults/secrets/readMetadata/action"}}}},
	})
	capabilities := roleCapabilities(secretID, definitions)
	if len(capabilities) != 1 || capabilities[0].EdgeType != "secret_access" || capabilities[0].TargetType != "Microsoft.KeyVault/vaults" {
		t.Fatalf("secret-value capabilities = %#v", capabilities)
	}
	if capabilities := roleCapabilities(metadataID, definitions); len(capabilities) != 0 {
		t.Fatalf("metadata-only role was treated as secret value access: %#v", capabilities)
	}
}

func TestCustomRolePreservesEachControlPlaneTarget(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/clinical-prod"
	storageID := rgID + "/providers/Microsoft.Storage/storageAccounts/archive"
	vaultID := rgID + "/providers/Microsoft.KeyVault/vaults/clinical"
	definitionID := "/subscriptions/" + testSubscription + "/providers/Microsoft.Authorization/roleDefinitions/multi-service-operator"
	rows := []resourceRow{
		{ID: storageID, Name: "archive", Type: "Microsoft.Storage/storageAccounts", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription},
		{ID: vaultID, Name: "clinical", Type: "Microsoft.KeyVault/vaults", ResourceGroup: "clinical-prod", SubscriptionID: testSubscription},
	}
	roles := []roleRow{{ID: "assignment", Scope: rgID, PrincipalID: testPrincipal, PrincipalType: "ServicePrincipal", RoleDefinitionID: definitionID}}
	definitions := []roleDefinitionRow{{
		ID: definitionID, RoleName: "Multi-service operator", RoleType: "CustomRole",
		Permissions: []permissionRow{{Actions: []string{"Microsoft.Storage/storageAccounts/write", "Microsoft.KeyVault/vaults/write"}}},
	}}

	snapshot := normalizeAzureWithDefinitions(model.Scope{SubscriptionID: testSubscription}, rows, roles, definitions, time.Unix(0, 0))
	wantTargets := map[string]bool{
		"Microsoft.Storage/storageAccounts": false,
		"Microsoft.KeyVault/vaults":         false,
	}
	for _, edge := range snapshot.Relationships {
		if edge.Type != "control_plane_access" || edge.Source != "principal:"+testPrincipal || edge.Target != rgID {
			continue
		}
		targetType := edge.Properties["targetType"]
		if _, wanted := wantTargets[targetType]; wanted {
			wantTargets[targetType] = true
		}
	}
	for targetType, found := range wantTargets {
		if !found {
			t.Fatalf("missing custom-role control-plane edge for %s; relationships = %#v", targetType, snapshot.Relationships)
		}
	}

	capabilities := roleCapabilities(definitionID, indexRoleDefinitions(definitions))
	for _, capability := range capabilities {
		targets := capabilityTargets(rgID, capability, map[string]model.ResourceNode{
			storageID: {ID: storageID, Type: "Microsoft.Storage/storageAccounts", Provider: "azure"},
			vaultID:   {ID: vaultID, Type: "Microsoft.KeyVault/vaults", Provider: "azure"},
		})
		if len(targets) != 1 {
			t.Fatalf("capability %q targets = %v, want exactly its resource type", capability.TargetType, targets)
		}
	}
}

func TestRBACNormalizationScalesWithAssignmentsNotDescendantResources(t *testing.T) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/prod"
	rows := make([]resourceRow, 250)
	for index := range rows {
		rows[index] = resourceRow{ID: fmt.Sprintf("%s/providers/Microsoft.Storage/storageAccounts/archive%d", rgID, index), Name: fmt.Sprintf("archive%d", index), Type: "microsoft.storage/storageaccounts", ResourceGroup: "prod", SubscriptionID: testSubscription}
	}
	roles := []roleRow{{ID: "assignment", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: ownerRole}}
	snapshot := normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, time.Unix(0, 0))
	grants := 0
	for _, edge := range snapshot.Relationships {
		if edge.Type == "control_plane_access" {
			grants++
			if edge.Target != rgID {
				t.Fatalf("grant target = %s, want scope %s", edge.Target, rgID)
			}
		}
	}
	if grants != 1 {
		t.Fatalf("control-plane grant edges = %d, want one", grants)
	}
}

type resourceGraphFunc func(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)

func (fn resourceGraphFunc) Resources(ctx context.Context, request armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	return fn(ctx, request, options)
}

func TestQueryAllPaginatesAndRetriesCurrentPage(t *testing.T) {
	var mutex sync.Mutex
	calls := 0
	client := resourceGraphFunc(func(_ context.Context, request armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		mutex.Lock()
		defer mutex.Unlock()
		calls++
		if calls == 1 {
			return armresourcegraph.ClientResourcesResponse{}, errors.New("transient")
		}
		if request.Options.SkipToken == nil {
			return queryResponse([]any{"first"}, to.Ptr("next")), nil
		}
		return queryResponse([]any{"second"}, nil), nil
	})
	rows, err := queryAllWithRetry(context.Background(), client, testSubscription, "query", queryOptions{MaxAttempts: 2, Retryable: func(error) bool { return true }, RetryDelay: func(context.Context, int) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows, []any{"first", "second"}) || calls != 3 {
		t.Fatalf("rows=%v calls=%d", rows, calls)
	}
}

func TestQueryIndependentBoundsConcurrency(t *testing.T) {
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	client := resourceGraphFunc(func(ctx context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		started <- struct{}{}
		select {
		case <-release:
			return queryResponse([]any{}, nil), nil
		case <-ctx.Done():
			return armresourcegraph.ClientResourcesResponse{}, ctx.Err()
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := queryIndependent(context.Background(), client, testSubscription, []namedQuery{{name: "one"}, {name: "two"}, {name: "three"}}, queryOptions{MaxConcurrency: 2, MaxAttempts: 1})
		done <- err
	}()
	<-started
	<-started
	select {
	case <-started:
		t.Fatal("third query started before a bounded worker was released")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQueryAllHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := resourceGraphFunc(func(callContext context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		cancel()
		<-callContext.Done()
		return armresourcegraph.ClientResourcesResponse{}, callContext.Err()
	})
	_, err := queryAllWithRetry(ctx, client, testSubscription, "query", queryOptions{MaxAttempts: 3, Retryable: func(error) bool { return true }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("query cancellation error = %v", err)
	}
}

func TestQueryAllRejectsRowsBeyondPerQueryBudget(t *testing.T) {
	calls := 0
	client := resourceGraphFunc(func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		return queryResponse([]any{"one", "two", "three"}, to.Ptr("more")), nil
	})
	_, err := queryAllWithRetry(context.Background(), client, testSubscription, "query", queryOptions{MaxAttempts: 1, MaxRowsPerQuery: 3, MaxPagesPerQuery: 10})
	if !errors.Is(err, ErrCollectionBudgetExceeded) {
		t.Fatalf("row budget error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("Resource Graph calls = %d, want one before refusing a partial result", calls)
	}
}

func TestQueryAllRejectsUnboundedPagination(t *testing.T) {
	calls := 0
	client := resourceGraphFunc(func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		return queryResponse([]any{}, to.Ptr(fmt.Sprintf("page-%d", calls))), nil
	})
	_, err := queryAllWithRetry(context.Background(), client, testSubscription, "query", queryOptions{MaxAttempts: 1, MaxRowsPerQuery: 10, MaxPagesPerQuery: 2})
	if !errors.Is(err, ErrCollectionBudgetExceeded) {
		t.Fatalf("page budget error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("Resource Graph calls = %d, want two", calls)
	}
}

func TestQueryIndependentSharesRowBudgetAcrossConcurrentQueries(t *testing.T) {
	client := resourceGraphFunc(func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		return queryResponse([]any{"one", "two"}, nil), nil
	})
	_, err := queryIndependent(context.Background(), client, testSubscription, []namedQuery{{name: "one"}, {name: "two"}}, queryOptions{
		MaxConcurrency: 2, MaxAttempts: 1, MaxRowsPerQuery: 10, MaxRowsAcrossQueries: 3, MaxPagesPerQuery: 1,
	})
	if !errors.Is(err, ErrCollectionBudgetExceeded) {
		t.Fatalf("shared row budget error = %v", err)
	}
}

func TestQueryAllRejectsBytesBeyondPerQueryBudget(t *testing.T) {
	client := resourceGraphFunc(func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		return queryResponse([]any{map[string]any{"nested": strings.Repeat("x", 128)}}, nil), nil
	})
	_, err := queryAllWithRetry(context.Background(), client, testSubscription, "query", queryOptions{
		MaxAttempts: 1, MaxRowsPerQuery: 10, MaxBytesPerQuery: 64, MaxPagesPerQuery: 1,
	})
	if !errors.Is(err, ErrCollectionBudgetExceeded) {
		t.Fatalf("byte budget error = %v", err)
	}
}

func TestQueryIndependentSharesByteBudgetAcrossConcurrentQueries(t *testing.T) {
	client := resourceGraphFunc(func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		return queryResponse([]any{map[string]any{"nested": strings.Repeat("x", 48)}}, nil), nil
	})
	_, err := queryIndependent(context.Background(), client, testSubscription, []namedQuery{{name: "one"}, {name: "two"}}, queryOptions{
		MaxConcurrency: 2, MaxAttempts: 1, MaxRowsPerQuery: 10, MaxRowsAcrossQueries: 10,
		MaxBytesPerQuery: 256, MaxBytesAcrossQueries: 100, MaxPagesPerQuery: 1,
	})
	if !errors.Is(err, ErrCollectionBudgetExceeded) {
		t.Fatalf("shared byte budget error = %v", err)
	}
}

func queryResponse(data []any, skipToken *string) armresourcegraph.ClientResourcesResponse {
	return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{Data: data, SkipToken: skipToken}}
}

func BenchmarkNormalizeRBACScopeGrant(b *testing.B) {
	rgID := "/subscriptions/" + testSubscription + "/resourceGroups/prod"
	rows := make([]resourceRow, 1000)
	for index := range rows {
		rows[index] = resourceRow{ID: fmt.Sprintf("%s/providers/Microsoft.Storage/storageAccounts/archive%d", rgID, index), Type: "microsoft.storage/storageaccounts", ResourceGroup: "prod", SubscriptionID: testSubscription}
	}
	roles := []roleRow{{ID: "assignment", Scope: rgID, PrincipalID: testPrincipal, RoleDefinitionID: ownerRole}}
	b.ResetTimer()
	for range b.N {
		normalizeAzure(model.Scope{SubscriptionID: testSubscription}, rows, roles, time.Unix(0, 0))
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

func hasEdge(snapshot model.Snapshot, edgeType, source, target string) bool {
	for _, edge := range snapshot.Relationships {
		if edge.Type == edgeType && edge.Source == source && edge.Target == target {
			return true
		}
	}
	return false
}
