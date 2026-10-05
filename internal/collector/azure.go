package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const resourceQuery = `Resources
| where type in~ ('Microsoft.Web/sites', 'Microsoft.Web/sites/functions', 'Microsoft.Compute/virtualMachines', 'Microsoft.Network/networkSecurityGroups', 'Microsoft.Network/publicIPAddresses', 'Microsoft.Storage/storageAccounts', 'Microsoft.KeyVault/vaults', 'Microsoft.Sql/servers', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.ManagedIdentity/userAssignedIdentities', 'Microsoft.OperationalInsights/workspaces')
| project id=tostring(id), name=tostring(name), type=tostring(type), location=tostring(location), resourceGroup=tostring(resourceGroup), subscriptionId=tostring(subscriptionId), publicNetworkAccess=tostring(properties.publicNetworkAccess), systemPrincipalId=tostring(identity.principalId), managedIdentityPrincipalId=tostring(properties.principalId), userAssignedIdentities=identity.userAssignedIdentities, kind=tostring(kind), skuName=tostring(sku.name)
| order by id asc`

const roleQuery = `AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| project id=tostring(id), name=tostring(name), type=tostring(type), scope=tostring(properties.scope), principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleDefinitionId=tostring(properties.roleDefinitionId)
| order by id asc`

// AzureResourceGraph collects only projected, non-secret metadata through Azure's
// read-only Resource Graph endpoint. It creates no Azure resources and uses no ARM
// write client.
type AzureResourceGraph struct{}

type resourceRow struct {
	ID                         string                             `json:"id"`
	Name                       string                             `json:"name"`
	Type                       string                             `json:"type"`
	Location                   string                             `json:"location"`
	ResourceGroup              string                             `json:"resourceGroup"`
	SubscriptionID             string                             `json:"subscriptionId"`
	PublicNetworkAccess        string                             `json:"publicNetworkAccess"`
	SystemPrincipalID          string                             `json:"systemPrincipalId"`
	ManagedIdentityPrincipalID string                             `json:"managedIdentityPrincipalId"`
	UserAssignedIdentities     map[string]userAssignedIdentityRow `json:"userAssignedIdentities"`
	Kind                       string                             `json:"kind"`
	SKUName                    string                             `json:"skuName"`
}

type userAssignedIdentityRow struct {
	PrincipalID string `json:"principalId"`
	ClientID    string `json:"clientId"`
}

type roleRow struct {
	ID               string `json:"id"`
	Scope            string `json:"scope"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	RoleDefinitionID string `json:"roleDefinitionId"`
}

// Collect implements model.Collector with DefaultAzureCredential. It requires only
// Resource Graph read access in the requested subscription.
func (AzureResourceGraph) Collect(ctx context.Context, scope model.Scope) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	if err := validateScope(scope); err != nil {
		return model.Snapshot{}, err
	}
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("create Azure credential: %w", err)
	}
	client, err := armresourcegraph.NewClient(credential, nil)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("create Azure Resource Graph client: %w", err)
	}
	resourcesQuery, err := scopedQuery(resourceQuery, scope.SubscriptionID, scope.ResourceGroup, false)
	if err != nil {
		return model.Snapshot{}, err
	}
	rolesQuery, err := scopedQuery(roleQuery, scope.SubscriptionID, scope.ResourceGroup, true)
	if err != nil {
		return model.Snapshot{}, err
	}
	resourcesData, err := queryAll(ctx, client, scope.SubscriptionID, resourcesQuery)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("query Azure resources: %w", err)
	}
	rolesData, err := queryAll(ctx, client, scope.SubscriptionID, rolesQuery)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("query Azure role assignments: %w", err)
	}
	resourceRows, err := decodeRows[resourceRow](resourcesData)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("decode Azure resources: %w", err)
	}
	roleRows, err := decodeRows[roleRow](rolesData)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("decode Azure role assignments: %w", err)
	}
	return normalizeAzure(scope, resourceRows, roleRows, time.Now().UTC()), nil
}

type resourceGraphClient interface {
	Resources(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

func queryAll(ctx context.Context, client resourceGraphClient, subscriptionID, query string) ([]any, error) {
	var rows []any
	var skipToken *string
	for {
		response, err := client.Resources(ctx, armresourcegraph.QueryRequest{
			Query:         to.Ptr(query),
			Subscriptions: []*string{to.Ptr(subscriptionID)},
			Options: &armresourcegraph.QueryRequestOptions{
				ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
				SkipToken:    skipToken,
				Top:          to.Ptr[int32](1000),
			},
		}, nil)
		if err != nil {
			return nil, err
		}
		page, ok := response.Data.([]any)
		if !ok {
			encoded, marshalErr := json.Marshal(response.Data)
			if marshalErr != nil {
				return nil, fmt.Errorf("encode query page: %w", marshalErr)
			}
			if unmarshalErr := json.Unmarshal(encoded, &page); unmarshalErr != nil {
				return nil, fmt.Errorf("query returned unexpected data %T: %w", response.Data, unmarshalErr)
			}
		}
		rows = append(rows, page...)
		if response.SkipToken == nil || *response.SkipToken == "" {
			break
		}
		skipToken = response.SkipToken
	}
	return rows, nil
}

func decodeRows[T any](data []any) ([]T, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var rows []T
	if err := json.Unmarshal(encoded, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func scopedQuery(query, subscriptionID, resourceGroup string, authorization bool) (string, error) {
	if strings.TrimSpace(resourceGroup) == "" {
		return query, nil
	}
	if err := validateResourceGroupName(resourceGroup); err != nil {
		return "", err
	}
	if !subscriptionIDPattern.MatchString(subscriptionID) {
		return "", fmt.Errorf("subscription id must be a UUID")
	}
	escaped := escapeKustoString(resourceGroup)
	filter := fmt.Sprintf("\n| where resourceGroup =~ '%s'", escaped)
	if authorization {
		subscriptionScope := escapeKustoString(strings.ToLower("/subscriptions/" + subscriptionID))
		baseScope := strings.ToLower(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroup))
		baseScope = escapeKustoString(baseScope)
		filter = fmt.Sprintf("\n| where tolower(scope) == '%s' or tolower(scope) == '%s' or tolower(scope) startswith '%s/'", subscriptionScope, baseScope, baseScope)
	}
	return strings.Replace(query, "\n| project", filter+"\n| project", 1), nil
}

func normalizeAzure(scope model.Scope, resourceRows []resourceRow, roleRows []roleRow, generatedAt time.Time) model.Snapshot {
	resourceRows = append([]resourceRow(nil), resourceRows...)
	roleRows = append([]roleRow(nil), roleRows...)
	sort.Slice(resourceRows, func(i, j int) bool { return resourceRows[i].ID < resourceRows[j].ID })
	sort.Slice(roleRows, func(i, j int) bool { return roleRows[i].ID < roleRows[j].ID })
	resources := make(map[string]model.ResourceNode)
	relationships := make(map[string]model.RelationshipEdge)
	resourceGroups := make(map[string]string)
	principalNodes := make(map[string]string)
	publicNeeded := false

	for _, row := range resourceRows {
		if row.ID == "" {
			continue
		}
		typeName := canonicalResourceType(row.Type)
		properties := map[string]string{}
		putIfPresent(properties, "resourceGroup", row.ResourceGroup)
		putIfPresent(properties, "subscriptionId", row.SubscriptionID)
		putIfPresent(properties, "publicNetworkAccess", row.PublicNetworkAccess)
		putIfPresent(properties, "kind", row.Kind)
		putIfPresent(properties, "sku", row.SKUName)
		putIfPresent(properties, "principalId", row.ManagedIdentityPrincipalID)
		resources[row.ID] = model.ResourceNode{ID: row.ID, Name: fallback(row.Name, lastSegment(row.ID)), Type: typeName, Category: categoryForType(typeName), Provider: "azure", Location: row.Location, Criticality: criticalityForType(typeName), Properties: properties}
		if row.ManagedIdentityPrincipalID != "" {
			principalNodes[strings.ToLower(row.ManagedIdentityPrincipalID)] = row.ID
		}

		if row.ResourceGroup != "" {
			subscriptionID := fallback(row.SubscriptionID, scope.SubscriptionID)
			rgID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, row.ResourceGroup)
			resourceGroups[strings.ToLower(rgID)] = rgID
			if _, exists := resources[rgID]; !exists {
				resources[rgID] = model.ResourceNode{ID: rgID, Name: row.ResourceGroup, Type: "Microsoft.Resources/resourceGroups", Category: "scope", Provider: "azure", Criticality: model.SeverityMedium, Properties: map[string]string{"subscriptionId": subscriptionID}}
			}
			addRelationship(relationships, rgID, row.ID, "contains", "contains", "The resource belongs to this resource group.", false, true, nil)
		}

		if isPublic(row, typeName) {
			publicNeeded = true
			addRelationship(relationships, "internet-public", row.ID, "public_exposure", "public endpoint", "Resource Graph reports public network exposure for this resource.", true, true, nil)
		}
		if row.SystemPrincipalID != "" {
			identityID := "identity:" + strings.ToLower(row.SystemPrincipalID)
			if _, exists := resources[identityID]; !exists {
				resources[identityID] = model.ResourceNode{ID: identityID, Name: "System-assigned identity " + shortID(row.SystemPrincipalID), Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"principalId": row.SystemPrincipalID}}
			}
			principalNodes[strings.ToLower(row.SystemPrincipalID)] = identityID
			addRelationship(relationships, row.ID, identityID, "managed_identity", "runs as", "The resource can request tokens for its managed identity.", true, false, nil)
		}
		identityIDs := make([]string, 0, len(row.UserAssignedIdentities))
		for identityID := range row.UserAssignedIdentities {
			identityIDs = append(identityIDs, identityID)
		}
		sort.Strings(identityIDs)
		for _, identityID := range identityIDs {
			identity := row.UserAssignedIdentities[identityID]
			if identityID == "" {
				continue
			}
			if existing, exists := resources[identityID]; exists {
				if existing.Properties == nil {
					existing.Properties = make(map[string]string)
				}
				putIfPresent(existing.Properties, "principalId", identity.PrincipalID)
				putIfPresent(existing.Properties, "clientId", identity.ClientID)
				resources[identityID] = existing
			} else {
				identityProperties := map[string]string{}
				putIfPresent(identityProperties, "principalId", identity.PrincipalID)
				putIfPresent(identityProperties, "clientId", identity.ClientID)
				resources[identityID] = model.ResourceNode{ID: identityID, Name: fallback(lastSegment(identityID), "User-assigned identity"), Type: "Microsoft.ManagedIdentity/userAssignedIdentities", Category: "identity", Provider: "azure", Criticality: model.SeverityHigh, Properties: identityProperties}
			}
			if identity.PrincipalID != "" {
				principalNodes[strings.ToLower(identity.PrincipalID)] = identityID
			}
			addRelationship(relationships, row.ID, identityID, "managed_identity", "runs as", "The resource can request tokens for its user-assigned identity.", true, false, nil)
		}
	}

	for _, row := range roleRows {
		if row.PrincipalID == "" || row.Scope == "" {
			continue
		}
		principalID, managed := principalNodes[strings.ToLower(row.PrincipalID)]
		if !managed {
			principalID = "principal:" + strings.ToLower(row.PrincipalID)
		}
		if _, exists := resources[principalID]; !exists {
			resources[principalID] = model.ResourceNode{ID: principalID, Name: fallback(row.PrincipalType, "Azure principal") + " " + shortID(row.PrincipalID), Type: principalType(row.PrincipalType), Category: "identity", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"principalId": row.PrincipalID, "principalType": row.PrincipalType}}
		}
		capability := roleDetails(row.RoleDefinitionID)
		properties := map[string]string{"roleDefinitionId": row.RoleDefinitionID, "inferred": "true"}
		if row.ID != "" {
			properties["roleAssignmentId"] = row.ID
		}
		if !capability.Exploitable {
			scopeID := canonicalScope(row.Scope, resourceGroups, resources)
			if _, exists := resources[scopeID]; !exists {
				resources[scopeID] = model.ResourceNode{ID: scopeID, Name: lastSegment(scopeID), Type: "Microsoft.Authorization/scopes", Category: "scope", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"inferred": "true"}}
			}
			addRelationship(relationships, principalID, scopeID, "role_assignment", capability.Name, "An unclassified Azure role is present; CloudThreat Atlas does not assume exploitability.", false, true, properties)
			continue
		}
		if capability.EdgeType == "role_management" {
			scopeID := canonicalScope(row.Scope, resourceGroups, resources)
			if _, exists := resources[scopeID]; !exists {
				resources[scopeID] = model.ResourceNode{ID: scopeID, Name: lastSegment(scopeID), Type: "Microsoft.Authorization/scopes", Category: "scope", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"inferred": "true"}}
			}
			addRelationship(relationships, principalID, scopeID, capability.EdgeType, capability.Name, capability.Description, true, true, properties)
			continue
		}
		for _, targetID := range capabilityTargets(row.Scope, capability, resources) {
			addRelationship(relationships, principalID, targetID, capability.EdgeType, capability.Name, capability.Description, true, true, cloneProperties(properties))
		}
	}

	if publicNeeded {
		resources["internet-public"] = model.ResourceNode{ID: "internet-public", Name: "Public Internet", Type: "external.internet", Category: "entry_point", Provider: "external", Criticality: model.SeverityInfo, Properties: map[string]string{"trust": "untrusted", "inferred": "true"}}
	}

	nodes := make([]model.ResourceNode, 0, len(resources))
	for _, resource := range resources {
		nodes = append(nodes, resource)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	edges := make([]model.RelationshipEdge, 0, len(relationships))
	for _, relationship := range relationships {
		edges = append(edges, relationship)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	return model.Snapshot{SchemaVersion: "1.0", ID: "azure-" + strings.ToLower(strings.ReplaceAll(scope.SubscriptionID, "-", "")), Name: "Azure subscription " + shortID(scope.SubscriptionID), Provider: "azure", GeneratedAt: generatedAt.UTC(), Description: "Read-only Azure Resource Graph snapshot. Inferred relationships are defensive hypotheses, not proof of exploitability.", Resources: nodes, Relationships: edges, Findings: []model.Finding{}, AttackPaths: []model.AttackPath{}}
}

func addRelationship(target map[string]model.RelationshipEdge, source, destination, edgeType, label, description string, exploitable, inferred bool, properties map[string]string) {
	if properties == nil {
		properties = map[string]string{}
	}
	if inferred {
		properties["inferred"] = "true"
	}
	id := edgeID(source, destination, edgeType)
	target[id] = model.RelationshipEdge{ID: id, Source: source, Target: destination, Type: edgeType, Label: label, Description: description, Exploitable: exploitable, Properties: properties}
}

func edgeID(source, target, edgeType string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + target + "\x00" + edgeType))
	return "rel-" + hex.EncodeToString(sum[:8])
}

func canonicalResourceType(value string) string {
	known := map[string]string{
		"microsoft.web/sites": "Microsoft.Web/sites", "microsoft.web/sites/functions": "Microsoft.Web/sites/functions", "microsoft.compute/virtualmachines": "Microsoft.Compute/virtualMachines", "microsoft.network/networksecuritygroups": "Microsoft.Network/networkSecurityGroups", "microsoft.network/publicipaddresses": "Microsoft.Network/publicIPAddresses", "microsoft.storage/storageaccounts": "Microsoft.Storage/storageAccounts", "microsoft.keyvault/vaults": "Microsoft.KeyVault/vaults", "microsoft.sql/servers": "Microsoft.Sql/servers", "microsoft.dbforpostgresql/flexibleservers": "Microsoft.DBforPostgreSQL/flexibleServers", "microsoft.managedidentity/userassignedidentities": "Microsoft.ManagedIdentity/userAssignedIdentities", "microsoft.operationalinsights/workspaces": "Microsoft.OperationalInsights/workspaces",
	}
	if canonical, ok := known[strings.ToLower(value)]; ok {
		return canonical
	}
	return value
}

func categoryForType(resourceType string) string {
	switch strings.ToLower(resourceType) {
	case "microsoft.web/sites", "microsoft.web/sites/functions", "microsoft.compute/virtualmachines":
		return "compute"
	case "microsoft.network/networksecuritygroups", "microsoft.network/publicipaddresses":
		return "network"
	case "microsoft.storage/storageaccounts", "microsoft.sql/servers", "microsoft.dbforpostgresql/flexibleservers":
		return "data"
	case "microsoft.keyvault/vaults":
		return "secrets"
	case "microsoft.managedidentity/userassignedidentities", "microsoft.managedidentity/systemassignedidentities":
		return "identity"
	case "microsoft.operationalinsights/workspaces":
		return "security"
	default:
		return "resource"
	}
}

func criticalityForType(resourceType string) model.Severity {
	switch strings.ToLower(resourceType) {
	case "microsoft.storage/storageaccounts", "microsoft.sql/servers", "microsoft.dbforpostgresql/flexibleservers", "microsoft.operationalinsights/workspaces":
		return model.SeverityCritical
	case "microsoft.keyvault/vaults", "microsoft.managedidentity/userassignedidentities", "microsoft.managedidentity/systemassignedidentities":
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}

func isPublic(row resourceRow, resourceType string) bool {
	return strings.EqualFold(row.PublicNetworkAccess, "enabled") || strings.EqualFold(row.PublicNetworkAccess, "true") || strings.EqualFold(resourceType, "Microsoft.Network/publicIPAddresses")
}

type roleCapability struct {
	Name        string
	EdgeType    string
	TargetType  string
	Description string
	Exploitable bool
}

func roleDetails(definitionID string) roleCapability {
	roles := map[string]roleCapability{
		"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": {Name: "Owner", EdgeType: "control_plane_access", Description: "Owner rights allow control-plane changes to this resource.", Exploitable: true},
		"b24988ac-6180-42a0-ab88-20f7382dd24c": {Name: "Contributor", EdgeType: "control_plane_access", Description: "Contributor rights allow control-plane changes to this resource.", Exploitable: true},
		"18d7d88d-d35e-4fb8-a5c7-7773c20a72d9": {Name: "User Access Administrator", EdgeType: "role_management", Description: "User Access Administrator can change role assignments at this scope.", Exploitable: true},
		"ba92f5b4-2d11-453d-a403-e96b0029c9fe": {Name: "Storage Blob Data Contributor", EdgeType: "data_access", TargetType: "Microsoft.Storage/storageAccounts", Description: "The role grants read and write access to blob data on this storage account.", Exploitable: true},
		"4633458b-17de-408a-b874-0445c86b69e6": {Name: "Key Vault Secrets User", EdgeType: "secret_access", TargetType: "Microsoft.KeyVault/vaults", Description: "The role grants access to secret values in this Key Vault.", Exploitable: true},
	}
	id := strings.ToLower(lastSegment(definitionID))
	if capability, ok := roles[id]; ok {
		return capability
	}
	return roleCapability{Name: "Azure role " + shortID(id), Exploitable: false}
}

func capabilityTargets(scope string, capability roleCapability, resources map[string]model.ResourceNode) []string {
	var targets []string
	for id, resource := range resources {
		if !withinScope(id, scope) || resource.Provider != "azure" {
			continue
		}
		if capability.TargetType != "" {
			if !strings.EqualFold(resource.Type, capability.TargetType) {
				continue
			}
		} else if resource.Category == "identity" || resource.Category == "scope" || resource.Category == "entry_point" {
			continue
		}
		targets = append(targets, id)
	}
	sort.Strings(targets)
	return targets
}

func withinScope(resourceID, scope string) bool {
	resourceID = strings.ToLower(strings.TrimSuffix(resourceID, "/"))
	scope = strings.ToLower(strings.TrimSuffix(scope, "/"))
	return resourceID == scope || strings.HasPrefix(resourceID, scope+"/")
}

func canonicalScope(scope string, resourceGroups map[string]string, resources map[string]model.ResourceNode) string {
	for id := range resources {
		if strings.EqualFold(id, scope) {
			return id
		}
	}
	if id, ok := resourceGroups[strings.ToLower(scope)]; ok {
		return id
	}
	return scope
}

func principalType(value string) string {
	switch strings.ToLower(value) {
	case "serviceprincipal":
		return "Microsoft.Entra/servicePrincipals"
	case "user":
		return "Microsoft.Entra/users"
	case "group":
		return "Microsoft.Entra/groups"
	default:
		return "Microsoft.Entra/principals"
	}
}

var subscriptionIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateScope(scope model.Scope) error {
	if !subscriptionIDPattern.MatchString(scope.SubscriptionID) {
		return fmt.Errorf("subscription id must be a UUID")
	}
	if scope.ResourceGroup != "" {
		return validateResourceGroupName(scope.ResourceGroup)
	}
	return nil
}

func validateResourceGroupName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > 90 {
		return fmt.Errorf("resource group name must contain 1 to 90 characters")
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("resource group name must not end with a period")
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) || unicode.In(r, unicode.Pc, unicode.Pd) || strings.ContainsRune("().", r) {
			continue
		}
		return fmt.Errorf("resource group name contains unsupported character %q", r)
	}
	return nil
}

func escapeKustoString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func cloneProperties(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func putIfPresent(target map[string]string, key, value string) {
	if value != "" {
		target[key] = value
	}
}
func fallback(value, fallbackValue string) string {
	if value != "" {
		return value
	}
	return fallbackValue
}
func lastSegment(value string) string {
	value = strings.TrimSuffix(value, "/")
	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[index+1:]
	}
	return value
}
func shortID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

var _ model.Collector = AzureResourceGraph{}
