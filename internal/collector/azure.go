package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const resourceQuery = `Resources
| where type in~ ('Microsoft.Web/sites', 'Microsoft.Web/sites/functions', 'Microsoft.Compute/virtualMachines', 'Microsoft.Network/networkInterfaces', 'Microsoft.Network/virtualNetworks', 'Microsoft.Network/virtualNetworks/subnets', 'Microsoft.Network/networkSecurityGroups', 'Microsoft.Network/publicIPAddresses', 'Microsoft.Network/privateEndpoints', 'Microsoft.Storage/storageAccounts', 'Microsoft.KeyVault/vaults', 'Microsoft.Sql/servers', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.ManagedIdentity/userAssignedIdentities', 'Microsoft.OperationalInsights/workspaces')
| project id=tostring(id), name=tostring(name), type=tostring(type), location=tostring(location), resourceGroup=tostring(resourceGroup), subscriptionId=tostring(subscriptionId), publicNetworkAccess=tostring(properties.publicNetworkAccess), systemPrincipalId=tostring(identity.principalId), managedIdentityPrincipalId=tostring(properties.principalId), userAssignedIdentities=identity.userAssignedIdentities, kind=tostring(kind), skuName=tostring(sku.name), networkProfile=properties.networkProfile, ipConfigurations=properties.ipConfigurations, networkSecurityGroupId=tostring(properties.networkSecurityGroup.id), subnets=properties.subnets, securityRules=properties.securityRules, ipConfigurationId=tostring(properties.ipConfiguration.id), subnetId=tostring(properties.subnet.id), networkInterfaces=properties.networkInterfaces, privateLinkServiceConnections=properties.privateLinkServiceConnections, ipSecurityRestrictionCount=array_length(properties.siteConfig.ipSecurityRestrictions), ipSecurityDefaultAction=tostring(properties.siteConfig.ipSecurityRestrictionsDefaultAction), networkDefaultAction=tostring(properties.networkAcls.defaultAction), allowBlobPublicAccess=tostring(properties.allowBlobPublicAccess), enableRbacAuthorization=tostring(properties.enableRbacAuthorization), delegatedSubnetResourceId=tostring(properties.delegatedSubnetResourceId)
| order by id asc`

const roleQuery = `AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| project id=tostring(id), name=tostring(name), type=tostring(type), scope=tostring(properties.scope), principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleDefinitionId=tostring(properties.roleDefinitionId)
| order by id asc`

const roleDefinitionQuery = `AuthorizationResources
| where type =~ 'microsoft.authorization/roledefinitions'
| project id=tostring(id), name=tostring(name), roleName=tostring(properties.roleName), roleType=tostring(properties.type), permissions=properties.permissions, assignableScopes=properties.assignableScopes
| order by id asc`

const (
	resourceGraphPageSize        = int32(1000)
	defaultMaxRowsPerQuery       = 50_000
	defaultMaxRowsAcrossQueries  = 100_000
	defaultMaxBytesPerQuery      = 64 << 20
	defaultMaxBytesAcrossQueries = 96 << 20
	defaultMaxPagesPerQuery      = 50
)

// ErrCollectionBudgetExceeded means Resource Graph returned more data than a
// local scan can retain safely. A scan fails closed instead of publishing a
// partial snapshot that could understate exposure.
var ErrCollectionBudgetExceeded = errors.New("Azure Resource Graph collection budget exceeded")

// AzureResourceGraph collects only projected, non-secret metadata through Azure's
// read-only Resource Graph endpoint. It creates no Azure resources and uses no ARM
// write client.
type AzureResourceGraph struct{}

type resourceReference struct {
	ID string `json:"id"`
}

type networkProfileRow struct {
	NetworkInterfaces []resourceReference `json:"networkInterfaces"`
}

type ipConfigurationRow struct {
	ID         string `json:"id"`
	Properties struct {
		Subnet          resourceReference `json:"subnet"`
		PublicIPAddress resourceReference `json:"publicIPAddress"`
	} `json:"properties"`
}

type subnetRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		NetworkSecurityGroup resourceReference `json:"networkSecurityGroup"`
	} `json:"properties"`
}

type securityRuleRow struct {
	Name       string `json:"name"`
	Properties struct {
		Access                     string   `json:"access"`
		Direction                  string   `json:"direction"`
		Protocol                   string   `json:"protocol"`
		Priority                   int      `json:"priority"`
		SourceAddressPrefix        string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes      []string `json:"sourceAddressPrefixes"`
		DestinationPortRange       string   `json:"destinationPortRange"`
		DestinationPortRanges      []string `json:"destinationPortRanges"`
		DestinationAddressPrefix   string   `json:"destinationAddressPrefix"`
		DestinationAddressPrefixes []string `json:"destinationAddressPrefixes"`
	} `json:"properties"`
}

type privateLinkConnectionRow struct {
	Properties struct {
		PrivateLinkServiceID string   `json:"privateLinkServiceId"`
		GroupIDs             []string `json:"groupIds"`
	} `json:"properties"`
}

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
	NetworkProfile             networkProfileRow                  `json:"networkProfile"`
	IPConfigurations           []ipConfigurationRow               `json:"ipConfigurations"`
	NetworkSecurityGroupID     string                             `json:"networkSecurityGroupId"`
	Subnets                    []subnetRow                        `json:"subnets"`
	SecurityRules              []securityRuleRow                  `json:"securityRules"`
	IPConfigurationID          string                             `json:"ipConfigurationId"`
	SubnetID                   string                             `json:"subnetId"`
	NetworkInterfaces          []resourceReference                `json:"networkInterfaces"`
	PrivateLinkConnections     []privateLinkConnectionRow         `json:"privateLinkServiceConnections"`
	IPSecurityRestrictionCount int                                `json:"ipSecurityRestrictionCount"`
	IPSecurityDefaultAction    string                             `json:"ipSecurityDefaultAction"`
	NetworkDefaultAction       string                             `json:"networkDefaultAction"`
	AllowBlobPublicAccess      string                             `json:"allowBlobPublicAccess"`
	EnableRBACAuthorization    string                             `json:"enableRbacAuthorization"`
	DelegatedSubnetResourceID  string                             `json:"delegatedSubnetResourceId"`
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

type permissionRow struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

type roleDefinitionRow struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	RoleName         string          `json:"roleName"`
	RoleType         string          `json:"roleType"`
	Permissions      []permissionRow `json:"permissions"`
	AssignableScopes []string        `json:"assignableScopes"`
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
	definitionsQuery := roleDefinitionQuery
	queryData, err := queryIndependent(ctx, client, scope.SubscriptionID, []namedQuery{{name: "Azure resources", query: resourcesQuery}, {name: "Azure role assignments", query: rolesQuery}, {name: "Azure role definitions", query: definitionsQuery}}, defaultQueryOptions())
	if err != nil {
		return model.Snapshot{}, err
	}
	resourceRows, err := decodeRows[resourceRow](queryData["Azure resources"])
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("decode Azure resources: %w", err)
	}
	roleRows, err := decodeRows[roleRow](queryData["Azure role assignments"])
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("decode Azure role assignments: %w", err)
	}
	roleDefinitions, err := decodeRows[roleDefinitionRow](queryData["Azure role definitions"])
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("decode Azure role definitions: %w", err)
	}
	return normalizeAzureWithDefinitions(scope, resourceRows, roleRows, roleDefinitions, time.Now().UTC()), nil
}

type resourceGraphClient interface {
	Resources(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

type namedQuery struct {
	name  string
	query string
}

type queryOptions struct {
	MaxConcurrency        int
	MaxAttempts           int
	MaxRowsPerQuery       int
	MaxRowsAcrossQueries  int
	MaxBytesPerQuery      int
	MaxBytesAcrossQueries int
	MaxPagesPerQuery      int
	RetryDelay            func(context.Context, int) error
	Retryable             func(error) bool
}

func defaultQueryOptions() queryOptions {
	return queryOptions{MaxConcurrency: 3, MaxAttempts: 3, MaxRowsPerQuery: defaultMaxRowsPerQuery, MaxRowsAcrossQueries: defaultMaxRowsAcrossQueries, MaxBytesPerQuery: defaultMaxBytesPerQuery, MaxBytesAcrossQueries: defaultMaxBytesAcrossQueries, MaxPagesPerQuery: defaultMaxPagesPerQuery, RetryDelay: func(ctx context.Context, attempt int) error {
		timer := time.NewTimer(time.Duration(attempt) * 200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}, Retryable: isRetryableAzureError}
}

func isRetryableAzureError(err error) bool {
	var responseErr *azcore.ResponseError
	if !errors.As(err, &responseErr) {
		return false
	}
	return responseErr.StatusCode == http.StatusTooManyRequests || responseErr.StatusCode == http.StatusRequestTimeout || responseErr.StatusCode >= 500
}

func queryIndependent(ctx context.Context, client resourceGraphClient, subscriptionID string, queries []namedQuery, options queryOptions) (map[string][]any, error) {
	options = normalizedQueryOptions(options)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(map[string][]any, len(queries))
	errs := make([]error, len(queries))
	budget := &queryRetentionBudget{rowLimit: options.MaxRowsAcrossQueries, byteLimit: options.MaxBytesAcrossQueries}
	jobs := make(chan int)
	var mutex sync.Mutex
	var workers sync.WaitGroup
	workerCount := min(options.MaxConcurrency, len(queries))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				rows, err := queryAllWithBudget(ctx, client, subscriptionID, queries[index].query, options, budget)
				mutex.Lock()
				if err != nil {
					errs[index] = fmt.Errorf("query %s: %w", queries[index].name, err)
					cancel()
				} else {
					results[queries[index].name] = rows
				}
				mutex.Unlock()
			}
		}()
	}
enqueue:
	for index := range queries {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(jobs)
	workers.Wait()
	for _, err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func queryAll(ctx context.Context, client resourceGraphClient, subscriptionID, query string) ([]any, error) {
	options := defaultQueryOptions()
	options.MaxAttempts = 1
	return queryAllWithRetry(ctx, client, subscriptionID, query, options)
}

func queryAllWithRetry(ctx context.Context, client resourceGraphClient, subscriptionID, query string, options queryOptions) ([]any, error) {
	return queryAllWithBudget(ctx, client, subscriptionID, query, normalizedQueryOptions(options), nil)
}

type queryRetentionBudget struct {
	mutex     sync.Mutex
	rowsUsed  int
	rowLimit  int
	bytesUsed int
	byteLimit int
}

func (budget *queryRetentionBudget) reserve(rows, bytes int) error {
	if budget == nil || (rows == 0 && bytes == 0) {
		return nil
	}
	budget.mutex.Lock()
	defer budget.mutex.Unlock()
	if rows > budget.rowLimit-budget.rowsUsed {
		return fmt.Errorf("%w: concurrent queries exceeded %d retained rows; refusing a partial snapshot", ErrCollectionBudgetExceeded, budget.rowLimit)
	}
	if bytes > budget.byteLimit-budget.bytesUsed {
		return fmt.Errorf("%w: concurrent queries exceeded %d retained JSON bytes; refusing a partial snapshot", ErrCollectionBudgetExceeded, budget.byteLimit)
	}
	budget.rowsUsed += rows
	budget.bytesUsed += bytes
	return nil
}

func normalizedQueryOptions(options queryOptions) queryOptions {
	if options.MaxConcurrency <= 0 {
		options.MaxConcurrency = 1
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 1
	}
	if options.MaxRowsPerQuery <= 0 {
		options.MaxRowsPerQuery = defaultMaxRowsPerQuery
	}
	if options.MaxRowsAcrossQueries <= 0 {
		options.MaxRowsAcrossQueries = defaultMaxRowsAcrossQueries
	}
	if options.MaxBytesPerQuery <= 0 {
		options.MaxBytesPerQuery = defaultMaxBytesPerQuery
	}
	if options.MaxBytesAcrossQueries <= 0 {
		options.MaxBytesAcrossQueries = defaultMaxBytesAcrossQueries
	}
	if options.MaxPagesPerQuery <= 0 {
		options.MaxPagesPerQuery = defaultMaxPagesPerQuery
	}
	return options
}

func queryAllWithBudget(ctx context.Context, client resourceGraphClient, subscriptionID, query string, options queryOptions, sharedBudget *queryRetentionBudget) ([]any, error) {
	options = normalizedQueryOptions(options)
	var rows []any
	retainedBytes := 0
	var skipToken *string
	seenSkipTokens := make(map[string]struct{})
	pages := 0
	for {
		if pages >= options.MaxPagesPerQuery {
			return nil, fmt.Errorf("%w: query exceeded %d pages; refusing a partial snapshot", ErrCollectionBudgetExceeded, options.MaxPagesPerQuery)
		}
		pages++
		var response armresourcegraph.ClientResourcesResponse
		var err error
		for attempt := 1; attempt <= options.MaxAttempts; attempt++ {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			response, err = client.Resources(ctx, armresourcegraph.QueryRequest{
				Query:         to.Ptr(query),
				Subscriptions: []*string{to.Ptr(subscriptionID)},
				Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray), SkipToken: skipToken, Top: to.Ptr(resourceGraphPageSize)},
			}, nil)
			if err == nil || attempt == options.MaxAttempts || options.Retryable == nil || !options.Retryable(err) {
				break
			}
			if options.RetryDelay != nil {
				if delayErr := options.RetryDelay(ctx, attempt); delayErr != nil {
					return nil, delayErr
				}
			}
		}
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
		if len(page) > options.MaxRowsPerQuery-len(rows) {
			return nil, fmt.Errorf("%w: query exceeded %d rows; refusing a partial snapshot", ErrCollectionBudgetExceeded, options.MaxRowsPerQuery)
		}
		encodedPage, marshalErr := json.Marshal(page)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode query page for retention budget: %w", marshalErr)
		}
		if len(encodedPage) > options.MaxBytesPerQuery-retainedBytes {
			return nil, fmt.Errorf("%w: query exceeded %d retained JSON bytes; refusing a partial snapshot", ErrCollectionBudgetExceeded, options.MaxBytesPerQuery)
		}
		if err := sharedBudget.reserve(len(page), len(encodedPage)); err != nil {
			return nil, err
		}
		retainedBytes += len(encodedPage)
		rows = append(rows, page...)
		if response.SkipToken == nil || *response.SkipToken == "" {
			break
		}
		if len(rows) == options.MaxRowsPerQuery {
			return nil, fmt.Errorf("%w: query reached %d rows with more pages available; refusing a partial snapshot", ErrCollectionBudgetExceeded, options.MaxRowsPerQuery)
		}
		if _, exists := seenSkipTokens[*response.SkipToken]; exists {
			return nil, fmt.Errorf("%w: Resource Graph repeated a pagination token", ErrCollectionBudgetExceeded)
		}
		seenSkipTokens[*response.SkipToken] = struct{}{}
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
	return normalizeAzureWithDefinitions(scope, resourceRows, roleRows, nil, generatedAt)
}

func normalizeAzureWithDefinitions(scope model.Scope, resourceRows []resourceRow, roleRows []roleRow, roleDefinitions []roleDefinitionRow, generatedAt time.Time) model.Snapshot {
	resourceRows = append([]resourceRow(nil), resourceRows...)
	roleRows = append([]roleRow(nil), roleRows...)
	sort.Slice(resourceRows, func(i, j int) bool { return resourceRows[i].ID < resourceRows[j].ID })
	sort.Slice(roleRows, func(i, j int) bool { return roleRows[i].ID < roleRows[j].ID })
	resources := make(map[string]model.ResourceNode)
	relationships := make(map[string]model.RelationshipEdge)
	resourceGroups := make(map[string]string)
	principalNodes := make(map[string]string)
	publicNeeded := false
	subscriptionScope := "/subscriptions/" + scope.SubscriptionID
	resources[subscriptionScope] = model.ResourceNode{ID: subscriptionScope, Name: "Subscription " + shortID(scope.SubscriptionID), Type: "Microsoft.Resources/subscriptions", Category: "scope", Provider: "azure", Criticality: model.SeverityMedium, Properties: map[string]string{"subscriptionId": scope.SubscriptionID}}

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
		putIfPresent(properties, "networkDefaultAction", row.NetworkDefaultAction)
		putIfPresent(properties, "allowBlobPublicAccess", row.AllowBlobPublicAccess)
		putIfPresent(properties, "enableRbacAuthorization", row.EnableRBACAuthorization)
		putIfPresent(properties, "delegatedSubnetResourceId", row.DelegatedSubnetResourceID)
		if row.IPSecurityRestrictionCount > 0 {
			properties["accessRestrictionCount"] = fmt.Sprintf("%d", row.IPSecurityRestrictionCount)
		}
		putIfPresent(properties, "accessRestrictionDefaultAction", row.IPSecurityDefaultAction)
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
				addClassifiedRelationship(relationships, subscriptionScope, rgID, "contains", "contains", "The resource group belongs to this subscription.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(rgID, "subscriptionId", subscriptionID)})
			}
			addClassifiedRelationship(relationships, rgID, row.ID, "contains", "contains", "The resource belongs to this resource group.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "resourceGroup", row.ResourceGroup)})
		}

		exposure := classifyPublicExposure(row, typeName)
		if exposure.visible {
			publicNeeded = true
			addClassifiedRelationship(relationships, "internet-public", row.ID, exposure.edgeType, exposure.label, exposure.description, exposure.exploitable, model.RelationshipDerived, exposure.confidence, nil, publicEvidence(row))
		}
		if row.SystemPrincipalID != "" {
			identityID := "identity:" + strings.ToLower(row.SystemPrincipalID)
			if _, exists := resources[identityID]; !exists {
				resources[identityID] = model.ResourceNode{ID: identityID, Name: "System-assigned identity " + shortID(row.SystemPrincipalID), Type: "Microsoft.ManagedIdentity/systemAssignedIdentities", Category: "identity", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"principalId": row.SystemPrincipalID}}
			}
			principalNodes[strings.ToLower(row.SystemPrincipalID)] = identityID
			addClassifiedRelationship(relationships, row.ID, identityID, "managed_identity", "runs as", "The resource can request tokens for its managed identity.", true, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "identity.principalId", row.SystemPrincipalID)})
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
			addClassifiedRelationship(relationships, row.ID, identityID, "managed_identity", "runs as", "The resource can request tokens for its user-assigned identity.", true, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "identity.userAssignedIdentities", identityID)})
		}
	}

	normalizeNetworkRelationships(resourceRows, resources, relationships, &publicNeeded)
	definitions := indexRoleDefinitions(roleDefinitions)

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
		scopeID := canonicalScope(row.Scope, resourceGroups, resources)
		if _, exists := resources[scopeID]; !exists {
			resources[scopeID] = model.ResourceNode{ID: scopeID, Name: lastSegment(scopeID), Type: scopeType(scopeID), Category: "scope", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"inferred": "true"}}
		}
		capabilities := roleCapabilities(row.RoleDefinitionID, definitions)
		properties := map[string]string{"roleDefinitionId": row.RoleDefinitionID, "scope": scopeID}
		if row.ID != "" {
			properties["roleAssignmentId"] = row.ID
		}
		if len(capabilities) == 0 {
			addDistinctClassifiedRelationship(relationships, principalID, scopeID, "role_assignment", "Azure role "+shortID(lastSegment(row.RoleDefinitionID)), "An unclassified Azure role is present; CloudThreat Atlas does not assume exploitability.", false, model.RelationshipObserved, model.ConfidenceHigh, properties, []model.EvidenceRecord{azureEvidence(row.ID, "properties.roleDefinitionId", row.RoleDefinitionID), azureEvidence(row.ID, "properties.scope", row.Scope)}, roleEdgeDiscriminator(row, roleCapability{}))
			continue
		}
		for _, capability := range capabilities {
			capabilityProperties := cloneProperties(properties)
			putIfPresent(capabilityProperties, "targetType", capability.TargetType)
			if capability.Custom {
				capabilityProperties["customRole"] = "true"
			}
			confidence := model.ConfidenceHigh
			if capability.Custom {
				confidence = model.ConfidenceMedium
			}
			addDistinctClassifiedRelationship(relationships, principalID, scopeID, capability.EdgeType, capability.Name, capability.Description, capability.Exploitable, model.RelationshipDerived, confidence, capabilityProperties, []model.EvidenceRecord{azureEvidence(row.ID, "properties.roleDefinitionId", row.RoleDefinitionID), azureEvidence(row.ID, "properties.scope", row.Scope)}, roleEdgeDiscriminator(row, capability))
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
	snapshotScope := scope
	return model.Snapshot{SchemaVersion: "1.0", ID: "azure-" + strings.ToLower(strings.ReplaceAll(scope.SubscriptionID, "-", "")), Name: "Azure subscription " + shortID(scope.SubscriptionID), Provider: "azure", Scope: &snapshotScope, GeneratedAt: generatedAt.UTC(), Description: "Read-only Azure Resource Graph snapshot. Inferred relationships are defensive hypotheses, not proof of exploitability.", Resources: nodes, Relationships: edges, Findings: []model.Finding{}, AttackPaths: []model.AttackPath{}}
}

func addRelationship(target map[string]model.RelationshipEdge, source, destination, edgeType, label, description string, exploitable, inferred bool, properties map[string]string) {
	origin := model.RelationshipObserved
	confidence := model.ConfidenceHigh
	if inferred {
		origin = model.RelationshipDerived
	}
	addClassifiedRelationship(target, source, destination, edgeType, label, description, exploitable, origin, confidence, properties, nil)
}

func addClassifiedRelationship(target map[string]model.RelationshipEdge, source, destination, edgeType, label, description string, exploitable bool, origin model.RelationshipOrigin, confidence model.Confidence, properties map[string]string, evidence []model.EvidenceRecord) {
	addDistinctClassifiedRelationship(target, source, destination, edgeType, label, description, exploitable, origin, confidence, properties, evidence, "")
}

func addDistinctClassifiedRelationship(target map[string]model.RelationshipEdge, source, destination, edgeType, label, description string, exploitable bool, origin model.RelationshipOrigin, confidence model.Confidence, properties map[string]string, evidence []model.EvidenceRecord, discriminator string) {
	properties = cloneProperties(properties)
	if properties == nil {
		properties = map[string]string{}
	}
	if origin != model.RelationshipObserved {
		properties["inferred"] = "true"
	}
	id := edgeID(source, destination, edgeType, discriminator)
	target[id] = model.RelationshipEdge{ID: id, Source: source, Target: destination, Type: edgeType, Label: label, Description: description, Exploitable: exploitable, Properties: properties, Origin: origin, Confidence: confidence, Evidence: append([]model.EvidenceRecord(nil), evidence...)}
}

func edgeID(source, target, edgeType string, discriminators ...string) string {
	identity := source + "\x00" + target + "\x00" + edgeType
	for _, discriminator := range discriminators {
		if discriminator != "" {
			identity += "\x00" + discriminator
		}
	}
	sum := sha256.Sum256([]byte(identity))
	return "rel-" + hex.EncodeToString(sum[:8])
}

func roleEdgeDiscriminator(row roleRow, capability roleCapability) string {
	return strings.Join([]string{row.ID, row.RoleDefinitionID, row.Scope, capability.EdgeType, capability.TargetType, capability.Name}, "\x00")
}

func canonicalResourceType(value string) string {
	known := map[string]string{
		"microsoft.web/sites": "Microsoft.Web/sites", "microsoft.web/sites/functions": "Microsoft.Web/sites/functions", "microsoft.compute/virtualmachines": "Microsoft.Compute/virtualMachines", "microsoft.network/networkinterfaces": "Microsoft.Network/networkInterfaces", "microsoft.network/virtualnetworks": "Microsoft.Network/virtualNetworks", "microsoft.network/virtualnetworks/subnets": "Microsoft.Network/virtualNetworks/subnets", "microsoft.network/networksecuritygroups": "Microsoft.Network/networkSecurityGroups", "microsoft.network/publicipaddresses": "Microsoft.Network/publicIPAddresses", "microsoft.network/privateendpoints": "Microsoft.Network/privateEndpoints", "microsoft.storage/storageaccounts": "Microsoft.Storage/storageAccounts", "microsoft.keyvault/vaults": "Microsoft.KeyVault/vaults", "microsoft.sql/servers": "Microsoft.Sql/servers", "microsoft.dbforpostgresql/flexibleservers": "Microsoft.DBforPostgreSQL/flexibleServers", "microsoft.managedidentity/userassignedidentities": "Microsoft.ManagedIdentity/userAssignedIdentities", "microsoft.operationalinsights/workspaces": "Microsoft.OperationalInsights/workspaces",
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
	case "microsoft.network/networksecuritygroups", "microsoft.network/publicipaddresses", "microsoft.network/networkinterfaces", "microsoft.network/virtualnetworks", "microsoft.network/virtualnetworks/subnets", "microsoft.network/privateendpoints":
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

type publicExposure struct {
	visible     bool
	exploitable bool
	edgeType    string
	label       string
	description string
	confidence  model.Confidence
}

func classifyPublicExposure(row resourceRow, resourceType string) publicExposure {
	endpoint := publicExposure{
		visible: true, edgeType: "public_endpoint", label: "public endpoint enabled",
		description: "A public endpoint exists, but the collected metadata does not establish Internet-wide reachability.",
		confidence:  model.ConfidenceHigh,
	}
	wide := publicExposure{
		visible: true, exploitable: true, edgeType: "public_exposure", label: "Internet-wide endpoint",
		description: "Resource Graph network settings allow Internet-wide network reachability; service authentication may still apply.",
		confidence:  model.ConfidenceHigh,
	}
	if strings.EqualFold(resourceType, "Microsoft.Network/publicIPAddresses") {
		return endpoint
	}
	if strings.EqualFold(row.PublicNetworkAccess, "disabled") || strings.EqualFold(row.PublicNetworkAccess, "false") {
		return publicExposure{}
	}
	if strings.EqualFold(row.NetworkDefaultAction, "deny") || strings.EqualFold(row.IPSecurityDefaultAction, "deny") {
		if strings.EqualFold(row.PublicNetworkAccess, "enabled") || strings.EqualFold(row.PublicNetworkAccess, "true") {
			return endpoint
		}
		return publicExposure{}
	}
	if strings.EqualFold(row.NetworkDefaultAction, "allow") || strings.EqualFold(row.IPSecurityDefaultAction, "allow") {
		return wide
	}
	if strings.EqualFold(resourceType, "Microsoft.Web/sites") || strings.EqualFold(resourceType, "Microsoft.Web/sites/functions") {
		if (strings.EqualFold(row.PublicNetworkAccess, "enabled") || strings.EqualFold(row.PublicNetworkAccess, "true")) && row.IPSecurityRestrictionCount == 0 {
			wide.confidence = model.ConfidenceMedium
			return wide
		}
	}
	if strings.EqualFold(row.PublicNetworkAccess, "enabled") || strings.EqualFold(row.PublicNetworkAccess, "true") {
		return endpoint
	}
	return publicExposure{}
}

func publicEvidence(row resourceRow) []model.EvidenceRecord {
	var evidence []model.EvidenceRecord
	if row.PublicNetworkAccess != "" {
		evidence = append(evidence, azureEvidence(row.ID, "properties.publicNetworkAccess", row.PublicNetworkAccess))
	}
	if row.NetworkDefaultAction != "" {
		evidence = append(evidence, azureEvidence(row.ID, "properties.networkAcls.defaultAction", row.NetworkDefaultAction))
	}
	if strings.EqualFold(row.Type, "Microsoft.Network/publicIPAddresses") {
		evidence = append(evidence, azureEvidence(row.ID, "type", row.Type))
	}
	return evidence
}

func azureEvidence(resourceID, field, value string) model.EvidenceRecord {
	return model.EvidenceRecord{Source: "azure-resource-graph", ResourceID: resourceID, Field: field, Value: value}
}

func normalizeNetworkRelationships(rows []resourceRow, resources map[string]model.ResourceNode, relationships map[string]model.RelationshipEdge, publicNeeded *bool) {
	canonicalIDs := make(map[string]string, len(resources))
	for id := range resources {
		canonicalIDs[strings.ToLower(id)] = id
	}
	ensure := func(id, resourceType string) string {
		if id == "" {
			return ""
		}
		if canonical, ok := canonicalIDs[strings.ToLower(id)]; ok {
			return canonical
		}
		resources[id] = model.ResourceNode{ID: id, Name: lastSegment(id), Type: resourceType, Category: categoryForType(resourceType), Provider: "azure", Criticality: model.SeverityMedium, Properties: map[string]string{"inferred": "true"}}
		canonicalIDs[strings.ToLower(id)] = id
		return id
	}

	for _, row := range rows {
		if !strings.EqualFold(row.Type, "Microsoft.Network/virtualNetworks") {
			continue
		}
		for _, subnet := range row.Subnets {
			subnetID := ensure(subnet.ID, "Microsoft.Network/virtualNetworks/subnets")
			if subnetID == "" {
				continue
			}
			addClassifiedRelationship(relationships, row.ID, subnetID, "contains", "contains subnet", "The virtual network contains this subnet.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.subnets", subnet.ID)})
			if nsgID := ensure(subnet.Properties.NetworkSecurityGroup.ID, "Microsoft.Network/networkSecurityGroups"); nsgID != "" {
				addClassifiedRelationship(relationships, nsgID, subnetID, "network_filter", "filters subnet", "The network security group filters traffic for this subnet. This attachment alone does not prove effective reachability.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(subnetID, "properties.networkSecurityGroup.id", nsgID)})
			}
		}
	}

	for _, row := range rows {
		switch strings.ToLower(row.Type) {
		case "microsoft.compute/virtualmachines":
			for _, reference := range row.NetworkProfile.NetworkInterfaces {
				if nicID := ensure(reference.ID, "Microsoft.Network/networkInterfaces"); nicID != "" {
					addClassifiedRelationship(relationships, nicID, row.ID, "network_access", "attached to", "The network interface is attached to this virtual machine.", true, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.networkProfile.networkInterfaces", nicID)})
				}
			}
		case "microsoft.network/networkinterfaces":
			if nsgID := ensure(row.NetworkSecurityGroupID, "Microsoft.Network/networkSecurityGroups"); nsgID != "" {
				addClassifiedRelationship(relationships, nsgID, row.ID, "network_filter", "filters interface", "The network security group filters traffic for this network interface. This attachment alone does not prove effective reachability.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.networkSecurityGroup.id", nsgID)})
			}
			for _, configuration := range row.IPConfigurations {
				if subnetID := ensure(configuration.Properties.Subnet.ID, "Microsoft.Network/virtualNetworks/subnets"); subnetID != "" {
					addClassifiedRelationship(relationships, subnetID, row.ID, "network_segment", "connects interface", "The network interface has an IP configuration on this subnet.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.ipConfigurations[].properties.subnet.id", subnetID)})
				}
				if publicIPID := ensure(configuration.Properties.PublicIPAddress.ID, "Microsoft.Network/publicIPAddresses"); publicIPID != "" {
					*publicNeeded = true
					addClassifiedRelationship(relationships, publicIPID, row.ID, "public_ip_association", "addresses interface", "The public IP address is associated with this network interface; an NSG or service rule must independently establish allowed ingress.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.ipConfigurations[].properties.publicIPAddress.id", publicIPID)})
				}
			}
		case "microsoft.network/publicipaddresses":
			if nicID := parentResourceID(row.IPConfigurationID, "/ipConfigurations/"); nicID != "" {
				nicID = ensure(nicID, "Microsoft.Network/networkInterfaces")
				addClassifiedRelationship(relationships, row.ID, nicID, "public_ip_association", "addresses interface", "The public IP address is associated with this network interface; an NSG or service rule must independently establish allowed ingress.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.ipConfiguration.id", row.IPConfigurationID)})
			}
		case "microsoft.network/privateendpoints":
			if subnetID := ensure(row.SubnetID, "Microsoft.Network/virtualNetworks/subnets"); subnetID != "" {
				addClassifiedRelationship(relationships, subnetID, row.ID, "network_segment", "hosts private endpoint", "The private endpoint is connected to this subnet.", false, model.RelationshipObserved, model.ConfidenceHigh, nil, []model.EvidenceRecord{azureEvidence(row.ID, "properties.subnet.id", subnetID)})
			}
			for _, connection := range row.PrivateLinkConnections {
				if serviceID := ensure(connection.Properties.PrivateLinkServiceID, "Microsoft.Resources/resources"); serviceID != "" {
					properties := map[string]string{"groupIds": strings.Join(connection.Properties.GroupIDs, ",")}
					addClassifiedRelationship(relationships, row.ID, serviceID, "private_endpoint", "private link", "The private endpoint connects to this Azure service.", false, model.RelationshipObserved, model.ConfidenceHigh, properties, []model.EvidenceRecord{azureEvidence(row.ID, "properties.privateLinkServiceConnections[].properties.privateLinkServiceId", serviceID)})
				}
			}
		case "microsoft.network/networksecuritygroups":
			for _, rule := range row.SecurityRules {
				if !isPublicInboundAllow(rule) {
					continue
				}
				*publicNeeded = true
				properties := map[string]string{"securityRule": rule.Name, "priority": fmt.Sprintf("%d", rule.Properties.Priority), "protocol": rule.Properties.Protocol, "destinationPorts": joinedValues(rule.Properties.DestinationPortRange, rule.Properties.DestinationPortRanges)}
				addClassifiedRelationship(relationships, "internet-public", row.ID, "public_ingress_candidate", "public inbound rule", "An inbound allow rule accepts an Internet-wide source, but effective reachability also depends on public addressing, rule priority, and every subnet- and NIC-level NSG.", false, model.RelationshipHeuristic, model.ConfidenceMedium, properties, []model.EvidenceRecord{azureEvidence(row.ID, "properties.securityRules", rule.Name)})
			}
		}
	}
}

func isPublicInboundAllow(rule securityRuleRow) bool {
	if !strings.EqualFold(rule.Properties.Access, "allow") || !strings.EqualFold(rule.Properties.Direction, "inbound") {
		return false
	}
	sources := append([]string{rule.Properties.SourceAddressPrefix}, rule.Properties.SourceAddressPrefixes...)
	for _, source := range sources {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "*", "internet", "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

func parentResourceID(id, marker string) string {
	index := strings.Index(strings.ToLower(id), strings.ToLower(marker))
	if index < 0 {
		return ""
	}
	return id[:index]
}

func joinedValues(single string, values []string) string {
	result := append([]string(nil), values...)
	if single != "" {
		result = append([]string{single}, result...)
	}
	return strings.Join(result, ",")
}

type roleCapability struct {
	Name        string
	EdgeType    string
	TargetType  string
	Description string
	Exploitable bool
	Custom      bool
}

func indexRoleDefinitions(rows []roleDefinitionRow) map[string]roleDefinitionRow {
	result := make(map[string]roleDefinitionRow, len(rows)*2)
	for _, row := range rows {
		result[strings.ToLower(row.ID)] = row
		result[strings.ToLower(lastSegment(row.ID))] = row
	}
	return result
}

func roleCapabilities(definitionID string, definitions map[string]roleDefinitionRow) []roleCapability {
	known := roleDetails(definitionID)
	if known.Exploitable {
		return []roleCapability{known}
	}
	definition, ok := definitions[strings.ToLower(definitionID)]
	if !ok {
		definition, ok = definitions[strings.ToLower(lastSegment(definitionID))]
	}
	if !ok {
		return nil
	}
	name := fallback(definition.RoleName, "Custom Azure role "+shortID(lastSegment(definitionID)))
	custom := strings.EqualFold(definition.RoleType, "CustomRole")
	type candidate struct {
		action      string
		data        bool
		edgeType    string
		targetType  string
		description string
	}
	candidates := []candidate{
		{action: "Microsoft.Authorization/roleAssignments/write", edgeType: "role_management", description: "The role's actions permit role-assignment changes at the assigned scope."},
		{action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", data: true, edgeType: "data_access", targetType: "Microsoft.Storage/storageAccounts", description: "The role's data actions permit reading blob data within the assigned scope."},
		{action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", data: true, edgeType: "data_access", targetType: "Microsoft.Storage/storageAccounts", description: "The role's data actions permit writing blob data within the assigned scope."},
		{action: "Microsoft.KeyVault/vaults/secrets/getSecret/action", data: true, edgeType: "secret_access", targetType: "Microsoft.KeyVault/vaults", description: "The role's data actions permit reading Key Vault secret values within the assigned scope."},
		{action: "Microsoft.Storage/storageAccounts/write", edgeType: "control_plane_access", targetType: "Microsoft.Storage/storageAccounts", description: "The role's actions permit storage-account control-plane changes within the assigned scope."},
		{action: "Microsoft.KeyVault/vaults/write", edgeType: "control_plane_access", targetType: "Microsoft.KeyVault/vaults", description: "The role's actions permit Key Vault control-plane changes within the assigned scope."},
		{action: "Microsoft.Web/sites/write", edgeType: "control_plane_access", targetType: "Microsoft.Web/sites", description: "The role's actions permit App Service control-plane changes within the assigned scope."},
		{action: "Microsoft.Compute/virtualMachines/write", edgeType: "control_plane_access", targetType: "Microsoft.Compute/virtualMachines", description: "The role's actions permit virtual-machine control-plane changes within the assigned scope."},
	}
	byKey := make(map[string]roleCapability)
	for _, permission := range definition.Permissions {
		for _, candidate := range candidates {
			allowed := permissionAllows(permission.Actions, permission.NotActions, candidate.action)
			if candidate.data {
				allowed = permissionAllows(permission.DataActions, permission.NotDataActions, candidate.action)
			}
			if !allowed {
				continue
			}
			key := candidate.edgeType + "\x00" + candidate.targetType
			byKey[key] = roleCapability{Name: name, EdgeType: candidate.edgeType, TargetType: candidate.targetType, Description: candidate.description, Exploitable: true, Custom: custom}
		}
	}
	// Keep one capability per edge/target pair. Combining target types into a
	// comma-separated string made type comparisons fail and collapsed distinct
	// custom-role grants into one ambiguous relationship.
	result := make([]roleCapability, 0, len(byKey))
	for _, capability := range byKey {
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].EdgeType == result[j].EdgeType {
			return result[i].TargetType < result[j].TargetType
		}
		return result[i].EdgeType < result[j].EdgeType
	})
	return result
}

func permissionAllows(grants, exclusions []string, desired string) bool {
	allowed := false
	for _, grant := range grants {
		if azureActionMatches(grant, desired) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	for _, exclusion := range exclusions {
		if azureActionMatches(exclusion, desired) {
			return false
		}
	}
	return true
}

func azureActionMatches(pattern, action string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	action = strings.ToLower(strings.TrimSpace(action))
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	matched, err := regexp.MatchString("^"+quoted+"$", action)
	return err == nil && matched
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

func scopeType(scope string) string {
	lower := strings.ToLower(strings.TrimSuffix(scope, "/"))
	switch {
	case regexp.MustCompile(`^/subscriptions/[^/]+$`).MatchString(lower):
		return "Microsoft.Resources/subscriptions"
	case strings.Contains(lower, "/resourcegroups/") && !strings.Contains(lower[strings.Index(lower, "/resourcegroups/")+len("/resourcegroups/"):], "/"):
		return "Microsoft.Resources/resourceGroups"
	default:
		return "Microsoft.Authorization/scopes"
	}
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
