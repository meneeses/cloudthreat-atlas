package rules

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const (
	defaultChainRuleMaxWork          = 100_000
	defaultAzureExposureMaxWork      = 250_000
	defaultAzureExposureMaxDepth     = 16
	defaultAzureExposureMaxTargets   = 2_000
	defaultAzureExposureMaxFindings  = 2_000
	defaultRoleManagementMaxWork     = 200_000
	defaultRoleManagementMaxFindings = 2_000
)

// ErrRuleEvaluationBudgetExceeded means an untrusted graph required more work
// or retained results than a built-in rule can safely process. Callers must
// reject the analysis rather than use partial findings.
var ErrRuleEvaluationBudgetExceeded = errors.New("rule evaluation budget exceeded")

type evaluationBudget struct {
	label string
	limit int
	used  int
}

func newEvaluationBudget(label string, limit int) *evaluationBudget {
	return &evaluationBudget{label: label, limit: limit}
}

func (b *evaluationBudget) consume(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.used >= b.limit {
		return fmt.Errorf("%w: %s exceeded %d work units", ErrRuleEvaluationBudgetExceeded, b.label, b.limit)
	}
	b.used++
	return nil
}

func evaluationLimitError(label, dimension string, limit int) error {
	return fmt.Errorf("%w: %s exceeded %d %s", ErrRuleEvaluationBudgetExceeded, label, limit, dimension)
}

type chainRule struct {
	id          string
	findingID   string
	title       string
	description string
	severity    model.Severity
	score       int
	nodeTypes   []string
	edgeTypes   []string
	evidence    []string
	remediation model.Remediation
	maxWork     int
}

// Default returns the native Go rules used by the deterministic demo and local scanner.
func Default() []model.Rule {
	return []model.Rule{
		chainRule{
			id:          "CTA-AZ-001",
			findingID:   "finding-public-app-secret-chain",
			title:       "Public application identity can reach the clinical database",
			description: "An internet-facing App Service uses a managed identity that can read a database credential from Key Vault.",
			severity:    model.SeverityCritical,
			score:       96,
			nodeTypes: []string{
				"external.internet",
				"Microsoft.Web/sites",
				"Microsoft.ManagedIdentity/userAssignedIdentities",
				"Microsoft.KeyVault/vaults",
				"Microsoft.DBforPostgreSQL/flexibleServers",
			},
			edgeTypes: []string{"public_http", "managed_identity", "secret_access", "credential_pivot"},
			evidence: []string{
				"The App Service accepts public internet traffic.",
				"Its managed identity can read a database credential from Key Vault.",
				"The credential unlocks a critical PostgreSQL server.",
			},
			remediation: model.Remediation{
				Summary: "Remove the identity's direct secret-read permission and use a narrowly scoped credential flow.",
				Steps: []string{
					"Remove the Key Vault secret access relationship from the application identity.",
					"Restrict App Service ingress with a private endpoint or an authenticated gateway.",
					"Rotate the affected database credential after access is removed.",
				},
			},
		},
		chainRule{
			id:          "CTA-AZ-002",
			findingID:   "finding-public-vm-storage-chain",
			title:       "Public VM identity can read sensitive patient storage",
			description: "A permissive NSG exposes a virtual machine whose workload identity has data-plane access to a critical storage account.",
			severity:    model.SeverityCritical,
			score:       94,
			nodeTypes: []string{
				"external.internet",
				"Microsoft.Network/networkSecurityGroups",
				"Microsoft.Compute/virtualMachines",
				"Microsoft.ManagedIdentity/userAssignedIdentities",
				"Microsoft.Storage/storageAccounts",
			},
			edgeTypes: []string{"public_ingress", "network_access", "privileged_identity", "data_access"},
			evidence: []string{
				"The NSG accepts management traffic from any source.",
				"The virtual machine exposes a privileged workload identity.",
				"The identity has blob data access on patient storage.",
			},
			remediation: model.Remediation{
				Summary: "Remove public management ingress and reduce the workload identity's storage role.",
				Steps: []string{
					"Delete the public NSG rule and use Azure Bastion or a private management path.",
					"Replace broad blob access with the minimum container-scoped role.",
					"Review storage diagnostics for access from the exposed VM.",
				},
			},
		},
		chainRule{
			id:          "CTA-AZ-003",
			findingID:   "finding-pipeline-owner-chain",
			title:       "Pipeline credential grants production Owner control",
			description: "A compromised delivery pipeline can assume a service principal with Owner rights over a production resource group.",
			severity:    model.SeverityCritical,
			score:       98,
			nodeTypes: []string{
				"devops.pipeline",
				"Microsoft.Entra/servicePrincipals",
				"Microsoft.Resources/resourceGroups",
				"Microsoft.OperationalInsights/workspaces",
			},
			edgeTypes: []string{"pipeline_credential", "owner_role", "controls"},
			evidence: []string{
				"The pipeline can authenticate as a long-lived service principal.",
				"The service principal has the Owner role at resource-group scope.",
				"The resource group contains a critical security analytics workspace.",
			},
			remediation: model.Remediation{
				Summary: "Replace the secret with workload federation and remove Owner-level access.",
				Steps: []string{
					"Revoke the long-lived service-principal secret.",
					"Configure workload identity federation for the pipeline.",
					"Replace Owner with a task-specific custom role at resource scope.",
				},
			},
		},
		azureExposureRule{},
		roleManagementRule{},
	}
}

func (r chainRule) ID() string { return r.id }

func (r chainRule) Evaluate(ctx context.Context, g model.Graph) ([]model.Finding, error) {
	maxWork := r.maxWork
	if maxWork <= 0 {
		maxWork = defaultChainRuleMaxWork
	}
	resourceIDs, relationshipIDs, found, err := matchChain(ctx, g, r.nodeTypes, r.edgeTypes, newEvaluationBudget(r.id, maxWork))
	if err != nil || !found {
		return nil, err
	}
	return []model.Finding{{
		ID:              r.findingID,
		RuleID:          r.id,
		Title:           r.title,
		Description:     r.description,
		Severity:        r.severity,
		Score:           r.score,
		ResourceIDs:     resourceIDs,
		RelationshipIDs: relationshipIDs,
		Evidence:        slices.Clone(r.evidence),
		Remediation:     r.remediation,
	}}, nil
}

func matchChain(ctx context.Context, g model.Graph, nodeTypes, edgeTypes []string, budget *evaluationBudget) ([]string, []string, bool, error) {
	if len(nodeTypes) == 0 || len(edgeTypes) != len(nodeTypes)-1 {
		return nil, nil, false, nil
	}
	resources := g.Resources()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	for _, resource := range resources {
		if err := budget.consume(ctx); err != nil {
			return nil, nil, false, err
		}
		if resource.Type != nodeTypes[0] {
			continue
		}
		visited := map[string]bool{resource.ID: true}
		nodes, edges, found, err := walkChain(ctx, g, resource.ID, 0, nodeTypes, edgeTypes, visited, budget)
		if err != nil {
			return nil, nil, false, err
		}
		if found {
			return append([]string{resource.ID}, nodes...), edges, true, nil
		}
	}
	return nil, nil, false, nil
}

func walkChain(ctx context.Context, g model.Graph, current string, index int, nodeTypes, edgeTypes []string, visited map[string]bool, budget *evaluationBudget) ([]string, []string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}
	if index == len(edgeTypes) {
		return nil, nil, true, nil
	}
	for _, edge := range g.Outgoing(current) {
		if err := budget.consume(ctx); err != nil {
			return nil, nil, false, err
		}
		if !edge.Exploitable || edge.Type != edgeTypes[index] || visited[edge.Target] {
			continue
		}
		node, ok := g.Node(edge.Target)
		if !ok || node.Type != nodeTypes[index+1] {
			continue
		}
		visited[node.ID] = true
		nodes, edges, found, err := walkChain(ctx, g, node.ID, index+1, nodeTypes, edgeTypes, visited, budget)
		delete(visited, node.ID)
		if err != nil {
			return nil, nil, false, err
		}
		if found {
			return append([]string{node.ID}, nodes...), append([]string{edge.ID}, edges...), true, nil
		}
	}
	return nil, nil, false, nil
}

var _ model.Rule = chainRule{}

// azureExposureRule joins the normalized public-exposure, managed-identity, and
// capability-aware RBAC relationships. It deliberately ignores generic role edges.
type azureExposureRule struct {
	limits azureExposureLimits
}

type azureExposureLimits struct {
	maxWork              int
	maxContainmentDepth  int
	maxCapabilityTargets int
	maxFindings          int
}

func (limits azureExposureLimits) normalized() azureExposureLimits {
	if limits.maxWork <= 0 {
		limits.maxWork = defaultAzureExposureMaxWork
	}
	if limits.maxContainmentDepth <= 0 {
		limits.maxContainmentDepth = defaultAzureExposureMaxDepth
	}
	if limits.maxCapabilityTargets <= 0 {
		limits.maxCapabilityTargets = defaultAzureExposureMaxTargets
	}
	if limits.maxFindings <= 0 {
		limits.maxFindings = defaultAzureExposureMaxFindings
	}
	return limits
}

func (azureExposureRule) ID() string { return "CTA-AZ-004" }

func (r azureExposureRule) Evaluate(ctx context.Context, g model.Graph) ([]model.Finding, error) {
	limits := r.limits.normalized()
	budget := newEvaluationBudget(r.ID(), limits.maxWork)
	resources := g.Resources()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	findings := make(map[string]model.Finding)
	addFinding := func(finding model.Finding) error {
		if _, exists := findings[finding.ID]; !exists && len(findings) >= limits.maxFindings {
			return evaluationLimitError(r.ID(), "findings", limits.maxFindings)
		}
		findings[finding.ID] = finding
		return nil
	}
	for _, entry := range resources {
		if err := budget.consume(ctx); err != nil {
			return nil, err
		}
		if entry.Type != "external.internet" {
			continue
		}
		for _, exposure := range g.Outgoing(entry.ID) {
			if err := budget.consume(ctx); err != nil {
				return nil, err
			}
			if !exposure.Exploitable || exposure.Type != "public_exposure" {
				continue
			}
			exposed, ok := g.Node(exposure.Target)
			if !ok {
				continue
			}
			if exposed.Criticality == model.SeverityCritical {
				finding := directPublicFinding(entry, exposed, exposure)
				if err := addFinding(finding); err != nil {
					return nil, err
				}
			}
			for _, identityEdge := range g.Outgoing(exposed.ID) {
				if err := budget.consume(ctx); err != nil {
					return nil, err
				}
				if !identityEdge.Exploitable || identityEdge.Type != "managed_identity" {
					continue
				}
				identity, ok := g.Node(identityEdge.Target)
				if !ok || !isManagedIdentity(identity) {
					continue
				}
				for _, capability := range g.Outgoing(identity.ID) {
					if err := budget.consume(ctx); err != nil {
						return nil, err
					}
					if !capability.Exploitable || !isResourceCapability(capability.Type) {
						continue
					}
					resolved, err := resolveCapabilityTargets(ctx, g, capability, limits, budget)
					if err != nil {
						return nil, err
					}
					for _, resolution := range resolved {
						target := resolution.target
						if target.Criticality != model.SeverityCritical && capability.Type != "secret_access" {
							continue
						}
						finding := identityCapabilityFinding(entry, exposed, identity, target, exposure, identityEdge, capability, resolution.containment)
						if err := addFinding(finding); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func directPublicFinding(entry, target model.ResourceNode, exposure model.RelationshipEdge) model.Finding {
	return model.Finding{
		ID:              "finding-direct-public-" + strings.TrimPrefix(exposure.ID, "rel-"),
		RuleID:          "CTA-AZ-004",
		Title:           target.Name + " is publicly reachable",
		Description:     "A critical Azure resource is exposed directly to the public internet according to Resource Graph metadata.",
		Severity:        model.SeverityCritical,
		Score:           92,
		ResourceIDs:     []string{entry.ID, target.ID},
		RelationshipIDs: []string{exposure.ID},
		Evidence:        []string{fmt.Sprintf("%s has a public-exposure relationship to %s.", entry.Name, target.Name)},
		EvidenceDetails: appendEvidence(nil, exposure.Evidence...),
		Remediation: model.Remediation{
			Summary: "Disable public network access and use a private endpoint or tightly controlled ingress.",
			Steps:   []string{"Confirm the service's intended network boundary.", "Disable public network access after a tested private path exists.", "Review diagnostic logs for unexpected public access."},
		},
	}
}

func identityCapabilityFinding(entry, exposed, identity, target model.ResourceNode, exposure, identityEdge, capability model.RelationshipEdge, containment []model.RelationshipEdge) model.Finding {
	title := fmt.Sprintf("Public workload identity can reach %s", target.Name)
	description := fmt.Sprintf("The publicly reachable %s can obtain tokens for %s, whose %s capability reaches %s.", exposed.Name, identity.Name, capability.Label, target.Name)
	severity := model.SeverityCritical
	score := 95
	remediation := "Remove the capability from the workload identity or scope it to the minimum required resource."
	if capability.Type == "secret_access" {
		severity = model.SeverityHigh
		score = 88
		remediation = "Remove direct secret-value access from the public workload identity and adopt a narrowly scoped secret flow."
	}
	relationshipIDs := []string{exposure.ID, identityEdge.ID, capability.ID}
	for _, edge := range containment {
		relationshipIDs = append(relationshipIDs, edge.ID)
	}
	idParts := []string{
		strings.TrimPrefix(exposure.ID, "rel-"),
		strings.TrimPrefix(identityEdge.ID, "rel-"),
		strings.TrimPrefix(capability.ID, "rel-"),
	}
	for _, edge := range containment {
		idParts = append(idParts, strings.TrimPrefix(edge.ID, "rel-"))
	}
	details := appendEvidence(nil, exposure.Evidence...)
	details = appendEvidence(details, identityEdge.Evidence...)
	details = appendEvidence(details, capability.Evidence...)
	for _, edge := range containment {
		details = appendEvidence(details, edge.Evidence...)
	}
	return model.Finding{
		ID:              "finding-public-identity-" + strings.Join(idParts, "-"),
		RuleID:          "CTA-AZ-004",
		Title:           title,
		Description:     description,
		Severity:        severity,
		Score:           score,
		ResourceIDs:     []string{entry.ID, exposed.ID, identity.ID, target.ID},
		RelationshipIDs: relationshipIDs,
		Evidence: []string{
			fmt.Sprintf("%s is publicly reachable.", exposed.Name),
			fmt.Sprintf("%s runs as %s.", exposed.Name, identity.Name),
			fmt.Sprintf("%s has %s on %s.", identity.Name, capability.Label, target.Name),
		},
		EvidenceDetails: details,
		Remediation:     model.Remediation{Summary: remediation, Steps: []string{"Restrict public ingress to the workload.", "Replace broad RBAC with a resource-specific least-privilege role.", "Review access logs for the affected identity and target."}},
	}
}

type capabilityResolution struct {
	target      model.ResourceNode
	containment []model.RelationshipEdge
}

func resolveCapabilityTargets(ctx context.Context, g model.Graph, capability model.RelationshipEdge, limits azureExposureLimits, budget *evaluationBudget) ([]capabilityResolution, error) {
	start, ok := g.Node(capability.Target)
	if !ok {
		return nil, nil
	}
	allowedTypes := make(map[string]struct{})
	for _, value := range strings.Split(capability.Properties["targetType"], ",") {
		if value = strings.TrimSpace(value); value != "" {
			allowedTypes[strings.ToLower(value)] = struct{}{}
		}
	}
	matches := func(node model.ResourceNode) bool {
		if node.Category == "scope" || node.Category == "identity" || node.Category == "entry_point" {
			return false
		}
		if len(allowedTypes) == 0 {
			return true
		}
		_, ok := allowedTypes[strings.ToLower(node.Type)]
		return ok
	}
	if matches(start) {
		return []capabilityResolution{{target: start}}, nil
	}
	type pending struct {
		id    string
		depth int
		path  []model.RelationshipEdge
	}
	queue := []pending{{id: start.ID}}
	visited := map[string]bool{start.ID: true}
	var result []capabilityResolution
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current := queue[0]
		queue = queue[1:]
		for _, edge := range g.Outgoing(current.id) {
			if err := budget.consume(ctx); err != nil {
				return nil, err
			}
			if edge.Type != "contains" || visited[edge.Target] {
				continue
			}
			node, exists := g.Node(edge.Target)
			if !exists {
				continue
			}
			depth := current.depth + 1
			if depth > limits.maxContainmentDepth {
				return nil, evaluationLimitError("CTA-AZ-004", "containment depth", limits.maxContainmentDepth)
			}
			visited[node.ID] = true
			path := append(slices.Clone(current.path), edge)
			if matches(node) {
				if len(result) >= limits.maxCapabilityTargets {
					return nil, evaluationLimitError("CTA-AZ-004", "capability targets", limits.maxCapabilityTargets)
				}
				result = append(result, capabilityResolution{target: node, containment: path})
			}
			if node.Category == "scope" {
				queue = append(queue, pending{id: node.ID, depth: depth, path: path})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].target.ID < result[j].target.ID })
	return result, nil
}

func appendEvidence(target []model.EvidenceRecord, evidence ...model.EvidenceRecord) []model.EvidenceRecord {
	seen := make(map[string]struct{}, len(target)+len(evidence))
	for _, item := range target {
		seen[item.Source+"\x00"+item.ResourceID+"\x00"+item.Field+"\x00"+item.Value] = struct{}{}
	}
	for _, item := range evidence {
		key := item.Source + "\x00" + item.ResourceID + "\x00" + item.Field + "\x00" + item.Value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		target = append(target, item)
	}
	return target
}

func isManagedIdentity(resource model.ResourceNode) bool {
	return resource.Type == "Microsoft.ManagedIdentity/systemAssignedIdentities" || resource.Type == "Microsoft.ManagedIdentity/userAssignedIdentities"
}

func isResourceCapability(edgeType string) bool {
	return edgeType == "control_plane_access" || edgeType == "data_access" || edgeType == "secret_access"
}

var _ model.Rule = azureExposureRule{}

type roleManagementRule struct {
	maxWork     int
	maxFindings int
}

func (roleManagementRule) ID() string { return "CTA-AZ-005" }

func (r roleManagementRule) Evaluate(ctx context.Context, g model.Graph) ([]model.Finding, error) {
	maxWork := r.maxWork
	if maxWork <= 0 {
		maxWork = defaultRoleManagementMaxWork
	}
	maxFindings := r.maxFindings
	if maxFindings <= 0 {
		maxFindings = defaultRoleManagementMaxFindings
	}
	budget := newEvaluationBudget(r.ID(), maxWork)
	var findings []model.Finding
	for _, edge := range g.Relationships() {
		if err := budget.consume(ctx); err != nil {
			return nil, err
		}
		if edge.Type != "role_management" || !edge.Exploitable {
			continue
		}
		principal, principalOK := g.Node(edge.Source)
		scope, scopeOK := g.Node(edge.Target)
		if !principalOK || !scopeOK {
			continue
		}
		if len(findings) >= maxFindings {
			return nil, evaluationLimitError(r.ID(), "findings", maxFindings)
		}
		findings = append(findings, model.Finding{
			ID:              "finding-role-management-" + strings.TrimPrefix(edge.ID, "rel-"),
			RuleID:          "CTA-AZ-005",
			Title:           principal.Name + " can manage Azure role assignments",
			Description:     "User Access Administrator can grant additional access at the assigned scope and should be tightly controlled.",
			Severity:        model.SeverityHigh,
			Score:           82,
			ResourceIDs:     []string{principal.ID, scope.ID},
			RelationshipIDs: []string{edge.ID},
			Evidence:        []string{fmt.Sprintf("%s has %s at %s.", principal.Name, edge.Label, scope.Name)},
			EvidenceDetails: appendEvidence(nil, edge.Evidence...),
			Remediation:     model.Remediation{Summary: "Remove standing role-management access or make it eligible and time-bound.", Steps: []string{"Confirm that the assignment is still required.", "Use privileged identity management for time-bound activation.", "Alert on role assignments created by this principal."}},
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings, nil
}

var _ model.Rule = roleManagementRule{}
