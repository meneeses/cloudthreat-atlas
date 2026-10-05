package rules

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

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
	resourceIDs, relationshipIDs, found, err := matchChain(ctx, g, r.nodeTypes, r.edgeTypes)
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

func matchChain(ctx context.Context, g model.Graph, nodeTypes, edgeTypes []string) ([]string, []string, bool, error) {
	if len(nodeTypes) == 0 || len(edgeTypes) != len(nodeTypes)-1 {
		return nil, nil, false, nil
	}
	resources := g.Resources()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	for _, resource := range resources {
		if resource.Type != nodeTypes[0] {
			continue
		}
		visited := map[string]bool{resource.ID: true}
		nodes, edges, found, err := walkChain(ctx, g, resource.ID, 0, nodeTypes, edgeTypes, visited)
		if err != nil {
			return nil, nil, false, err
		}
		if found {
			return append([]string{resource.ID}, nodes...), edges, true, nil
		}
	}
	return nil, nil, false, nil
}

func walkChain(ctx context.Context, g model.Graph, current string, index int, nodeTypes, edgeTypes []string, visited map[string]bool) ([]string, []string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}
	if index == len(edgeTypes) {
		return nil, nil, true, nil
	}
	for _, edge := range g.Outgoing(current) {
		if !edge.Exploitable || edge.Type != edgeTypes[index] || visited[edge.Target] {
			continue
		}
		node, ok := g.Node(edge.Target)
		if !ok || node.Type != nodeTypes[index+1] {
			continue
		}
		visited[node.ID] = true
		nodes, edges, found, err := walkChain(ctx, g, node.ID, index+1, nodeTypes, edgeTypes, visited)
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
type azureExposureRule struct{}

func (azureExposureRule) ID() string { return "CTA-AZ-004" }

func (azureExposureRule) Evaluate(ctx context.Context, g model.Graph) ([]model.Finding, error) {
	resources := g.Resources()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	findings := make(map[string]model.Finding)
	for _, entry := range resources {
		if entry.Type != "external.internet" {
			continue
		}
		for _, exposure := range g.Outgoing(entry.ID) {
			if err := ctx.Err(); err != nil {
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
				findings[finding.ID] = finding
			}
			for _, identityEdge := range g.Outgoing(exposed.ID) {
				if !identityEdge.Exploitable || identityEdge.Type != "managed_identity" {
					continue
				}
				identity, ok := g.Node(identityEdge.Target)
				if !ok || !isManagedIdentity(identity) {
					continue
				}
				for _, capability := range g.Outgoing(identity.ID) {
					if !capability.Exploitable || !isResourceCapability(capability.Type) {
						continue
					}
					target, ok := g.Node(capability.Target)
					if !ok || (target.Criticality != model.SeverityCritical && capability.Type != "secret_access") {
						continue
					}
					finding := identityCapabilityFinding(entry, exposed, identity, target, exposure, identityEdge, capability)
					findings[finding.ID] = finding
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
		Remediation: model.Remediation{
			Summary: "Disable public network access and use a private endpoint or tightly controlled ingress.",
			Steps:   []string{"Confirm the service's intended network boundary.", "Disable public network access after a tested private path exists.", "Review diagnostic logs for unexpected public access."},
		},
	}
}

func identityCapabilityFinding(entry, exposed, identity, target model.ResourceNode, exposure, identityEdge, capability model.RelationshipEdge) model.Finding {
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
	return model.Finding{
		ID: "finding-public-identity-" + strings.Join([]string{
			strings.TrimPrefix(exposure.ID, "rel-"),
			strings.TrimPrefix(identityEdge.ID, "rel-"),
			strings.TrimPrefix(capability.ID, "rel-"),
		}, "-"),
		RuleID:          "CTA-AZ-004",
		Title:           title,
		Description:     description,
		Severity:        severity,
		Score:           score,
		ResourceIDs:     []string{entry.ID, exposed.ID, identity.ID, target.ID},
		RelationshipIDs: []string{exposure.ID, identityEdge.ID, capability.ID},
		Evidence: []string{
			fmt.Sprintf("%s is publicly reachable.", exposed.Name),
			fmt.Sprintf("%s runs as %s.", exposed.Name, identity.Name),
			fmt.Sprintf("%s has %s on %s.", identity.Name, capability.Label, target.Name),
		},
		Remediation: model.Remediation{Summary: remediation, Steps: []string{"Restrict public ingress to the workload.", "Replace broad RBAC with a resource-specific least-privilege role.", "Review access logs for the affected identity and target."}},
	}
}

func isManagedIdentity(resource model.ResourceNode) bool {
	return resource.Type == "Microsoft.ManagedIdentity/systemAssignedIdentities" || resource.Type == "Microsoft.ManagedIdentity/userAssignedIdentities"
}

func isResourceCapability(edgeType string) bool {
	return edgeType == "control_plane_access" || edgeType == "data_access" || edgeType == "secret_access"
}

var _ model.Rule = azureExposureRule{}

type roleManagementRule struct{}

func (roleManagementRule) ID() string { return "CTA-AZ-005" }

func (roleManagementRule) Evaluate(ctx context.Context, g model.Graph) ([]model.Finding, error) {
	var findings []model.Finding
	for _, edge := range g.Relationships() {
		if err := ctx.Err(); err != nil {
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
			Remediation:     model.Remediation{Summary: "Remove standing role-management access or make it eligible and time-bound.", Steps: []string{"Confirm that the assignment is still required.", "Use privileged identity management for time-bound activation.", "Alert on role assignments created by this principal."}},
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings, nil
}

var _ model.Rule = roleManagementRule{}
