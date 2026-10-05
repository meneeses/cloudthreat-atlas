package demodata

import (
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const (
	PathPublicApp = "path-internet-public-app-clinical-api-identity-clinical-api-vault-clinical-prod-database-clinical-prod-39e3349351c7"
	PathPublicVM  = "path-internet-public-nsg-jumpbox-public-vm-ops-jumpbox-identity-ops-jumpbox-storage-patient-archive-9e23be8e7e47"
	PathPipeline  = "path-pipeline-ci-security-sp-deploy-prod-rg-production-workspace-security-prod-a3922827901b"
)

// ContosoHealth returns a synthetic topology containing no real tenant identifiers or secrets.
func ContosoHealth() model.Snapshot {
	return model.Snapshot{
		SchemaVersion: "1.0",
		ID:            "contoso-health-demo",
		Name:          "Contoso Health",
		Provider:      "azure",
		GeneratedAt:   time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC),
		Description:   "Synthetic healthcare environment designed to demonstrate explainable Azure attack paths.",
		Resources: []model.ResourceNode{
			{ID: "internet-public", Name: "Public Internet", Type: "external.internet", Category: "entry_point", Provider: "external", Criticality: model.SeverityInfo, Properties: map[string]string{"trust": "untrusted"}},
			{ID: "app-clinical-api", Name: "Clinical API", Type: "Microsoft.Web/sites", Category: "compute", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"httpsOnly": "true", "publicNetworkAccess": "enabled"}},
			{ID: "identity-clinical-api", Name: "Clinical API Identity", Type: "Microsoft.ManagedIdentity/userAssignedIdentities", Category: "identity", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"credentialType": "managed_identity"}},
			{ID: "vault-clinical-prod", Name: "Clinical Secrets Vault", Type: "Microsoft.KeyVault/vaults", Category: "secrets", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"publicNetworkAccess": "disabled", "rbacAuthorization": "true"}},
			{ID: "database-clinical-prod", Name: "Clinical Records PostgreSQL", Type: "Microsoft.DBforPostgreSQL/flexibleServers", Category: "data", Provider: "azure", Location: "westeurope", Criticality: model.SeverityCritical, Properties: map[string]string{"dataClassification": "restricted", "publicNetworkAccess": "disabled"}},
			{ID: "nsg-jumpbox-public", Name: "Jumpbox NSG", Type: "Microsoft.Network/networkSecurityGroups", Category: "network", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"source": "0.0.0.0/0", "destinationPort": "22"}},
			{ID: "vm-ops-jumpbox", Name: "Operations Jumpbox", Type: "Microsoft.Compute/virtualMachines", Category: "compute", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"publicIp": "synthetic", "patchState": "outdated"}},
			{ID: "identity-ops-jumpbox", Name: "Jumpbox Operations Identity", Type: "Microsoft.ManagedIdentity/userAssignedIdentities", Category: "identity", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"role": "Storage Blob Data Contributor"}},
			{ID: "storage-patient-archive", Name: "Patient Archive", Type: "Microsoft.Storage/storageAccounts", Category: "data", Provider: "azure", Location: "westeurope", Criticality: model.SeverityCritical, Properties: map[string]string{"dataClassification": "restricted", "allowBlobPublicAccess": "false"}},
			{ID: "pipeline-ci-security", Name: "Security Platform Pipeline", Type: "devops.pipeline", Category: "entry_point", Provider: "github", Criticality: model.SeverityHigh, Properties: map[string]string{"credential": "long_lived_secret", "environment": "production"}},
			{ID: "sp-deploy-prod", Name: "Production Deployment Principal", Type: "Microsoft.Entra/servicePrincipals", Category: "identity", Provider: "azure", Criticality: model.SeverityHigh, Properties: map[string]string{"authentication": "client_secret"}},
			{ID: "rg-production", Name: "Production Resource Group", Type: "Microsoft.Resources/resourceGroups", Category: "scope", Provider: "azure", Location: "westeurope", Criticality: model.SeverityHigh, Properties: map[string]string{"roleAssignment": "Owner"}},
			{ID: "workspace-security-prod", Name: "Production Security Analytics", Type: "Microsoft.OperationalInsights/workspaces", Category: "security", Provider: "azure", Location: "westeurope", Criticality: model.SeverityCritical, Properties: map[string]string{"retentionDays": "90", "containsSecurityTelemetry": "true"}},
		},
		Relationships: []model.RelationshipEdge{
			{ID: "rel-internet-app", Source: "internet-public", Target: "app-clinical-api", Type: "public_http", Label: "public HTTPS", Description: "The public internet can send requests to the Clinical API.", Exploitable: true},
			{ID: "rel-app-identity", Source: "app-clinical-api", Target: "identity-clinical-api", Type: "managed_identity", Label: "runs as", Description: "Code execution in the app can request tokens for its managed identity.", Exploitable: true},
			{ID: "rel-identity-vault", Source: "identity-clinical-api", Target: "vault-clinical-prod", Type: "secret_access", Label: "can read secrets", Description: "The managed identity can read secrets from the production vault.", Exploitable: true},
			{ID: "rel-vault-database", Source: "vault-clinical-prod", Target: "database-clinical-prod", Type: "credential_pivot", Label: "unlocks database", Description: "A stored credential grants access to the clinical PostgreSQL server.", Exploitable: true},
			{ID: "rel-internet-nsg", Source: "internet-public", Target: "nsg-jumpbox-public", Type: "public_ingress", Label: "0.0.0.0/0 to SSH", Description: "The NSG permits SSH traffic from every internet address.", Exploitable: true},
			{ID: "rel-nsg-vm", Source: "nsg-jumpbox-public", Target: "vm-ops-jumpbox", Type: "network_access", Label: "exposes", Description: "The permissive rule exposes the operations jumpbox.", Exploitable: true},
			{ID: "rel-vm-identity", Source: "vm-ops-jumpbox", Target: "identity-ops-jumpbox", Type: "privileged_identity", Label: "runs as", Description: "A process on the VM can request tokens for the operations identity.", Exploitable: true},
			{ID: "rel-identity-storage", Source: "identity-ops-jumpbox", Target: "storage-patient-archive", Type: "data_access", Label: "can read and write blobs", Description: "The identity can access restricted patient archive containers.", Exploitable: true},
			{ID: "rel-pipeline-sp", Source: "pipeline-ci-security", Target: "sp-deploy-prod", Type: "pipeline_credential", Label: "authenticates as", Description: "The pipeline stores a long-lived credential for the deployment principal.", Exploitable: true},
			{ID: "rel-sp-owner", Source: "sp-deploy-prod", Target: "rg-production", Type: "owner_role", Label: "Owner", Description: "The service principal has Owner rights over the production resource group.", Exploitable: true},
			{ID: "rel-rg-workspace", Source: "rg-production", Target: "workspace-security-prod", Type: "controls", Label: "contains", Description: "Owner rights permit changes to the critical security analytics workspace.", Exploitable: true},
		},
		Simulations: []model.SimulationPreset{
			{ID: "sim-scope-vault-access", Name: "Remove direct Key Vault secret access", Description: "Tests the effect of removing the Clinical API identity's direct secret permission.", Changes: []model.SimulationChange{{ID: "change-remove-vault-access", Type: "remove-edge", TargetID: "rel-identity-vault", Description: "Remove the identity-to-vault secret access edge."}}, RiskScoreAfter: 80, RemovedAttackPaths: []string{PathPublicApp}},
			{ID: "sim-close-public-ssh", Name: "Close public SSH ingress", Description: "Tests the effect of moving jumpbox administration to a private path.", Changes: []model.SimulationChange{{ID: "change-remove-public-vm-access", Type: "remove-edge", TargetID: "rel-nsg-vm", Description: "Remove the public NSG-to-VM access edge."}}, RiskScoreAfter: 81, RemovedAttackPaths: []string{PathPublicVM}},
			{ID: "sim-remove-owner", Name: "Replace production Owner role", Description: "Tests the effect of replacing broad Owner access with least privilege.", Changes: []model.SimulationChange{{ID: "change-remove-owner-role", Type: "remove-edge", TargetID: "rel-sp-owner", Description: "Remove the service-principal Owner assignment."}}, RiskScoreAfter: 80, RemovedAttackPaths: []string{PathPipeline}},
		},
	}
}
