// Package redaction creates deterministic, share-safe copies of local snapshots.
package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Redact returns a copy with tenant-specific names and identifiers replaced by
// deterministic aliases. The source snapshot is never mutated.
func Redact(source model.Snapshot) model.Snapshot {
	result := model.CloneSnapshot(source)
	replacements := make(map[string]string)
	resourceIDs := make(map[string]string, len(result.Resources))
	relationshipIDs := make(map[string]string, len(result.Relationships))
	pathIDs := make(map[string]string, len(result.AttackPaths))

	for i := range result.Resources {
		resource := &result.Resources[i]
		if resource.Provider == "external" {
			resourceIDs[resource.ID] = resource.ID
			continue
		}
		oldID, oldName := resource.ID, resource.Name
		alias := "resource-" + digest(oldID)
		resourceIDs[oldID] = alias
		replacements[oldID] = alias
		resource.ID = alias
		resource.Name = resourceLabel(resource.Category, alias)
		if oldName != "" {
			replacements[oldName] = resource.Name
		}
		resource.Properties = safeProperties(resource.Properties)
	}

	for i := range result.Relationships {
		relationship := &result.Relationships[i]
		for _, key := range []string{"roleAssignmentId", "roleDefinitionId"} {
			if value := relationship.Properties[key]; value != "" {
				replacements[value] = "redacted-" + strings.ToLower(key)
				fragment := identifierFragment(value)
				if len(fragment) >= 8 {
					replacements[fragment[:8]] = "redacted"
				}
			}
		}
		oldID := relationship.ID
		alias := "relationship-" + digest(oldID)
		relationshipIDs[oldID] = alias
		replacements[oldID] = alias
		relationship.ID = alias
		relationship.Source = mapped(resourceIDs, relationship.Source)
		relationship.Target = mapped(resourceIDs, relationship.Target)
		relationship.Properties = safeProperties(relationship.Properties)
	}

	for i := range result.Findings {
		finding := &result.Findings[i]
		finding.ResourceIDs = mapIDs(finding.ResourceIDs, resourceIDs)
		finding.RelationshipIDs = mapIDs(finding.RelationshipIDs, relationshipIDs)
	}

	for i := range result.AttackPaths {
		path := &result.AttackPaths[i]
		oldID := path.ID
		alias := "path-" + digest(oldID)
		pathIDs[oldID] = alias
		replacements[oldID] = alias
		path.ID = alias
		path.EntryPoint = mapped(resourceIDs, path.EntryPoint)
		path.Target = mapped(resourceIDs, path.Target)
		path.ResourceIDs = mapIDs(path.ResourceIDs, resourceIDs)
		path.RelationshipIDs = mapIDs(path.RelationshipIDs, relationshipIDs)
		for stepIndex := range path.Steps {
			step := &path.Steps[stepIndex]
			step.Source = mapped(resourceIDs, step.Source)
			step.Target = mapped(resourceIDs, step.Target)
			step.RelationshipID = mapped(relationshipIDs, step.RelationshipID)
		}
	}

	for i := range result.Simulations {
		simulation := &result.Simulations[i]
		for changeIndex := range simulation.Changes {
			change := &simulation.Changes[changeIndex]
			change.TargetID = mapped(resourceIDs, mapped(relationshipIDs, change.TargetID))
		}
		simulation.RemovedAttackPaths = mapIDs(simulation.RemovedAttackPaths, pathIDs)
	}

	replacer := newReplacer(replacements)
	redactText(&result, replacer)
	result.ID = "redacted-" + digest(source.ID)
	result.Name = "Redacted Azure environment"
	result.Description = "Tenant-specific names and identifiers were deterministically redacted for sharing."
	return result
}

func redactText(snapshot *model.Snapshot, replacer *strings.Replacer) {
	for i := range snapshot.Relationships {
		relationship := &snapshot.Relationships[i]
		relationship.Label = replacer.Replace(relationship.Label)
		relationship.Description = replacer.Replace(relationship.Description)
	}
	for i := range snapshot.Findings {
		finding := &snapshot.Findings[i]
		finding.Title = replacer.Replace(finding.Title)
		finding.Description = replacer.Replace(finding.Description)
		for evidenceIndex := range finding.Evidence {
			finding.Evidence[evidenceIndex] = replacer.Replace(finding.Evidence[evidenceIndex])
		}
		finding.Remediation.Summary = replacer.Replace(finding.Remediation.Summary)
		for stepIndex := range finding.Remediation.Steps {
			finding.Remediation.Steps[stepIndex] = replacer.Replace(finding.Remediation.Steps[stepIndex])
		}
	}
	for i := range snapshot.AttackPaths {
		path := &snapshot.AttackPaths[i]
		path.Title = replacer.Replace(path.Title)
		path.Description = replacer.Replace(path.Description)
		for stepIndex := range path.Steps {
			path.Steps[stepIndex].Narrative = replacer.Replace(path.Steps[stepIndex].Narrative)
		}
	}
	for i := range snapshot.Simulations {
		simulation := &snapshot.Simulations[i]
		simulation.Name = replacer.Replace(simulation.Name)
		simulation.Description = replacer.Replace(simulation.Description)
		for changeIndex := range simulation.Changes {
			simulation.Changes[changeIndex].Description = replacer.Replace(simulation.Changes[changeIndex].Description)
		}
	}
}

func safeProperties(properties map[string]string) map[string]string {
	if len(properties) == 0 {
		return nil
	}
	allowed := map[string]bool{
		"capability": true, "inferred": true, "kind": true,
		"principalType": true, "publicNetworkAccess": true, "roleName": true,
		"sku": true, "trust": true,
	}
	result := make(map[string]string)
	for key, value := range properties {
		if allowed[key] {
			result[key] = value
		}
	}
	if resourceGroup, ok := properties["resourceGroup"]; ok {
		result["resourceGroup"] = "resource-group-" + digest(resourceGroup)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func resourceLabel(category, alias string) string {
	category = strings.Trim(strings.ToLower(strings.ReplaceAll(category, "_", "-")), "-")
	if category == "" {
		category = "resource"
	}
	return category + " " + strings.TrimPrefix(alias, "resource-")
}

func identifierFragment(value string) string {
	value = strings.TrimSuffix(value, "/")
	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[index+1:]
	}
	return value
}

func newReplacer(replacements map[string]string) *strings.Replacer {
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		pairs = append(pairs, key, replacements[key])
	}
	return strings.NewReplacer(pairs...)
}

func mapIDs(values []string, aliases map[string]string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = mapped(aliases, value)
	}
	return result
}

func mapped(aliases map[string]string, value string) string {
	if alias, ok := aliases[value]; ok {
		return alias
	}
	return value
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
