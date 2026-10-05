// Package redaction creates deterministic, share-safe copies of local snapshots.
package redaction

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Redact returns a copy with tenant-specific names and identifiers replaced by
// deterministic aliases. The source snapshot is never mutated.
func Redact(source model.Snapshot) model.Snapshot {
	result := model.CloneSnapshot(source)
	aliasKey := redactionAliasKey(source)
	replacements := make(map[string]string)
	var insensitiveReplacements []textReplacement
	resourceIDs := make(map[string]string, len(result.Resources))
	relationshipIDs := make(map[string]string, len(result.Relationships))
	pathIDs := make(map[string]string, len(result.AttackPaths))
	if result.Scope != nil {
		redactedScope := model.Scope{}
		if result.Scope.SubscriptionID != "" {
			redactedScope.SubscriptionID = "subscription-" + digest(strings.ToLower(result.Scope.SubscriptionID))
			replacements[result.Scope.SubscriptionID] = redactedScope.SubscriptionID
			insensitiveReplacements = append(insensitiveReplacements, newTokenReplacement(result.Scope.SubscriptionID, redactedScope.SubscriptionID))
		}
		if result.Scope.ResourceGroup != "" {
			// Resource-group names are frequently low entropy (for example,
			// "prod" or "platform"). Key the deterministic alias with the
			// subscription so a public export cannot be attacked with a generic
			// offline dictionary of common names.
			redactedScope.ResourceGroup = "resource-group-" + keyedDigest(aliasKey, strings.ToLower(result.Scope.ResourceGroup))
			replacements[result.Scope.ResourceGroup] = redactedScope.ResourceGroup
			insensitiveReplacements = append(insensitiveReplacements, newTokenReplacement(result.Scope.ResourceGroup, redactedScope.ResourceGroup))
		}
		result.Scope = &redactedScope
	}

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
		resource.Properties = safeProperties(resource.Properties, aliasKey)
	}

	for i := range result.Relationships {
		relationship := &result.Relationships[i]
		if strings.EqualFold(relationship.Properties["customRole"], "true") && relationship.Label != "" {
			replacements[relationship.Label] = "Custom Azure role"
			relationship.Label = "Custom Azure role"
		}
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
		relationship.Properties = safeProperties(relationship.Properties, aliasKey)
		// Structured collector evidence may contain tenant resource IDs, object
		// IDs, role-assignment IDs, and organization-specific names. The redacted
		// export intentionally omits it instead of risking a partial scrub.
		relationship.Evidence = nil
	}

	for i := range result.Findings {
		finding := &result.Findings[i]
		finding.ResourceIDs = mapIDs(finding.ResourceIDs, resourceIDs)
		finding.RelationshipIDs = mapIDs(finding.RelationshipIDs, relationshipIDs)
		finding.EvidenceDetails = nil
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

	redactor := newTextRedactor(replacements, insensitiveReplacements)
	redactText(&result, redactor)
	result.ID = "redacted-" + digest(source.ID)
	result.Name = "Redacted Azure environment"
	result.Description = "Tenant-specific names and identifiers were deterministically redacted for sharing."
	return result
}

type textReplacement struct {
	pattern     *regexp.Regexp
	replacement string
}

func newTokenReplacement(value, alias string) textReplacement {
	// Azure scope values may be repeated in text with different casing. Match
	// only complete identifier tokens so a short resource-group name cannot
	// rewrite characters inside unrelated words.
	pattern := regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(value) + `([^A-Za-z0-9_-]|$)`)
	return textReplacement{pattern: pattern, replacement: "${1}" + alias + "${2}"}
}

func newTextRedactor(replacements map[string]string, insensitive []textReplacement) func(string) string {
	replacer := newReplacer(replacements)
	return func(value string) string {
		value = replacer.Replace(value)
		for _, replacement := range insensitive {
			value = replacement.pattern.ReplaceAllString(value, replacement.replacement)
		}
		return value
	}
}

func redactText(snapshot *model.Snapshot, redact func(string) string) {
	for i := range snapshot.Relationships {
		relationship := &snapshot.Relationships[i]
		relationship.Label = redact(relationship.Label)
		relationship.Description = redact(relationship.Description)
	}
	for i := range snapshot.Findings {
		finding := &snapshot.Findings[i]
		finding.Title = redact(finding.Title)
		finding.Description = redact(finding.Description)
		for evidenceIndex := range finding.Evidence {
			finding.Evidence[evidenceIndex] = redact(finding.Evidence[evidenceIndex])
		}
		finding.Remediation.Summary = redact(finding.Remediation.Summary)
		for stepIndex := range finding.Remediation.Steps {
			finding.Remediation.Steps[stepIndex] = redact(finding.Remediation.Steps[stepIndex])
		}
	}
	for i := range snapshot.AttackPaths {
		path := &snapshot.AttackPaths[i]
		path.Title = redact(path.Title)
		path.Description = redact(path.Description)
		for stepIndex := range path.Steps {
			path.Steps[stepIndex].Narrative = redact(path.Steps[stepIndex].Narrative)
		}
	}
	for i := range snapshot.Simulations {
		simulation := &snapshot.Simulations[i]
		simulation.Name = redact(simulation.Name)
		simulation.Description = redact(simulation.Description)
		for changeIndex := range simulation.Changes {
			simulation.Changes[changeIndex].Description = redact(simulation.Changes[changeIndex].Description)
		}
	}
}

func safeProperties(properties map[string]string, aliasKey []byte) map[string]string {
	if len(properties) == 0 {
		return nil
	}
	allowed := map[string]bool{
		"capability": true, "customRole": true, "inferred": true, "kind": true,
		"principalType": true, "publicNetworkAccess": true,
		"sku": true, "targetType": true, "trust": true,
	}
	result := make(map[string]string)
	for key, value := range properties {
		if allowed[key] {
			result[key] = value
		}
	}
	if resourceGroup, ok := properties["resourceGroup"]; ok {
		result["resourceGroup"] = "resource-group-" + keyedDigest(aliasKey, strings.ToLower(resourceGroup))
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

func redactionAliasKey(source model.Snapshot) []byte {
	seed := source.ID
	if source.Scope != nil && strings.TrimSpace(source.Scope.SubscriptionID) != "" {
		seed = strings.ToLower(strings.TrimSpace(source.Scope.SubscriptionID))
	}
	sum := sha256.Sum256([]byte("cloudthreat-atlas/redaction-alias/v1\x00" + seed))
	return sum[:]
}

func keyedDigest(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}
