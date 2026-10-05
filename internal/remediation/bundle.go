// Package remediation creates review-only remediation bundles. It never invokes
// a cloud CLI, Terraform, or any other mutation mechanism.
package remediation

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Bundle creates a ZIP containing prose and fully commented examples. An empty
// findingIDs slice includes every finding in the snapshot.
func Bundle(snapshot model.Snapshot, findingIDs []string) ([]byte, error) {
	selected := selectFindings(snapshot.Findings, findingIDs)
	if len(findingIDs) > 0 && len(selected) != len(unique(findingIDs)) {
		return nil, fmt.Errorf("one or more requested findings do not exist in snapshot %q", snapshot.ID)
	}
	var output bytes.Buffer
	zw := zip.NewWriter(&output)
	files := []struct{ name, content string }{
		{"README.md", readme(snapshot, selected)},
		{"remediation-plan.md", plan(selected)},
		{"azure-cli.example.sh", cliExample(selected)},
		{"terraform.example.tf", terraformExample(selected)},
	}
	for _, file := range files {
		writer, err := zw.Create(file.name)
		if err != nil {
			return nil, fmt.Errorf("create bundle entry: %w", err)
		}
		if _, err := writer.Write([]byte(file.content)); err != nil {
			return nil, fmt.Errorf("write bundle entry: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finish remediation bundle: %w", err)
	}
	return output.Bytes(), nil
}

func selectFindings(findings []model.Finding, ids []string) []model.Finding {
	wanted := unique(ids)
	var selected []model.Finding
	for _, finding := range findings {
		if len(wanted) == 0 {
			selected = append(selected, finding)
		} else if _, ok := wanted[finding.ID]; ok {
			selected = append(selected, finding)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	return selected
}

func unique(ids []string) map[string]struct{} {
	result := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		result[id] = struct{}{}
	}
	return result
}

func readme(snapshot model.Snapshot, findings []model.Finding) string {
	return fmt.Sprintf("# CloudThreat Atlas remediation bundle\n\nSnapshot: `%s`\nSelected findings: %d\n\nThis bundle is review-only. Every CLI and Terraform line is commented out. CloudThreat Atlas does not execute, apply, or deploy remediation. Validate scope, ownership, and rollback with the resource owner before adapting any example.\n", snapshot.ID, len(findings))
}

func plan(findings []model.Finding) string {
	var out strings.Builder
	out.WriteString("# Remediation plan\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&out, "## %s (`%s`)\n\n%s\n\n", finding.Title, finding.ID, finding.Remediation.Summary)
		for _, step := range finding.Remediation.Steps {
			fmt.Fprintf(&out, "- %s\n", step)
		}
		out.WriteString("\n")
	}
	return out.String()
}

func cliExample(findings []model.Finding) string {
	var out strings.Builder
	out.WriteString("#!/usr/bin/env bash\n# REVIEW-ONLY EXAMPLE — every command is intentionally commented out.\n# Copy only a validated command into a separately approved change workflow.\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&out, "# Finding %s: %s\n# az <service> <operation> --resource-id '<replace-after-review>' --only-show-errors\n\n", commentValue(finding.ID), commentValue(finding.Title))
	}
	return out.String()
}

func terraformExample(findings []model.Finding) string {
	var out strings.Builder
	out.WriteString("# REVIEW-ONLY EXAMPLE — no active Terraform resources are defined.\n# Translate validated changes into the owning infrastructure repository.\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&out, "# Finding %s: %s\n# resource \"azurerm_REPLACE_AFTER_REVIEW\" \"remediation\" {\n#   # Import and review the existing resource before changing it.\n# }\n\n", commentValue(finding.ID), commentValue(finding.Title))
	}
	return out.String()
}

// commentValue keeps attacker-controlled snapshot text on one commented line.
// Imported snapshots are untrusted, and a newline must never turn generated
// review guidance into an active shell command or Terraform block.
func commentValue(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "(empty)"
	}
	return value
}
