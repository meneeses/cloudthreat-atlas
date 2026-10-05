package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Renderer produces portable, local-only reports in every supported format.
type Renderer struct{}

// New creates a report renderer.
func New() *Renderer { return &Renderer{} }

// Render implements model.Reporter.
func (r *Renderer) Render(snapshot model.Snapshot, format model.ReportFormat) ([]byte, error) {
	switch format {
	case model.ReportJSON:
		data, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	case model.ReportMarkdown:
		return renderMarkdown(snapshot), nil
	case model.ReportHTML:
		return renderHTML(snapshot)
	case model.ReportSARIF:
		return renderSARIF(snapshot)
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func renderMarkdown(snapshot model.Snapshot) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "# CloudThreat Atlas report: %s\n\n", snapshot.Name)
	fmt.Fprintf(&out, "- Snapshot: `%s`\n- Provider: `%s`\n- Risk score: **%d/100**\n- Findings: **%d**\n- Attack paths: **%d**\n\n", snapshot.ID, snapshot.Provider, snapshot.RiskScore, len(snapshot.Findings), len(snapshot.AttackPaths))
	out.WriteString("## Findings\n\n")
	for _, finding := range snapshot.Findings {
		fmt.Fprintf(&out, "### %s — %s\n\n%s\n\n", strings.ToUpper(string(finding.Severity)), finding.Title, finding.Description)
		fmt.Fprintf(&out, "**Evidence**\n\n")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(&out, "- %s\n", evidence)
		}
		fmt.Fprintf(&out, "\n**Remediation:** %s\n\n", finding.Remediation.Summary)
	}
	out.WriteString("## Attack paths\n\n")
	for _, path := range snapshot.AttackPaths {
		fmt.Fprintf(&out, "### %s\n\n%s\n\n", path.Title, path.Description)
		for _, step := range path.Steps {
			fmt.Fprintf(&out, "%d. %s\n", step.Order, step.Narrative)
		}
		out.WriteString("\n")
	}
	return []byte(out.String())
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CloudThreat Atlas — {{.Name}}</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, system-ui, sans-serif; background:#071018; color:#dce8f2 }
    body { max-width: 1040px; margin: 0 auto; padding: 40px 24px 80px }
    header,.card { border:1px solid #203446; border-radius:16px; background:#0b1722; padding:24px; margin:16px 0 }
    h1,h2,h3 { color:#f4fbff } .score { color:#ff667e; font-size:48px; font-weight:800 }
    .critical { color:#ff667e; font-weight:700; text-transform:uppercase } li { margin:8px 0 }
    code { color:#65d8ff } small { color:#91a9bb }
  </style>
</head>
<body>
  <header><small>CLOUDTHREAT ATLAS / DEFENSIVE REPORT</small><h1>{{.Name}}</h1><div class="score">{{.RiskScore}}/100</div><p>{{.Description}}</p></header>
  <h2>Findings</h2>
  {{range .Findings}}<section class="card"><div class="critical">{{.Severity}} · {{.Score}}</div><h3>{{.Title}}</h3><p>{{.Description}}</p><ul>{{range .Evidence}}<li>{{.}}</li>{{end}}</ul><strong>Remediation</strong><p>{{.Remediation.Summary}}</p></section>{{end}}
  <h2>Attack paths</h2>
  {{range .AttackPaths}}<section class="card"><div class="critical">{{.Severity}} · {{.Score}}</div><h3>{{.Title}}</h3><p>{{.Description}}</p><ol>{{range .Steps}}<li>{{.Narrative}}</li>{{end}}</ol></section>{{end}}
</body>
</html>`))

func renderHTML(snapshot model.Snapshot) ([]byte, error) {
	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, snapshot); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func renderSARIF(snapshot model.Snapshot) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string  `json:"id"`
		Name             string  `json:"name"`
		ShortDescription message `json:"shortDescription"`
		Help             message `json:"help"`
	}
	type result struct {
		RuleID  string         `json:"ruleId"`
		Level   string         `json:"level"`
		Message message        `json:"message"`
		Props   map[string]any `json:"properties,omitempty"`
	}
	rules := make([]rule, 0, len(snapshot.Findings))
	results := make([]result, 0, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		rules = append(rules, rule{ID: finding.RuleID, Name: finding.Title, ShortDescription: message{Text: finding.Description}, Help: message{Text: finding.Remediation.Summary}})
		results = append(results, result{RuleID: finding.RuleID, Level: sarifLevel(finding.Severity), Message: message{Text: finding.Title}, Props: map[string]any{"severity": finding.Severity, "score": finding.Score, "resourceIds": finding.ResourceIDs}})
	}
	document := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "CloudThreat Atlas", "informationUri": "https://github.com/meneeses/cloudthreat-atlas", "rules": rules}},
			"results": results,
		}},
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

var _ model.Reporter = (*Renderer)(nil)
