package reporting_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/reporting"
)

func TestAllReportFormats(t *testing.T) {
	snapshot, err := analysis.NewDefault().Analyze(context.Background(), demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	renderer := reporting.New()
	formats := []model.ReportFormat{model.ReportJSON, model.ReportHTML, model.ReportMarkdown, model.ReportSARIF}
	for _, format := range formats {
		data, renderErr := renderer.Render(snapshot, format)
		if renderErr != nil {
			t.Fatalf("render %s: %v", format, renderErr)
		}
		if len(data) == 0 || !strings.Contains(string(data), "CloudThreat Atlas") && format != model.ReportJSON {
			t.Fatalf("%s report is empty or missing product name", format)
		}
		if format == model.ReportSARIF {
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("invalid SARIF JSON: %v", err)
			}
			if document["version"] != "2.1.0" {
				t.Fatalf("SARIF version = %v", document["version"])
			}
		}
	}
}
