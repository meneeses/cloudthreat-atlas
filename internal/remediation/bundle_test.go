package remediation_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/remediation"
)

func TestBundleContainsOnlyReviewExamples(t *testing.T) {
	snapshot, err := analysis.NewDefault().Analyze(context.Background(), demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Findings[0].ID = "finding-safe\naz account clear"
	snapshot.Findings[0].Title = "Review me\nresource \"unsafe\" \"injected\" {}"
	data, err := remediation.Bundle(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 4 {
		t.Fatalf("entries = %d", len(archive.File))
	}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(file.Name, ".sh") {
			for _, line := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "az ") {
					t.Fatalf("active CLI command: %q", line)
				}
			}
		}
		if strings.HasSuffix(file.Name, ".tf") {
			for _, line := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "resource ") {
					t.Fatalf("active Terraform resource: %q", line)
				}
			}
		}
	}
}
