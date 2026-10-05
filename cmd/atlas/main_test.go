package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpAndDefaultReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "atlas demo") {
		t.Fatal("help is missing demo command")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"report", "--format", "markdown"}, &stdout, &stderr); code != 0 {
		t.Fatalf("report exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Risk score") || !strings.Contains(stdout.String(), "Attack paths") {
		t.Fatal("markdown report is missing expected sections")
	}
}

func TestAnalyzeRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"analyze"}, &stdout, &stderr); code != 1 {
		t.Fatalf("analyze exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--input is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAzureScanRequiresSubscriptionBeforeAuthentication(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"scan", "azure"}, &stdout, &stderr); code != 1 {
		t.Fatalf("scan exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--subscription is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
