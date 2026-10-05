package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/collector"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/redaction"
	"github.com/meneeses/cloudthreat-atlas/internal/reporting"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
)

const usage = `CloudThreat Atlas maps cloud relationships into explainable attack paths.

Usage:
  atlas demo [--addr 127.0.0.1:8080] [--web-dir DIRECTORY]
  atlas analyze --input snapshot.json [--output analyzed.json]
  atlas scan azure --subscription SUBSCRIPTION_ID [--resource-group NAME] [--redact] [--output snapshot.local.json]
  atlas report [--input snapshot.json] --format json|html|markdown|sarif [--output report]
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "demo":
		err = runDemo(ctx, args[1:], stdout, stderr)
	case "analyze":
		err = runAnalyze(ctx, args[1:], stdout, stderr)
	case "scan":
		err = runScan(ctx, args[1:], stdout, stderr)
	case "report":
		err = runReport(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("addr", "127.0.0.1:8080", "local listen address")
	webDir := flags.String("web-dir", "", "optional compiled dashboard override directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("demo does not accept positional arguments")
	}
	api, err := server.New(ctx, demodata.ContosoHealth(), analysis.NewDefault(), *webDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "CloudThreat Atlas is running at http://%s\n", *addr)
	fmt.Fprintln(stdout, "Synthetic data only. Press Ctrl+C to stop.")
	return server.ListenAndServe(ctx, *addr, api.Handler())
}

func runAnalyze(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input snapshot JSON")
	output := flags.String("output", "", "output file (defaults to stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	snapshot, err := loadSnapshot(*input)
	if err != nil {
		return err
	}
	analyzed, err := analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	data, err := reporting.New().Render(analyzed, model.ReportJSON)
	if err != nil {
		return err
	}
	return writeResult(stdout, *output, data)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "azure" {
		return fmt.Errorf("usage: atlas scan azure --subscription SUBSCRIPTION_ID")
	}
	flags := flag.NewFlagSet("scan azure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	subscription := flags.String("subscription", "", "Azure subscription id")
	resourceGroup := flags.String("resource-group", "", "optional Azure resource group")
	redact := flags.Bool("redact", false, "replace tenant-specific names and identifiers before writing output")
	output := flags.String("output", "", "output JSON file (defaults to stdout; use *.local.json for raw scans)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*subscription) == "" {
		return fmt.Errorf("--subscription is required")
	}
	snapshot, err := (collector.AzureResourceGraph{}).Collect(ctx, model.Scope{SubscriptionID: *subscription, ResourceGroup: *resourceGroup})
	if err != nil {
		return err
	}
	snapshot, err = analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	if *redact {
		snapshot = redaction.Redact(snapshot)
	}
	data, err := reporting.New().Render(snapshot, model.ReportJSON)
	if err != nil {
		return err
	}
	return writeResult(stdout, *output, data)
}

func runReport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input snapshot JSON (defaults to the synthetic demo)")
	format := flags.String("format", "json", "json, html, markdown, or sarif")
	output := flags.String("output", "", "output file (defaults to stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var snapshot model.Snapshot
	var err error
	if *input == "" {
		snapshot = demodata.ContosoHealth()
	} else {
		snapshot, err = loadSnapshot(*input)
		if err != nil {
			return err
		}
	}
	snapshot, err = analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	reportFormat, err := parseFormat(*format)
	if err != nil {
		return err
	}
	data, err := reporting.New().Render(snapshot, reportFormat)
	if err != nil {
		return err
	}
	return writeResult(stdout, *output, data)
}

func loadSnapshot(path string) (model.Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("open snapshot: %w", err)
	}
	defer file.Close()
	var snapshot model.Snapshot
	decoder := json.NewDecoder(io.LimitReader(file, 32<<20))
	if err := decoder.Decode(&snapshot); err != nil {
		return model.Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return snapshot, nil
}

func parseFormat(value string) (model.ReportFormat, error) {
	switch strings.ToLower(value) {
	case "json":
		return model.ReportJSON, nil
	case "html":
		return model.ReportHTML, nil
	case "markdown", "md":
		return model.ReportMarkdown, nil
	case "sarif":
		return model.ReportSARIF, nil
	default:
		return "", fmt.Errorf("unsupported report format %q", value)
	}
}

func writeResult(stdout io.Writer, output string, data []byte) error {
	if output == "" || output == "-" {
		_, err := stdout.Write(data)
		return err
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
