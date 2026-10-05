package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/collector"
	"github.com/meneeses/cloudthreat-atlas/internal/comparison"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/redaction"
	"github.com/meneeses/cloudthreat-atlas/internal/remediation"
	"github.com/meneeses/cloudthreat-atlas/internal/reporting"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
	"github.com/pkg/browser"
)

const usage = `CloudThreat Atlas maps cloud relationships into explainable attack paths.

Usage:
  atlas app [--addr 127.0.0.1:8080] [--data-dir DIRECTORY] [--web-dir DIRECTORY] [--no-open]
  atlas import --input snapshot.json [--environment ID] [--data-dir DIRECTORY]
  atlas snapshots [list|show SNAPSHOT_ID] [--data-dir DIRECTORY]
  atlas compare BASE_SNAPSHOT_ID TARGET_SNAPSHOT_ID [--data-dir DIRECTORY]
  atlas doctor [--data-dir DIRECTORY]
  atlas bundle --snapshot SNAPSHOT_ID --output remediation.zip [--findings ID,ID] [--data-dir DIRECTORY]
  atlas demo [--addr 127.0.0.1:8080] [--web-dir DIRECTORY]
  atlas analyze --input snapshot.json [--output analyzed.json]
  atlas scan azure --subscription SUBSCRIPTION_ID [--resource-group NAME] [--redact] [--save] [--data-dir DIRECTORY] [--output snapshot.local.json]
  atlas report [--input snapshot.json] --format json|html|markdown|sarif [--output report]
`

const maxPortableSnapshotBytes = 64 << 20

var azureScanner model.Collector = collector.AzureResourceGraph{}

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
	case "app":
		err = runApp(ctx, args[1:], stdout, stderr)
	case "import":
		err = runImport(ctx, args[1:], stdout, stderr)
	case "snapshots":
		err = runSnapshots(ctx, args[1:], stdout, stderr)
	case "compare":
		err = runCompare(ctx, args[1:], stdout, stderr)
	case "doctor":
		err = runDoctor(ctx, args[1:], stdout, stderr)
	case "bundle":
		err = runBundle(ctx, args[1:], stdout, stderr)
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

func runApp(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("app", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("addr", "127.0.0.1:8080", "loopback listen address")
	dataDir := flags.String("data-dir", "", "private workspace directory")
	webDir := flags.String("web-dir", "", "optional compiled dashboard override directory")
	noOpen := flags.Bool("no-open", false, "do not open the local dashboard in a browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("app does not accept positional arguments")
	}
	if err := requireLoopbackAddress(*addr); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	store, err := workspace.Open(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	api, err := server.NewWorkspace(store, analysis.NewDefault(), *webDir)
	if err != nil {
		return err
	}
	launchURL, err := api.LaunchURL("http://" + *addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "CloudThreat Atlas workspace: %s\n", store.Dir())
	fmt.Fprintf(stdout, "CloudThreat Atlas is running at %s\n", launchURL)
	fmt.Fprintln(stdout, "Local requests only. Press Ctrl+C to stop.")
	openCtx, cancelOpen := context.WithCancel(ctx)
	defer cancelOpen()
	if !*noOpen {
		go func() {
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-openCtx.Done():
				return
			case <-timer.C:
				if err := browser.OpenURL(launchURL); err != nil {
					fmt.Fprintln(stderr, "warning: could not open browser:", err)
				}
			}
		}()
	}
	serveErr := server.ListenAndServe(ctx, *addr, api.Handler())
	closeErr := api.Close()
	return errors.Join(serveErr, closeErr)
}

func runImport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "schema 1.0 snapshot JSON")
	environmentID := flags.String("environment", "", "stable environment identifier")
	dataDir := flags.String("data-dir", "", "private workspace directory")
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
	snapshot, err = analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	store, err := workspace.Open(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	metadata, err := store.Import(ctx, snapshot, *environmentID)
	if err != nil {
		return err
	}
	return writeJSONResult(stdout, metadata)
}

func runSnapshots(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	dataDir, remaining, err := extractDataDir(args)
	if err != nil {
		return err
	}
	command := "list"
	if len(remaining) > 0 {
		command = remaining[0]
		remaining = remaining[1:]
	}
	store, err := workspace.Open(ctx, dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	switch command {
	case "list":
		if len(remaining) != 0 {
			return fmt.Errorf("snapshots list does not accept positional arguments")
		}
		catalog, err := store.Catalog(ctx)
		if err != nil {
			return err
		}
		return writeJSONResult(stdout, catalog)
	case "show":
		if len(remaining) != 1 {
			return fmt.Errorf("usage: atlas snapshots show SNAPSHOT_ID [--data-dir DIRECTORY]")
		}
		snapshot, err := store.Load(ctx, remaining[0])
		if err != nil {
			return err
		}
		return writeJSONResult(stdout, snapshot)
	default:
		return fmt.Errorf("unknown snapshots command %q", command)
	}
}

func runCompare(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	dataDir, remaining, err := extractDataDir(args)
	if err != nil {
		return err
	}
	if len(remaining) != 2 {
		return fmt.Errorf("usage: atlas compare BASE_SNAPSHOT_ID TARGET_SNAPSHOT_ID [--data-dir DIRECTORY]")
	}
	store, err := workspace.Open(ctx, dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	base, err := store.Load(ctx, remaining[0])
	if err != nil {
		return err
	}
	target, err := store.Load(ctx, remaining[1])
	if err != nil {
		return err
	}
	return writeJSONResult(stdout, comparison.Compare(base, target))
}

func extractDataDir(args []string) (string, []string, error) {
	var dataDir string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--data-dir":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--data-dir requires a value")
			}
			i++
			dataDir = args[i]
		case strings.HasPrefix(arg, "--data-dir="):
			dataDir = strings.TrimPrefix(arg, "--data-dir=")
		default:
			rest = append(rest, arg)
		}
	}
	return dataDir, rest, nil
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", "", "private workspace directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("doctor does not accept positional arguments")
	}
	store, err := workspace.Open(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	checks := store.Diagnose(ctx)
	if err := writeJSONResult(stdout, checks); err != nil {
		return err
	}
	for _, check := range checks {
		if !check.OK {
			return fmt.Errorf("workspace check %q failed: %s", check.Name, check.Message)
		}
	}
	return nil
}

func runBundle(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bundle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	snapshotID := flags.String("snapshot", "", "workspace snapshot identifier")
	output := flags.String("output", "", "output ZIP path")
	findings := flags.String("findings", "", "optional comma-separated finding identifiers")
	dataDir := flags.String("data-dir", "", "private workspace directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *snapshotID == "" || *output == "" || *output == "-" {
		return fmt.Errorf("--snapshot and a file --output are required")
	}
	store, err := workspace.Open(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	snapshot, err := store.Load(ctx, *snapshotID)
	if err != nil {
		return err
	}
	var findingIDs []string
	for _, id := range strings.Split(*findings, ",") {
		if id = strings.TrimSpace(id); id != "" {
			findingIDs = append(findingIDs, id)
		}
	}
	data, err := remediation.Bundle(snapshot, findingIDs)
	if err != nil {
		return err
	}
	if err := writeResult(stdout, *output, data); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote review-only remediation bundle to %s\n", *output)
	return nil
}

func requireLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--addr must use a loopback host")
	}
	return nil
}

func writeJSONResult(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
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
	if err := requireLoopbackAddress(*addr); err != nil {
		return err
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
	save := flags.Bool("save", false, "save the analyzed snapshot in the local workspace")
	dataDir := flags.String("data-dir", "", "private workspace directory used with --save")
	output := flags.String("output", "", "output JSON file (defaults to stdout; use *.local.json for raw scans)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*subscription) == "" {
		return fmt.Errorf("--subscription is required")
	}
	scanScope := model.Scope{SubscriptionID: *subscription, ResourceGroup: *resourceGroup}
	snapshot, err := azureScanner.Collect(ctx, scanScope)
	if err != nil {
		return err
	}
	// The requested scope is part of the portable snapshot contract. Record it
	// even for third-party collectors so export/import preserves environment
	// identity and keeps resource-group history separate from subscription scans.
	snapshot.Scope = &model.Scope{SubscriptionID: scanScope.SubscriptionID, ResourceGroup: scanScope.ResourceGroup}
	snapshot, err = analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	if *redact {
		snapshot = redaction.Redact(snapshot)
	}
	if *save {
		store, openErr := workspace.Open(ctx, *dataDir)
		if openErr != nil {
			return openErr
		}
		metadata, importErr := store.Import(ctx, snapshot, "")
		closeErr := store.Close()
		if importErr != nil {
			return importErr
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Fprintf(stderr, "saved workspace snapshot %s\n", metadata.ID)
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
	info, err := file.Stat()
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("inspect snapshot: %w", err)
	}
	if info.Size() > maxPortableSnapshotBytes {
		return model.Snapshot{}, fmt.Errorf("snapshot exceeds 64 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPortableSnapshotBytes+1))
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("read snapshot: %w", err)
	}
	if len(data) > maxPortableSnapshotBytes {
		return model.Snapshot{}, fmt.Errorf("snapshot exceeds 64 MiB limit")
	}
	snapshot, err := analysis.DecodeSnapshotJSON(data)
	if err != nil {
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
