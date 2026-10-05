package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
)

func TestAPIEndpointsAndSimulation(t *testing.T) {
	api, err := server.New(context.Background(), demodata.ContosoHealth(), analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		key  string
	}{
		{"/healthz", "status"},
		{"/api/v1/snapshots/contoso-health-demo", "attackPaths"},
		{"/api/v1/findings?snapshot_id=contoso-health-demo", "findings"},
		{"/api/v1/attack-paths", "attackPaths"},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", test.path, response.Code, response.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body[test.key]; !ok {
			t.Fatalf("GET %s response missing %q", test.path, test.key)
		}
	}

	payload := `{"snapshotId":"contoso-health-demo","changes":[{"type":"remove-edge","targetId":"rel-identity-vault"}]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/simulations", strings.NewReader(payload))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("simulation = %d: %s", response.Code, response.Body.String())
	}
	var result model.SimulationResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.RemovedAttackPathIDs) != 1 || result.RemovedAttackPathIDs[0] != demodata.PathPublicApp {
		t.Fatalf("removed paths = %v", result.RemovedAttackPathIDs)
	}
}

func TestSPAFallback(t *testing.T) {
	webDir := t.TempDir()
	index := []byte("<!doctype html><title>CloudThreat Atlas</title>")
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), index, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "asset.js"), []byte("console.log('atlas')"), 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := server.New(context.Background(), demodata.ContosoHealth(), analysis.NewDefault(), webDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/attack-paths/demo", "/cloudthreat-atlas/", "/cloudthreat-atlas/attack-paths/demo"} {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), index) {
			t.Fatalf("SPA %s = %d %q", path, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/asset.js", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "atlas") {
		t.Fatalf("asset = %d %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/cloudthreat-atlas/asset.js", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "atlas") {
		t.Fatalf("Pages-prefixed asset = %d %q", response.Code, response.Body.String())
	}
}

func TestEmbeddedDashboardFallback(t *testing.T) {
	api, err := server.New(context.Background(), demodata.ContosoHealth(), analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}

	var index []byte
	for _, requestPath := range []string{"/", "/cloudthreat-atlas/", "/attack-paths/demo"} {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("embedded SPA %s = %d: %s", requestPath, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "CloudThreat Atlas") {
			t.Fatalf("embedded SPA %s did not return the dashboard", requestPath)
		}
		if requestPath == "/" {
			index = response.Body.Bytes()
		}
	}

	assetPattern := regexp.MustCompile(`src="([^"]+/assets/[^"]+\.js)"`)
	match := assetPattern.FindSubmatch(index)
	if len(match) != 2 {
		t.Fatalf("embedded index does not reference a JavaScript asset: %s", index)
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, string(match[1]), nil))
	if response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("embedded asset %s = %d (%d bytes)", match[1], response.Code, response.Body.Len())
	}

	for _, requestPath := range []string{"/assets/missing.js", "/assets/index.js.map"} {
		response = httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("embedded asset %s = %d, want 404", requestPath, response.Code)
		}
	}
}

func TestMissingDashboardOverrideIsRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := server.New(context.Background(), demodata.ContosoHealth(), analysis.NewDefault(), missing)
	if err == nil || !strings.Contains(err.Error(), "open dashboard override") {
		t.Fatalf("missing dashboard override error = %v", err)
	}
}

func TestRejectsUnknownSnapshotAndInvalidSimulation(t *testing.T) {
	api, err := server.New(context.Background(), demodata.ContosoHealth(), analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/snapshots/missing", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown snapshot = %d", response.Code)
	}
	response = httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/simulations", strings.NewReader(`{"changes":[]}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty simulation = %d", response.Code)
	}
}
