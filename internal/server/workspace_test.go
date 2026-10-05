package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/analysis"
	"github.com/meneeses/cloudthreat-atlas/internal/demodata"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
	"github.com/meneeses/cloudthreat-atlas/internal/server"
	"github.com/meneeses/cloudthreat-atlas/internal/workspace"
)

func TestWorkspaceAPICatalogSlicesPaginationAndComparison(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := analysis.NewDefault()
	first, err := engine.Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	firstMetadata, err := store.Import(ctx, first, "prod")
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.ID = "contoso-health-later"
	second.GeneratedAt = second.GeneratedAt.Add(time.Hour)
	second.Resources = append(second.Resources, model.ResourceNode{ID: "new-resource", Name: "New", Type: "test", Category: "test"})
	secondMetadata, err := store.Import(ctx, second, "prod")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, engine, "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct{ path, key string }{
		{"/api/v1/bootstrap", "capabilities"},
		{"/api/v1/snapshots", "snapshots"},
		{fmt.Sprintf("/api/v1/snapshots/%s/summary", firstMetadata.ID), "resourceCount"},
		{fmt.Sprintf("/api/v1/snapshots/%s/graph?limit=2", firstMetadata.ID), "resources"},
		{fmt.Sprintf("/api/v1/findings?snapshot_id=%s&page=1&page_size=1", firstMetadata.ID), "total"},
		{fmt.Sprintf("/api/v1/attack-paths?snapshot_id=%s&page_size=1", firstMetadata.ID), "attackPaths"},
		{fmt.Sprintf("/api/v1/comparisons?base_snapshot_id=%s&target_snapshot_id=%s", firstMetadata.ID, secondMetadata.ID), "resourceDelta"},
	}
	for _, test := range tests {
		response := serveLocal(api, http.MethodGet, test.path, nil, "")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", test.path, response.Code, response.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body[test.key]; !ok {
			t.Fatalf("GET %s missing %s: %v", test.path, test.key, body)
		}
	}
}

func TestWorkspaceSessionProtectsAPIAndHealthWithoutHidingShell(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()

	launchURL, err := api.LaunchURL("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(launchURL)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	accessToken := fragment.Get("atlas-session")
	if len(accessToken) != 43 || parsed.RawQuery != "" || strings.Contains(launchURL, "?atlas-session") {
		t.Fatalf("launch URL exposed or omitted session fragment: %q", launchURL)
	}
	if _, err := api.LaunchURL("http://example.com"); err == nil {
		t.Fatal("launch URL accepted a non-loopback host")
	}

	if response := serveLocalWithSession(api, http.MethodGet, "/", nil, "", ""); response.Code != http.StatusOK {
		t.Fatalf("public shell = %d: %s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/healthz", "/api/v1/session", "/api/v1/snapshots"} {
		if response := serveLocalWithSession(api, http.MethodGet, path, nil, "", ""); response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated GET %s = %d: %s", path, response.Code, response.Body.String())
		}
		if response := serveLocalWithSession(api, http.MethodGet, path, nil, "invalid", ""); response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid-session GET %s = %d: %s", path, response.Code, response.Body.String())
		}
	}

	session := serveLocalWithSession(api, http.MethodGet, "/api/v1/session", nil, accessToken, "")
	if session.Code != http.StatusOK {
		t.Fatalf("authenticated session = %d: %s", session.Code, session.Body.String())
	}
	var sessionBody map[string]string
	if err := json.Unmarshal(session.Body.Bytes(), &sessionBody); err != nil {
		t.Fatal(err)
	}
	if sessionBody["csrfToken"] == "" || sessionBody["csrfToken"] == accessToken {
		t.Fatalf("workspace and CSRF credentials were not independent: %#v", sessionBody)
	}
	if response := serveLocalWithSession(api, http.MethodPost, "/api/v1/snapshots", strings.NewReader(`{}`), accessToken, ""); response.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF = %d: %s", response.Code, response.Body.String())
	}
}

func TestWorkspaceFindingsSupportsBoundedExactIDQueries(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	template := snapshot.Findings[0]
	for index := 0; index < 200; index++ {
		finding := template
		finding.ID = fmt.Sprintf("generated-finding-%03d", index)
		snapshot.Findings = append(snapshot.Findings, finding)
	}
	specialID := "finding/outside first page ? owner=platform & region=eu"
	special := template
	special.ID = specialID
	snapshot.Findings = append(snapshot.Findings, special)
	metadata, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}

	query := url.Values{"snapshot_id": {metadata.ID}, "finding_id": {specialID, template.ID}}
	response := serveLocal(api, http.MethodGet, "/api/v1/findings?"+query.Encode(), nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("exact findings = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Findings []model.Finding `json:"findings"`
		Total    int             `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || len(body.Findings) != 2 || body.Findings[0].ID != template.ID || body.Findings[1].ID != specialID {
		t.Fatalf("exact findings response = %#v", body)
	}

	overLimit := url.Values{"snapshot_id": {metadata.ID}}
	for index := 0; index < 201; index++ {
		overLimit.Add("finding_id", fmt.Sprintf("finding-%03d", index))
	}
	response = serveLocal(api, http.MethodGet, "/api/v1/findings?"+overLimit.Encode(), nil, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("over-limit exact findings = %d: %s", response.Code, response.Body.String())
	}
}

func TestWorkspaceReadEndpointsShareSnapshotConcurrently(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := analysis.NewDefault().Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()

	paths := []string{
		fmt.Sprintf("/api/v1/snapshots/%s", metadata.ID),
		fmt.Sprintf("/api/v1/snapshots/%s/graph?limit=5", metadata.ID),
		fmt.Sprintf("/api/v1/findings?snapshot_id=%s&page_size=5", metadata.ID),
		fmt.Sprintf("/api/v1/attack-paths?snapshot_id=%s&page_size=5", metadata.ID),
	}
	const requests = 48
	start := make(chan struct{})
	errorsFound := make(chan error, requests)
	var wait sync.WaitGroup
	for index := range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			path := paths[index%len(paths)]
			response := serveLocal(api, http.MethodGet, path, nil, "")
			if response.Code != http.StatusOK {
				errorsFound <- fmt.Errorf("GET %s = %d: %s", path, response.Code, response.Body.String())
				return
			}
			var body any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				errorsFound <- fmt.Errorf("decode GET %s: %w", path, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for requestErr := range errorsFound {
		t.Fatal(requestErr)
	}
}

func TestWorkspaceAPIMutationSecurityAndCompactSimulation(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := analysis.NewDefault()
	snapshot, err := engine.Analyze(ctx, demodata.ContosoHealth())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Import(ctx, snapshot, "prod")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, engine, "")
	if err != nil {
		t.Fatal(err)
	}

	payload := fmt.Sprintf(`{"snapshotId":%q,"compact":true,"changes":[{"type":"remove-edge","targetId":"rel-identity-vault"}]}`, metadata.ID)
	response := serveLocal(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload), "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing token = %d", response.Code)
	}
	token := sessionToken(t, api)
	response = serveLocal(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload), token)
	if response.Code != http.StatusOK {
		t.Fatalf("compact simulation = %d: %s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["resultingSnapshot"]; ok {
		t.Fatal("compact result unexpectedly includes snapshot")
	}
	if _, ok := body["riskScoreDelta"]; !ok {
		t.Fatalf("compact result missing delta: %v", body)
	}
	response = serveLocal(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload+` {}`), token)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON = %d: %s", response.Code, response.Body.String())
	}
	response = serveLocalWithOrigin(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload), "", "http://127.0.0.1:8080")
	if response.Code != http.StatusForbidden {
		t.Fatalf("same-origin mutation without token = %d: %s", response.Code, response.Body.String())
	}
	response = serveLocalWithOrigin(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload), token, "http://127.0.0.1:8080")
	if response.Code != http.StatusOK {
		t.Fatalf("same-origin mutation with token = %d: %s", response.Code, response.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "http://evil.example/api/v1/snapshots", nil)
	request.Host = "evil.example"
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted Host = %d", recorder.Code)
	}

	response = serveLocalWithOrigin(api, http.MethodPost, "/api/v1/simulations", strings.NewReader(payload), token, "http://evil.example")
	if response.Code != http.StatusForbidden {
		t.Fatalf("untrusted Origin = %d", response.Code)
	}

	response = serveLocal(api, http.MethodGet, "/api/v1/bootstrap", nil, "")
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %v", response.Header())
	}
}

func TestWorkspaceGraphSliceCapsDenseRelationships(t *testing.T) {
	ctx := context.Background()
	store, err := workspace.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := demodata.ContosoHealth()
	snapshot, err = analysis.NewDefault().Analyze(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	originalRelationships := snapshot.Relationships
	snapshot.Relationships = nil
	for index := 0; index < 2_100; index++ {
		snapshot.Relationships = append(snapshot.Relationships, model.RelationshipEdge{
			ID: fmt.Sprintf("dense-%04d", index), Source: snapshot.Resources[0].ID, Target: snapshot.Resources[1].ID,
			Type: "dependency", Label: "dense test edge", Exploitable: false,
		})
	}
	snapshot.Relationships = append(snapshot.Relationships, originalRelationships...)
	metadata, err := store.Import(ctx, snapshot, "dense")
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	response := serveLocal(api, http.MethodGet, fmt.Sprintf("/api/v1/snapshots/%s/graph?limit=500&relationship_limit=9999", metadata.ID), nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("graph slice = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Relationships      []model.RelationshipEdge `json:"relationships"`
		RelationshipLimit  int                      `json:"relationshipLimit"`
		TotalRelationships int                      `json:"totalRelationships"`
		Truncated          bool                     `json:"truncated"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Relationships) != 2_000 || body.RelationshipLimit != 2_000 || body.TotalRelationships <= 2_000 || !body.Truncated {
		t.Fatalf("dense graph response = relationships:%d limit:%d total:%d truncated:%v", len(body.Relationships), body.RelationshipLimit, body.TotalRelationships, body.Truncated)
	}
	priorityID := snapshot.AttackPaths[0].RelationshipIDs[0]
	foundPriority := false
	for _, relationship := range body.Relationships {
		if relationship.ID == priorityID {
			foundPriority = true
			break
		}
	}
	if !foundPriority {
		t.Fatalf("bounded graph omitted attack-path relationship %q", priorityID)
	}
}

func TestWorkspaceAPIImportsAnalyzedSnapshot(t *testing.T) {
	store, err := workspace.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	api, err := server.NewWorkspace(store, analysis.NewDefault(), "")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := demodata.ContosoHealth()
	snapshot.ID = "api-import"
	snapshot.GeneratedAt = snapshot.GeneratedAt.Add(2 * time.Hour)
	snapshot.Scope = &model.Scope{SubscriptionID: "11111111-2222-3333-4444-555555555555", ResourceGroup: "clinical-prod"}
	data, err := json.Marshal(map[string]any{"environmentId": "prod", "snapshot": snapshot})
	if err != nil {
		t.Fatal(err)
	}
	response := serveLocal(api, http.MethodPost, "/api/v1/snapshots", bytes.NewReader(data), sessionToken(t, api))
	if response.Code != http.StatusCreated {
		t.Fatalf("import = %d: %s", response.Code, response.Body.String())
	}
	var metadata workspace.SnapshotMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) == 0 || len(loaded.AttackPaths) == 0 {
		t.Fatal("API stored an unanalyzed snapshot")
	}
	if loaded.Scope == nil || loaded.Scope.ResourceGroup != "clinical-prod" {
		t.Fatalf("API dropped portable scope: %#v", loaded.Scope)
	}
}

func serveLocal(api http.Handler, method, path string, body io.Reader, token string) *httptest.ResponseRecorder {
	return serveLocalWithSession(api, method, path, body, workspaceAccessToken(api), token)
}

func serveLocalWithSession(api http.Handler, method, path string, body io.Reader, sessionToken, csrfToken string) *httptest.ResponseRecorder {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, "http://127.0.0.1:8080"+path, nil)
	} else {
		request = httptest.NewRequest(method, "http://127.0.0.1:8080"+path, body)
	}
	request.Host = "127.0.0.1:8080"
	request.RemoteAddr = "127.0.0.1:54321"
	if sessionToken != "" {
		request.Header.Set("X-Atlas-Session-Token", sessionToken)
	}
	if csrfToken != "" {
		request.Header.Set("X-Atlas-CSRF-Token", csrfToken)
	}
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	return recorder
}

func serveLocalWithOrigin(api http.Handler, method, path string, body io.Reader, token, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, body)
	request.Host = "127.0.0.1:8080"
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", origin)
	request.Header.Set("X-Atlas-Session-Token", workspaceAccessToken(api))
	request.Header.Set("X-Atlas-CSRF-Token", token)
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	return recorder
}

func workspaceAccessToken(api http.Handler) string {
	launcher, ok := api.(interface {
		LaunchURL(string) (string, error)
	})
	if !ok {
		return ""
	}
	launchURL, err := launcher.LaunchURL("http://127.0.0.1:8080")
	if err != nil {
		panic(err)
	}
	parsed, err := url.Parse(launchURL)
	if err != nil {
		panic(err)
	}
	params, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		panic(err)
	}
	return params.Get("atlas-session")
}

func sessionToken(t *testing.T, api http.Handler) string {
	t.Helper()
	response := serveLocal(api, http.MethodGet, "/api/v1/session", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("session = %d: %s", response.Code, response.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["csrfToken"] == "" {
		t.Fatal(fmt.Errorf("missing CSRF token"))
	}
	return body["csrfToken"]
}
