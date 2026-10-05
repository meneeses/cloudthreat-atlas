package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestDecodeSnapshotJSONRecomputesDerivedResults(t *testing.T) {
	data, err := os.ReadFile("../../demo/contoso-health.json")
	if err != nil {
		t.Fatal(err)
	}
	var committed model.Snapshot
	if err := json.Unmarshal(data, &committed); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSnapshotJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Findings != nil || decoded.AttackPaths != nil || decoded.Analysis != nil {
		t.Fatal("untrusted derived results were materialized")
	}
	actual, err := NewDefault().Analyze(context.Background(), decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, committed) {
		t.Fatal("bounded decode followed by analysis changed the committed fixture")
	}
}

func TestDecodeSnapshotJSONRejectsResourceCardinalityDuringMaterialization(t *testing.T) {
	payload := "{\"resources\":[" + strings.Repeat(`{},`, defaultSnapshotComplexityLimits.maxResources) + `{}` + `]}`
	_, err := DecodeSnapshotJSON([]byte(payload))
	if !errors.Is(err, ErrSnapshotComplexityExceeded) {
		t.Fatalf("error = %v, want ErrSnapshotComplexityExceeded", err)
	}
}

func TestDecodeSnapshotJSONRejectsOversizedNestedCollections(t *testing.T) {
	properties := make(map[string]string, maxPropertiesPerRecord+1)
	for i := 0; i <= maxPropertiesPerRecord; i++ {
		properties[fmt.Sprintf("property-%03d", i)] = "value"
	}
	tests := []struct {
		name     string
		snapshot model.Snapshot
	}{
		{
			name: "properties",
			snapshot: model.Snapshot{Resources: []model.ResourceNode{{
				ID: "resource", Properties: properties,
			}}},
		},
		{
			name: "simulation changes",
			snapshot: model.Snapshot{Simulations: []model.SimulationPreset{{
				ID: "simulation", Changes: make([]model.SimulationChange, maxChangesPerPreset+1),
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeSnapshotJSON(data)
			if !errors.Is(err, ErrSnapshotComplexityExceeded) {
				t.Fatalf("error = %v, want ErrSnapshotComplexityExceeded", err)
			}
		})
	}
}

func TestDecodeSnapshotJSONSharesPropertyBudgetAcrossCollections(t *testing.T) {
	limits := defaultSnapshotComplexityLimits
	limits.maxPropertyEntries = 2
	snapshot := model.Snapshot{
		Resources: []model.ResourceNode{{Properties: map[string]string{"resource-a": "1"}}},
		Relationships: []model.RelationshipEdge{{
			Properties: map[string]string{"relationship-a": "1"},
		}},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSnapshotJSON(data, limits); err != nil {
		t.Fatalf("combined properties at limit were rejected: %v", err)
	}

	snapshot.Relationships[0].Properties["relationship-b"] = "2"
	data, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []byte(`{"relationships":[{"properties":{"relationship-a":"1","relationship-b":"2"}}],"resources":[{"properties":{"resource-a":"1"}}]}`)
	for _, payload := range [][]byte{data, reversed} {
		if _, err := decodeSnapshotJSON(payload, limits); !errors.Is(err, ErrSnapshotComplexityExceeded) {
			t.Fatalf("combined properties error = %v, want ErrSnapshotComplexityExceeded", err)
		}
	}
}

func TestDecodeSnapshotJSONRejectsDuplicateCollectionFields(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "resources", payload: `{"resources":[],"Resources":[]}`},
		{name: "relationships", payload: `{"relationships":[],"relationships":[]}`},
		{name: "findings", payload: `{"findings":[],"findings":[]}`},
		{name: "attack paths", payload: `{"attackPaths":[],"attackpaths":[]}`},
		{name: "simulations", payload: `{"simulations":[],"simulations":[]}`},
		{name: "analysis", payload: `{"analysis":{},"analysis":{}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeSnapshotJSON([]byte(test.payload)); !errors.Is(err, ErrSnapshotComplexityExceeded) {
				t.Fatalf("duplicate collection error = %v, want ErrSnapshotComplexityExceeded", err)
			}
		})
	}
}

func TestDecodeSnapshotJSONRejectsNestedDuplicateCollections(t *testing.T) {
	limits := defaultSnapshotComplexityLimits
	limits.maxPropertyEntries = 1
	limits.maxEvidenceRecords = 1
	limits.maxSimulationChanges = 1
	limits.maxRemovedAttackPathRefs = 1
	tests := []struct {
		name    string
		payload string
	}{
		{name: "duplicate property name", payload: `{"resources":[{"properties":{"x":"1","x":"2"}}]}`},
		{name: "resource properties", payload: `{"resources":[{"properties":{"a":"1"},"Properties":{"b":"2"}}]}`},
		{name: "relationship properties", payload: `{"relationships":[{"properties":{"a":"1"},"Properties":{"b":"2"}}]}`},
		{name: "relationship evidence", payload: `{"relationships":[{"evidence":[{}],"Evidence":[{}]}]}`},
		{name: "simulation changes", payload: `{"simulations":[{"changes":[{}],"Changes":[{}]}]}`},
		{name: "simulation removed paths", payload: `{"simulations":[{"removedAttackPaths":["a"],"RemovedAttackPaths":["b"]}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeSnapshotJSON([]byte(test.payload), limits); !errors.Is(err, ErrSnapshotComplexityExceeded) {
				t.Fatalf("nested duplicate error = %v, want ErrSnapshotComplexityExceeded", err)
			}
		})
	}
}

func TestDecodeSnapshotJSONPreservesCaseInsensitiveFieldMatching(t *testing.T) {
	payload := []byte(`{
		"ID":"snapshot",
		"Resources":[{"ID":"resource","Properties":{"key":"value"}}],
		"Relationships":[{"ID":"relationship","Source":"resource","Target":"resource","Evidence":[{}]}],
		"Simulations":[{"ID":"simulation","Changes":[{}],"RemovedAttackPaths":["path"]}]
	}`)
	snapshot, err := DecodeSnapshotJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ID != "snapshot" || len(snapshot.Resources) != 1 || snapshot.Resources[0].Properties["key"] != "value" {
		t.Fatalf("case-insensitive resource fields changed: %#v", snapshot)
	}
	if len(snapshot.Relationships) != 1 || len(snapshot.Relationships[0].Evidence) != 1 {
		t.Fatalf("case-insensitive relationship fields changed: %#v", snapshot.Relationships)
	}
	if len(snapshot.Simulations) != 1 || len(snapshot.Simulations[0].Changes) != 1 || len(snapshot.Simulations[0].RemovedAttackPaths) != 1 {
		t.Fatalf("case-insensitive simulation fields changed: %#v", snapshot.Simulations)
	}
}

func TestDecodeSnapshotJSONDiscardsLargeDerivedArrays(t *testing.T) {
	payload := "{\"id\":\"snapshot\",\"findings\":[" + strings.Repeat(`{},`, 200_000) + `{}],"attackPaths":[` + strings.Repeat(`{},`, 200_000) + `{}]}`
	snapshot, err := DecodeSnapshotJSON([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Findings != nil || snapshot.AttackPaths != nil {
		t.Fatal("derived arrays should be discarded before materialization")
	}
}

func TestDecodeSnapshotJSONStillValidatesDiscardedJSON(t *testing.T) {
	if _, err := DecodeSnapshotJSON([]byte(`{"findings":[invalid]}`)); err == nil {
		t.Fatal("invalid JSON inside a discarded derived field was accepted")
	}
}
