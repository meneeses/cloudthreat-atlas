package analysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const (
	maxPropertiesPerRecord   = 256
	maxEvidencePerEdge       = 256
	maxChangesPerPreset      = 100
	maxRemovedPathsPerPreset = 500
)

// DecodeSnapshotJSON decodes an untrusted portable snapshot with collection
// limits applied while arrays and maps are materialized. Derived findings,
// attack paths, and analysis metadata are intentionally discarded because the
// engine recomputes them from resources and relationships.
func DecodeSnapshotJSON(data []byte) (model.Snapshot, error) {
	wire, err := decodeSnapshotJSON(data, defaultSnapshotComplexityLimits)
	if err != nil {
		return model.Snapshot{}, err
	}
	return model.Snapshot{
		SchemaVersion: wire.SchemaVersion,
		ID:            wire.ID,
		Name:          wire.Name,
		Provider:      wire.Provider,
		Scope:         wire.Scope,
		GeneratedAt:   wire.GeneratedAt,
		Description:   wire.Description,
		Resources:     wire.Resources,
		Relationships: wire.Relationships,
		RiskScore:     wire.RiskScore,
		Simulations:   wire.Simulations,
	}, nil
}

type discardedJSON struct{}

func (*discardedJSON) UnmarshalJSON([]byte) error { return nil }

type boundedSnapshot struct {
	SchemaVersion string
	ID            string
	Name          string
	Provider      string
	Scope         *model.Scope
	GeneratedAt   time.Time
	Description   string
	Resources     []model.ResourceNode
	Relationships []model.RelationshipEdge
	RiskScore     int
	Simulations   []model.SimulationPreset
}

type snapshotDecodeBudget struct {
	limits                snapshotComplexityLimits
	propertyEntries       int
	evidenceRecords       int
	simulationChanges     int
	removedAttackPathRefs int
}

func decodeSnapshotJSON(data []byte, limits snapshotComplexityLimits) (boundedSnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return boundedSnapshot{}, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return boundedSnapshot{}, fmt.Errorf("snapshot must be a JSON object")
	}

	wire := boundedSnapshot{}
	budget := snapshotDecodeBudget{limits: limits}
	seenCollections := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return boundedSnapshot{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return boundedSnapshot{}, fmt.Errorf("snapshot field name must be a string")
		}
		field := strings.ToLower(key)
		var decodeErr error
		switch field {
		case "schemaversion":
			decodeErr = decoder.Decode(&wire.SchemaVersion)
		case "id":
			decodeErr = decoder.Decode(&wire.ID)
		case "name":
			decodeErr = decoder.Decode(&wire.Name)
		case "provider":
			decodeErr = decoder.Decode(&wire.Provider)
		case "scope":
			decodeErr = decoder.Decode(&wire.Scope)
		case "generatedat":
			decodeErr = decoder.Decode(&wire.GeneratedAt)
		case "description":
			decodeErr = decoder.Decode(&wire.Description)
		case "resources":
			if decodeErr = rejectDuplicateCollection(seenCollections, field); decodeErr == nil {
				value := boundedResources{budget: &budget}
				decodeErr = decoder.Decode(&value)
				wire.Resources = value.values
			}
		case "relationships":
			if decodeErr = rejectDuplicateCollection(seenCollections, field); decodeErr == nil {
				value := boundedRelationships{budget: &budget}
				decodeErr = decoder.Decode(&value)
				wire.Relationships = value.values
			}
		case "findings", "attackpaths", "analysis":
			if decodeErr = rejectDuplicateCollection(seenCollections, field); decodeErr == nil {
				decodeErr = decoder.Decode(&discardedJSON{})
			}
		case "riskscore":
			decodeErr = decoder.Decode(&wire.RiskScore)
		case "simulations":
			if decodeErr = rejectDuplicateCollection(seenCollections, field); decodeErr == nil {
				value := boundedSimulations{budget: &budget}
				decodeErr = decoder.Decode(&value)
				wire.Simulations = value.values
			}
		default:
			decodeErr = decoder.Decode(&discardedJSON{})
		}
		if decodeErr != nil {
			return boundedSnapshot{}, decodeErr
		}
	}
	if token, err = decoder.Token(); err != nil {
		return boundedSnapshot{}, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return boundedSnapshot{}, fmt.Errorf("invalid JSON object")
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			return boundedSnapshot{}, fmt.Errorf("trailing JSON content")
		}
		return boundedSnapshot{}, err
	}
	return wire, nil
}

func rejectDuplicateCollection(seen map[string]struct{}, field string) error {
	if _, exists := seen[field]; exists {
		return fmt.Errorf("%w: duplicate collection field %q", ErrSnapshotComplexityExceeded, field)
	}
	seen[field] = struct{}{}
	return nil
}

func decodeJSONObject(data []byte, label string, decodeField func(string, *json.Decoder) error) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s must be a JSON object", label)
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%s field name must be a string", label)
		}
		if err := decodeField(strings.ToLower(key), decoder); err != nil {
			return err
		}
	}
	if token, err = decoder.Token(); err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("invalid %s JSON object", label)
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content in %s", label)
		}
		return err
	}
	return nil
}

func (budget *snapshotDecodeBudget) reserveProperties(entries int) error {
	if entries > budget.limits.maxPropertyEntries-budget.propertyEntries {
		return complexityLimitError("resource and relationship properties", budget.propertyEntries+entries, budget.limits.maxPropertyEntries)
	}
	budget.propertyEntries += entries
	return nil
}

func (budget *snapshotDecodeBudget) reserveEvidence(records int) error {
	if records > budget.limits.maxEvidenceRecords-budget.evidenceRecords {
		return complexityLimitError("relationship evidence records", budget.evidenceRecords+records, budget.limits.maxEvidenceRecords)
	}
	budget.evidenceRecords += records
	return nil
}

func (budget *snapshotDecodeBudget) reserveSimulation(changes, removedPathRefs int) error {
	if changes > budget.limits.maxSimulationChanges-budget.simulationChanges {
		return complexityLimitError("simulation changes", budget.simulationChanges+changes, budget.limits.maxSimulationChanges)
	}
	if removedPathRefs > budget.limits.maxRemovedAttackPathRefs-budget.removedAttackPathRefs {
		return complexityLimitError("removed attack-path references", budget.removedAttackPathRefs+removedPathRefs, budget.limits.maxRemovedAttackPathRefs)
	}
	budget.simulationChanges += changes
	budget.removedAttackPathRefs += removedPathRefs
	return nil
}

type boundedProperties map[string]string

func (properties *boundedProperties) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*properties = nil
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("properties must be a JSON object")
	}
	result := make(map[string]string)
	entries := 0
	for decoder.More() {
		entries++
		if entries > maxPropertiesPerRecord {
			return complexityLimitError("properties per record", entries, maxPropertiesPerRecord)
		}
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("property name must be a string")
		}
		if _, exists := result[key]; exists {
			return fmt.Errorf("%w: duplicate property name %q", ErrSnapshotComplexityExceeded, key)
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		result[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*properties = result
	return nil
}

type wireResource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Category    string            `json:"category"`
	Provider    string            `json:"provider,omitempty"`
	Location    string            `json:"location,omitempty"`
	Criticality model.Severity    `json:"criticality,omitempty"`
	Properties  boundedProperties `json:"properties,omitempty"`
}

func (resource *wireResource) UnmarshalJSON(data []byte) error {
	seenCollections := make(map[string]struct{})
	return decodeJSONObject(data, "resource", func(field string, decoder *json.Decoder) error {
		switch field {
		case "id":
			return decoder.Decode(&resource.ID)
		case "name":
			return decoder.Decode(&resource.Name)
		case "type":
			return decoder.Decode(&resource.Type)
		case "category":
			return decoder.Decode(&resource.Category)
		case "provider":
			return decoder.Decode(&resource.Provider)
		case "location":
			return decoder.Decode(&resource.Location)
		case "criticality":
			return decoder.Decode(&resource.Criticality)
		case "properties":
			if err := rejectDuplicateCollection(seenCollections, field); err != nil {
				return err
			}
			return decoder.Decode(&resource.Properties)
		default:
			return decoder.Decode(&discardedJSON{})
		}
	})
}

type boundedResources struct {
	budget *snapshotDecodeBudget
	values []model.ResourceNode
}

func (resources *boundedResources) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "resources")
	if err != nil {
		return err
	}
	result := make([]model.ResourceNode, 0, min(1024, resources.budget.limits.maxResources))
	for decoder.More() {
		if len(result) >= resources.budget.limits.maxResources {
			return complexityLimitError("resources", len(result)+1, resources.budget.limits.maxResources)
		}
		var resource wireResource
		if err := decoder.Decode(&resource); err != nil {
			return err
		}
		if err := resources.budget.reserveProperties(len(resource.Properties)); err != nil {
			return err
		}
		result = append(result, model.ResourceNode{
			ID: resource.ID, Name: resource.Name, Type: resource.Type,
			Category: resource.Category, Provider: resource.Provider,
			Location: resource.Location, Criticality: resource.Criticality,
			Properties: map[string]string(resource.Properties),
		})
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	resources.values = result
	return nil
}

type boundedEvidence []model.EvidenceRecord

func (evidence *boundedEvidence) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "evidence")
	if err != nil {
		return err
	}
	result := make([]model.EvidenceRecord, 0, min(8, maxEvidencePerEdge))
	for decoder.More() {
		if len(result) >= maxEvidencePerEdge {
			return complexityLimitError("evidence records per relationship", len(result)+1, maxEvidencePerEdge)
		}
		var item model.EvidenceRecord
		if err := decoder.Decode(&item); err != nil {
			return err
		}
		result = append(result, item)
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	*evidence = result
	return nil
}

type wireRelationship struct {
	ID          string                   `json:"id"`
	Source      string                   `json:"source"`
	Target      string                   `json:"target"`
	Type        string                   `json:"type"`
	Label       string                   `json:"label"`
	Description string                   `json:"description,omitempty"`
	Exploitable bool                     `json:"exploitable"`
	Properties  boundedProperties        `json:"properties,omitempty"`
	Origin      model.RelationshipOrigin `json:"origin,omitempty"`
	Confidence  model.Confidence         `json:"confidence,omitempty"`
	Evidence    boundedEvidence          `json:"evidence,omitempty"`
}

func (relationship *wireRelationship) UnmarshalJSON(data []byte) error {
	seenCollections := make(map[string]struct{})
	return decodeJSONObject(data, "relationship", func(field string, decoder *json.Decoder) error {
		switch field {
		case "id":
			return decoder.Decode(&relationship.ID)
		case "source":
			return decoder.Decode(&relationship.Source)
		case "target":
			return decoder.Decode(&relationship.Target)
		case "type":
			return decoder.Decode(&relationship.Type)
		case "label":
			return decoder.Decode(&relationship.Label)
		case "description":
			return decoder.Decode(&relationship.Description)
		case "exploitable":
			return decoder.Decode(&relationship.Exploitable)
		case "properties":
			if err := rejectDuplicateCollection(seenCollections, field); err != nil {
				return err
			}
			return decoder.Decode(&relationship.Properties)
		case "origin":
			return decoder.Decode(&relationship.Origin)
		case "confidence":
			return decoder.Decode(&relationship.Confidence)
		case "evidence":
			if err := rejectDuplicateCollection(seenCollections, field); err != nil {
				return err
			}
			return decoder.Decode(&relationship.Evidence)
		default:
			return decoder.Decode(&discardedJSON{})
		}
	})
}

type boundedRelationships struct {
	budget *snapshotDecodeBudget
	values []model.RelationshipEdge
}

func (relationships *boundedRelationships) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "relationships")
	if err != nil {
		return err
	}
	result := make([]model.RelationshipEdge, 0, min(2048, relationships.budget.limits.maxRelationships))
	for decoder.More() {
		if len(result) >= relationships.budget.limits.maxRelationships {
			return complexityLimitError("relationships", len(result)+1, relationships.budget.limits.maxRelationships)
		}
		var relationship wireRelationship
		if err := decoder.Decode(&relationship); err != nil {
			return err
		}
		if err := relationships.budget.reserveProperties(len(relationship.Properties)); err != nil {
			return err
		}
		if err := relationships.budget.reserveEvidence(len(relationship.Evidence)); err != nil {
			return err
		}
		result = append(result, model.RelationshipEdge{
			ID: relationship.ID, Source: relationship.Source, Target: relationship.Target,
			Type: relationship.Type, Label: relationship.Label,
			Description: relationship.Description, Exploitable: relationship.Exploitable,
			Properties: map[string]string(relationship.Properties), Origin: relationship.Origin,
			Confidence: relationship.Confidence, Evidence: []model.EvidenceRecord(relationship.Evidence),
		})
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	relationships.values = result
	return nil
}

type boundedChanges []model.SimulationChange

func (changes *boundedChanges) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "simulation changes")
	if err != nil {
		return err
	}
	result := make([]model.SimulationChange, 0, min(8, maxChangesPerPreset))
	for decoder.More() {
		if len(result) >= maxChangesPerPreset {
			return complexityLimitError("changes per simulation preset", len(result)+1, maxChangesPerPreset)
		}
		var change model.SimulationChange
		if err := decoder.Decode(&change); err != nil {
			return err
		}
		result = append(result, change)
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	*changes = result
	return nil
}

type boundedRemovedPaths []string

func (paths *boundedRemovedPaths) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "removed attack paths")
	if err != nil {
		return err
	}
	result := make([]string, 0, min(16, maxRemovedPathsPerPreset))
	for decoder.More() {
		if len(result) >= maxRemovedPathsPerPreset {
			return complexityLimitError("removed paths per simulation preset", len(result)+1, maxRemovedPathsPerPreset)
		}
		var id string
		if err := decoder.Decode(&id); err != nil {
			return err
		}
		result = append(result, id)
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	*paths = result
	return nil
}

type wireSimulation struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Changes            boundedChanges      `json:"changes"`
	RiskScoreAfter     int                 `json:"riskScoreAfter"`
	RemovedAttackPaths boundedRemovedPaths `json:"removedAttackPaths"`
}

func (simulation *wireSimulation) UnmarshalJSON(data []byte) error {
	seenCollections := make(map[string]struct{})
	return decodeJSONObject(data, "simulation", func(field string, decoder *json.Decoder) error {
		switch field {
		case "id":
			return decoder.Decode(&simulation.ID)
		case "name":
			return decoder.Decode(&simulation.Name)
		case "description":
			return decoder.Decode(&simulation.Description)
		case "changes":
			if err := rejectDuplicateCollection(seenCollections, field); err != nil {
				return err
			}
			return decoder.Decode(&simulation.Changes)
		case "riskscoreafter":
			return decoder.Decode(&simulation.RiskScoreAfter)
		case "removedattackpaths":
			if err := rejectDuplicateCollection(seenCollections, field); err != nil {
				return err
			}
			return decoder.Decode(&simulation.RemovedAttackPaths)
		default:
			return decoder.Decode(&discardedJSON{})
		}
	})
}

type boundedSimulations struct {
	budget *snapshotDecodeBudget
	values []model.SimulationPreset
}

func (simulations *boundedSimulations) UnmarshalJSON(data []byte) error {
	decoder, err := arrayDecoder(data, "simulations")
	if err != nil {
		return err
	}
	result := make([]model.SimulationPreset, 0, min(16, simulations.budget.limits.maxSimulations))
	for decoder.More() {
		if len(result) >= simulations.budget.limits.maxSimulations {
			return complexityLimitError("simulations", len(result)+1, simulations.budget.limits.maxSimulations)
		}
		var simulation wireSimulation
		if err := decoder.Decode(&simulation); err != nil {
			return err
		}
		if err := simulations.budget.reserveSimulation(len(simulation.Changes), len(simulation.RemovedAttackPaths)); err != nil {
			return err
		}
		result = append(result, model.SimulationPreset{
			ID: simulation.ID, Name: simulation.Name, Description: simulation.Description,
			Changes: []model.SimulationChange(simulation.Changes), RiskScoreAfter: simulation.RiskScoreAfter,
			RemovedAttackPaths: []string(simulation.RemovedAttackPaths),
		})
	}
	if err := closeArray(decoder); err != nil {
		return err
	}
	simulations.values = result
	return nil
}

func arrayDecoder(data []byte, label string) (*json.Decoder, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		data = []byte("[]")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return nil, fmt.Errorf("%s must be a JSON array", label)
	}
	return decoder, nil
}

func closeArray(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("invalid JSON array")
	}
	return nil
}

func complexityLimitError(label string, value, limit int) error {
	return fmt.Errorf("%w: %s has %d entries (limit %d)", ErrSnapshotComplexityExceeded, label, value, limit)
}
