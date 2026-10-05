package graph

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

// Graph is an immutable-indexed view of resources and directed relationships.
type Graph struct {
	resources     []model.ResourceNode
	relationships []model.RelationshipEdge
	byID          map[string]model.ResourceNode
	outgoing      map[string][]model.RelationshipEdge
}

// New validates a snapshot topology and builds stable lookup indexes.
func New(resources []model.ResourceNode, relationships []model.RelationshipEdge) (*Graph, error) {
	g := &Graph{
		resources:     slices.Clone(resources),
		relationships: slices.Clone(relationships),
		byID:          make(map[string]model.ResourceNode, len(resources)),
		outgoing:      make(map[string][]model.RelationshipEdge),
	}
	for _, resource := range g.resources {
		if resource.ID == "" {
			return nil, errors.New("resource id must not be empty")
		}
		if _, exists := g.byID[resource.ID]; exists {
			return nil, fmt.Errorf("duplicate resource id %q", resource.ID)
		}
		g.byID[resource.ID] = resource
	}
	relationshipIDs := make(map[string]struct{}, len(g.relationships))
	for _, relationship := range g.relationships {
		if relationship.ID == "" {
			return nil, errors.New("relationship id must not be empty")
		}
		if _, exists := relationshipIDs[relationship.ID]; exists {
			return nil, fmt.Errorf("duplicate relationship id %q", relationship.ID)
		}
		relationshipIDs[relationship.ID] = struct{}{}
		if _, ok := g.byID[relationship.Source]; !ok {
			return nil, fmt.Errorf("relationship %q has unknown source %q", relationship.ID, relationship.Source)
		}
		if _, ok := g.byID[relationship.Target]; !ok {
			return nil, fmt.Errorf("relationship %q has unknown target %q", relationship.ID, relationship.Target)
		}
		g.outgoing[relationship.Source] = append(g.outgoing[relationship.Source], relationship)
	}
	for id := range g.outgoing {
		sort.Slice(g.outgoing[id], func(i, j int) bool {
			return g.outgoing[id][i].ID < g.outgoing[id][j].ID
		})
	}
	return g, nil
}

// Resources implements model.Graph and returns a defensive copy.
func (g *Graph) Resources() []model.ResourceNode {
	return slices.Clone(g.resources)
}

// Relationships implements model.Graph and returns a defensive copy.
func (g *Graph) Relationships() []model.RelationshipEdge {
	return slices.Clone(g.relationships)
}

// Node implements model.Graph.
func (g *Graph) Node(id string) (model.ResourceNode, bool) {
	node, ok := g.byID[id]
	return node, ok
}

// Outgoing implements model.Graph and returns relationships in stable ID order.
func (g *Graph) Outgoing(id string) []model.RelationshipEdge {
	return slices.Clone(g.outgoing[id])
}

var _ model.Graph = (*Graph)(nil)
