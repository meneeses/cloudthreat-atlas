package graph

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const defaultMaxDepth = 8

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// PathAnalyzer finds simple exploitable paths from entry_point nodes to critical assets.
type PathAnalyzer struct {
	MaxDepth int
}

// NewPathAnalyzer constructs a deterministic path analyzer.
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{MaxDepth: defaultMaxDepth}
}

// Analyze implements model.PathAnalyzer.
func (a *PathAnalyzer) Analyze(ctx context.Context, g model.Graph) ([]model.AttackPath, error) {
	maxDepth := a.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}

	var entries []model.ResourceNode
	for _, resource := range g.Resources() {
		if resource.Category == "entry_point" {
			entries = append(entries, resource)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

	var paths []model.AttackPath
	for _, entry := range entries {
		visited := map[string]bool{entry.ID: true}
		if err := a.walk(ctx, g, entry, entry.ID, nil, visited, maxDepth, &paths); err != nil {
			return nil, err
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return paths, nil
}

func (a *PathAnalyzer) walk(
	ctx context.Context,
	g model.Graph,
	entry model.ResourceNode,
	current string,
	edges []model.RelationshipEdge,
	visited map[string]bool,
	remaining int,
	paths *[]model.AttackPath,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if remaining == 0 {
		return nil
	}
	for _, edge := range g.Outgoing(current) {
		if !edge.Exploitable || visited[edge.Target] {
			continue
		}
		target, ok := g.Node(edge.Target)
		if !ok {
			continue
		}
		visited[edge.Target] = true
		nextEdges := append(slices.Clone(edges), edge)
		if target.Criticality == model.SeverityCritical {
			*paths = append(*paths, buildPath(g, entry, target, nextEdges))
		} else if err := a.walk(ctx, g, entry, target.ID, nextEdges, visited, remaining-1, paths); err != nil {
			return err
		}
		delete(visited, edge.Target)
	}
	return nil
}

func buildPath(g model.Graph, entry, target model.ResourceNode, edges []model.RelationshipEdge) model.AttackPath {
	resourceIDs := make([]string, 1, len(edges)+1)
	resourceIDs[0] = entry.ID
	relationshipIDs := make([]string, 0, len(edges))
	steps := make([]model.AttackStep, 0, len(edges))
	for i, edge := range edges {
		resourceIDs = append(resourceIDs, edge.Target)
		relationshipIDs = append(relationshipIDs, edge.ID)
		narrative := edge.Description
		if narrative == "" {
			narrative = fmt.Sprintf("%s can reach %s through %s.", displayName(g, edge.Source), displayName(g, edge.Target), edge.Label)
		}
		steps = append(steps, model.AttackStep{
			Order:          i + 1,
			Source:         edge.Source,
			Target:         edge.Target,
			RelationshipID: edge.ID,
			Narrative:      narrative,
		})
	}
	pathID := "path-" + slug(strings.Join(resourceIDs, "-"))
	title, description := pathCopy(entry, target)
	score := 100 - len(edges)
	if score < 90 {
		score = 90
	}
	return model.AttackPath{
		ID:              pathID,
		Title:           title,
		Description:     description,
		Severity:        model.SeverityCritical,
		Score:           score,
		EntryPoint:      entry.ID,
		Target:          target.ID,
		ResourceIDs:     resourceIDs,
		RelationshipIDs: relationshipIDs,
		Steps:           steps,
	}
}

func pathCopy(entry, target model.ResourceNode) (string, string) {
	switch {
	case target.Type == "Microsoft.DBforPostgreSQL/flexibleServers":
		return "Public application identity pivots into the clinical database",
			"An internet-facing application can use its managed identity, read a database secret, and reach protected clinical data."
	case target.Type == "Microsoft.Storage/storageAccounts":
		return "Exposed virtual machine reaches sensitive patient storage",
			"Open network ingress and an over-privileged workload identity create a direct route to sensitive blobs."
	case entry.Type == "devops.pipeline":
		return "Compromised pipeline controls a production resource group",
			"A leaked pipeline credential grants Owner-level control and reaches a critical security analytics resource."
	default:
		return fmt.Sprintf("%s can reach %s", entry.Name, target.Name),
			"CloudThreat Atlas found an exploitable sequence from an entry point to a critical asset."
	}
}

func displayName(g model.Graph, id string) string {
	if node, ok := g.Node(id); ok {
		return node.Name
	}
	return id
}

func slug(value string) string {
	return strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(value), "-"), "-")
}

var _ model.PathAnalyzer = (*PathAnalyzer)(nil)
