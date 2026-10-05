package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

const (
	defaultMaxDepth          = 8
	defaultMaxPaths          = 500
	defaultMaxPathsPerTarget = 20
	defaultMaxExpansions     = 100_000
)

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// PathAnalyzer finds simple exploitable paths from entry_point nodes to critical assets.
type PathAnalyzer struct {
	MaxDepth          int
	MaxPaths          int
	MaxPathsPerTarget int
	MaxExpansions     int
}

// PathResult includes both discovered paths and the bounds used to discover them.
type PathResult struct {
	Paths        []model.AttackPath
	Metadata     model.PathSearchMetadata
	targetCounts map[string]int
	seenPathIDs  map[string]struct{}
	halt         bool
}

// NewPathAnalyzer constructs a deterministic path analyzer.
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{MaxDepth: defaultMaxDepth, MaxPaths: defaultMaxPaths, MaxPathsPerTarget: defaultMaxPathsPerTarget, MaxExpansions: defaultMaxExpansions}
}

// Analyze implements model.PathAnalyzer.
func (a *PathAnalyzer) Analyze(ctx context.Context, g model.Graph) ([]model.AttackPath, error) {
	result, err := a.AnalyzeWithMetadata(ctx, g)
	return result.Paths, err
}

// AnalyzeWithMetadata performs deterministic, bounded path discovery.
func (a *PathAnalyzer) AnalyzeWithMetadata(ctx context.Context, g model.Graph) (PathResult, error) {
	maxDepth := a.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	maxPaths := a.MaxPaths
	if maxPaths <= 0 {
		maxPaths = defaultMaxPaths
	}
	maxExpansions := a.MaxExpansions
	if maxExpansions <= 0 {
		maxExpansions = defaultMaxExpansions
	}
	maxPathsPerTarget := a.MaxPathsPerTarget
	if maxPathsPerTarget <= 0 {
		maxPathsPerTarget = defaultMaxPathsPerTarget
	}
	result := PathResult{Metadata: model.PathSearchMetadata{MaxDepth: maxDepth, MaxPaths: maxPaths, MaxPathsPerTarget: maxPathsPerTarget, MaxExpansions: maxExpansions}, targetCounts: make(map[string]int), seenPathIDs: make(map[string]struct{})}

	var entries []model.ResourceNode
	for _, resource := range g.Resources() {
		if resource.Category == "entry_point" {
			entries = append(entries, resource)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

	for _, entry := range entries {
		if result.halt {
			break
		}
		visited := map[string]bool{entry.ID: true}
		if err := a.walk(ctx, g, entry, entry.ID, nil, visited, maxDepth, &result); err != nil {
			return PathResult{}, err
		}
	}
	sort.Slice(result.Paths, func(i, j int) bool { return result.Paths[i].ID < result.Paths[j].ID })
	return result, nil
}

func (a *PathAnalyzer) walk(
	ctx context.Context,
	g model.Graph,
	entry model.ResourceNode,
	current string,
	edges []model.RelationshipEdge,
	visited map[string]bool,
	remaining int,
	result *PathResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if remaining == 0 {
		for _, edge := range g.Outgoing(current) {
			if result.Metadata.Expansions >= result.Metadata.MaxExpansions {
				result.Metadata.Truncated = true
				result.Metadata.Reason = "max_expansions"
				result.halt = true
				return nil
			}
			result.Metadata.Expansions++
			if !edge.Exploitable || visited[edge.Target] {
				continue
			}
			if _, ok := g.Node(edge.Target); ok {
				result.Metadata.Truncated = true
				if result.Metadata.Reason == "" {
					result.Metadata.Reason = "max_depth"
				}
				break
			}
		}
		return nil
	}
	for _, edge := range g.Outgoing(current) {
		if result.Metadata.Expansions >= result.Metadata.MaxExpansions {
			result.Metadata.Truncated = true
			result.Metadata.Reason = "max_expansions"
			result.halt = true
			return nil
		}
		result.Metadata.Expansions++
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
			if result.targetCounts[target.ID] >= result.Metadata.MaxPathsPerTarget {
				result.Metadata.Truncated = true
				if result.Metadata.Reason == "" {
					result.Metadata.Reason = "max_paths_per_target"
				}
				delete(visited, edge.Target)
				continue
			}
			path := buildPath(g, entry, target, nextEdges)
			if _, duplicate := result.seenPathIDs[path.ID]; duplicate {
				delete(visited, edge.Target)
				continue
			}
			result.seenPathIDs[path.ID] = struct{}{}
			result.Paths = append(result.Paths, path)
			result.targetCounts[target.ID]++
			if len(result.Paths) >= result.Metadata.MaxPaths {
				result.Metadata.Truncated = true
				result.Metadata.Reason = "max_paths"
				result.halt = true
				delete(visited, edge.Target)
				return nil
			}
		} else if err := a.walk(ctx, g, entry, target.ID, nextEdges, visited, remaining-1, result); err != nil {
			return err
		}
		delete(visited, edge.Target)
		if result.halt {
			return nil
		}
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
	pathDigest := sha256.Sum256([]byte(strings.Join(relationshipIDs, "\x00")))
	pathID := "path-" + slug(strings.Join(resourceIDs, "-")) + "-" + hex.EncodeToString(pathDigest[:6])
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
