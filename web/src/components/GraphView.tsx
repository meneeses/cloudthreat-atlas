import { memo, useCallback, useMemo, useState, type CSSProperties } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeChange,
  type NodeProps,
  type XYPosition,
} from '@xyflow/react'
import type { AttackPath, Finding, RelationshipEdge, ResourceNode } from '../types'
import { resourceSeverity, riskForResource } from '../lib/atlas'
import { severityColor } from '../lib/severity'

interface GraphViewProps {
  resources: ResourceNode[]
  relationships: RelationshipEdge[]
  findings: Finding[]
  visibleNodeIds: Set<string>
  selectedNodeId: string | null
  activePath: AttackPath | null
  storyStep: number
  onSelectNode: (nodeId: string | null) => void
}

type StoryState = 'default' | 'path' | 'visited' | 'current' | 'future' | 'dimmed'

type ResourceNodeData = {
  resource: ResourceNode
  risk: number
  storyState: StoryState
} & Record<string, unknown>

type ResourceFlowNode = Node<ResourceNodeData, 'resource'>

const categoryColumns: Record<string, number> = {
  external: 0,
  entry_point: 0,
  devops: 0,
  network: 1,
  compute: 2,
  identity: 3,
  security: 4,
  secrets: 4,
  scope: 4,
  data: 5,
  database: 5,
  storage: 5,
}

const categoryGlyphs: Record<string, string> = {
  external: '◎',
  entry_point: '◎',
  devops: '⌘',
  network: '⇄',
  compute: '▣',
  identity: '◇',
  security: '⌾',
  secrets: '◈',
  scope: '◇',
  data: '▤',
  database: '◫',
  storage: '▱',
}

function ResourceCard({ data, selected }: NodeProps<ResourceFlowNode>) {
  const { resource, risk, storyState } = data
  const severity = resourceSeverity(resource)
  return (
    <div
      className={`resource-node resource-node-${severity} story-${storyState} ${selected ? 'is-selected' : ''}`}
      style={{ '--node-accent': severityColor[severity] } as CSSProperties}
    >
      <Handle type="target" position={Position.Left} className="resource-handle" />
      <span className="resource-glyph" aria-hidden="true">
        {categoryGlyphs[resource.category.toLowerCase()] ?? '⬡'}
      </span>
      <span className="resource-copy">
        <span className="resource-name">{resource.name}</span>
        <span className="resource-type">{resource.type}</span>
      </span>
      <span className="resource-risk">
        <strong>{risk}</strong>
        <small>RISK</small>
      </span>
      {storyState === 'current' ? <span className="story-radar" aria-hidden="true" /> : null}
      <Handle type="source" position={Position.Right} className="resource-handle" />
    </div>
  )
}

const MemoResourceCard = memo(ResourceCard)
const nodeTypes = { resource: MemoResourceCard }

function layoutResources(
  resources: ResourceNode[],
  findings: Finding[],
  selectedNodeId: string | null,
  activePath: AttackPath | null,
  storyStep: number,
): ResourceFlowNode[] {
  const counts = new Map<number, number>()
  const activeIndex = new Map(
    activePath?.resourceIds.map((nodeId, index) => [nodeId, index] as const) ?? [],
  )

  return resources.map((resource, fallbackIndex) => {
    const normalizedCategory = resource.category.toLowerCase()
    const column = categoryColumns[normalizedCategory] ?? (fallbackIndex % 5) + 1
    const row = counts.get(column) ?? 0
    counts.set(column, row + 1)
    const stepIndex = activeIndex.get(resource.id)
    let storyState: StoryState = activePath ? 'dimmed' : 'default'

    if (stepIndex !== undefined) {
      if (storyStep < 0) storyState = 'path'
      else if (stepIndex < storyStep) storyState = 'visited'
      else if (stepIndex === storyStep) storyState = 'current'
      else storyState = 'future'
    }

    return {
      id: resource.id,
      type: 'resource',
      position: { x: 70 + column * 260, y: 70 + row * 155 + (column % 2) * 34 },
      selected: selectedNodeId === resource.id,
      data: { resource, risk: riskForResource(resource, findings), storyState },
      ariaLabel: `${resource.name}, ${resource.type}, ${resourceSeverity(resource)} criticality`,
    }
  })
}

function buildEdges(
  relationships: RelationshipEdge[],
  visibleNodeIds: Set<string>,
  activePath: AttackPath | null,
  storyStep: number,
): Edge[] {
  const pathPairs = new Map<string, number>()
  if (activePath) {
    activePath.steps.forEach((step, index) => {
      pathPairs.set(`${step.source}::${step.target}`, index)
    })
  }

  return relationships
    .filter(
      (relationship) =>
        visibleNodeIds.has(relationship.source) && visibleNodeIds.has(relationship.target),
    )
    .map((relationship) => {
      const pathIndex = pathPairs.get(`${relationship.source}::${relationship.target}`)
      const onPath = pathIndex !== undefined
      const visited = onPath && (storyStep < 0 || pathIndex < storyStep)
      return {
        id: relationship.id,
        source: relationship.source,
        target: relationship.target,
        label: relationship.label,
        animated: visited,
        className: onPath ? (visited ? 'edge-story-active' : 'edge-story-future') : '',
        labelStyle: { fill: '#91a0b8', fontSize: 10, fontWeight: 600 },
        labelBgStyle: { fill: '#080d17', fillOpacity: 0.9 },
        labelBgPadding: [6, 4] as [number, number],
        style: {
          stroke: onPath ? (visited ? '#29e8b2' : '#39465a') : '#283448',
          strokeWidth: onPath ? 2.5 : 1.25,
          opacity: activePath && !onPath ? 0.18 : 0.85,
        },
      }
    })
}

function GraphLegend() {
  return (
    <div className="graph-legend" aria-label="Graph legend">
      <span><i className="legend-line legend-exposure" /> Exposure</span>
      <span><i className="legend-line legend-permission" /> Access</span>
      <span><i className="legend-line legend-path" /> Active path</span>
    </div>
  )
}

export default function GraphView({
  resources,
  relationships,
  findings,
  visibleNodeIds,
  selectedNodeId,
  activePath,
  storyStep,
  onSelectNode,
}: GraphViewProps) {
  const computedNodes = useMemo(
    () => layoutResources(resources, findings, selectedNodeId, activePath, storyStep),
    [activePath, findings, resources, selectedNodeId, storyStep],
  )
  const computedEdges = useMemo(
    () => buildEdges(relationships, visibleNodeIds, activePath, storyStep),
    [activePath, relationships, storyStep, visibleNodeIds],
  )
  const [positionOverrides, setPositionOverrides] = useState<Record<string, XYPosition>>({})
  const nodes = useMemo(
    () =>
      computedNodes.map((node) => ({
        ...node,
        position: positionOverrides[node.id] ?? node.position,
      })),
    [computedNodes, positionOverrides],
  )
  const onNodesChange = useCallback((changes: NodeChange<ResourceFlowNode>[]) => {
    const positionChanges = changes.filter(
      (change) => change.type === 'position' && change.position,
    )
    if (positionChanges.length === 0) return

    setPositionOverrides((current) => {
      const next = { ...current }
      for (const change of positionChanges) {
        if (change.type === 'position' && change.position) {
          next[change.id] = change.position
        }
      }
      return next
    })
  }, [])

  if (resources.length === 0) {
    return (
      <div className="graph-empty" role="status">
        <span aria-hidden="true">⌁</span>
        <strong>No assets match this view</strong>
        <p>Clear one or more filters to restore the attack surface.</p>
      </div>
    )
  }

  return (
    <div className="graph-canvas" data-testid="attack-graph">
      <ReactFlow
        nodes={nodes}
        edges={computedEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeClick={(_, node) => onSelectNode(node.id)}
        onPaneClick={() => onSelectNode(null)}
        fitView
        fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
        minZoom={0.25}
        maxZoom={1.8}
        nodesConnectable={false}
        deleteKeyCode={null}
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1b293c" />
        <MiniMap
          pannable
          zoomable
          position="bottom-left"
          nodeColor={(node) => {
            const data = node.data as ResourceNodeData
            return severityColor[resourceSeverity(data.resource)]
          }}
          nodeStrokeColor="#05080f"
          maskColor="rgba(3, 7, 13, 0.72)"
        />
        <Controls position="bottom-left" showInteractive={false} />
      </ReactFlow>
      <GraphLegend />
    </div>
  )
}
