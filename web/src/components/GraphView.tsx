import { memo, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type ReactFlowInstance,
  type XYPosition,
} from '@xyflow/react'
import type { AttackPath, RelationshipEdge, ResourceNode } from '../types'
import { resourceSeverity } from '../lib/atlas'
import { severityColor } from '../lib/severity'
import type { AtlasViewModel } from '../lib/view-model'

interface GraphViewProps {
  resources: ResourceNode[]
  relationships: RelationshipEdge[]
  model: AtlasViewModel
  visibleNodeIds: Set<string>
  selectedNodeId: string | null
  activePath: AttackPath | null
  storyStep: number
  performanceMode: boolean
  onSelectNode: (nodeId: string | null) => void
}

type StoryState = 'default' | 'path' | 'visited' | 'current' | 'future' | 'dimmed'

type ResourceNodeData = {
  resource: ResourceNode
  risk: number
  storyState: StoryState
} & Record<string, unknown>

type ResourceFlowNode = Node<ResourceNodeData, 'resource'>

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
  model: AtlasViewModel,
  selectedNodeId: string | null,
  activePath: AttackPath | null,
  storyStep: number,
): ResourceFlowNode[] {
  const activeIndex = new Map(
    activePath?.resourceIds.map((nodeId, index) => [nodeId, index] as const) ?? [],
  )

  return resources.map((resource) => {
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
      position: model.positionByResourceId.get(resource.id) ?? { x: 0, y: 0 },
      selected: selectedNodeId === resource.id,
      data: { resource, risk: model.riskByResourceId.get(resource.id) ?? 0, storyState },
      ariaLabel: `${resource.name}, ${resource.type}, ${resourceSeverity(resource)} criticality`,
    }
  })
}

function buildEdges(
  relationships: RelationshipEdge[],
  visibleNodeIds: Set<string>,
  activePath: AttackPath | null,
  storyStep: number,
  performanceMode: boolean,
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
      const normalizedType = relationship.type.toLowerCase()
      const exposure = /exposure|public|internet|network/.test(normalizedType)
      const permission = /role|permission|access|identity|authenticate|control/.test(normalizedType)
      const semantic = exposure ? 'exposure' : permission ? 'permission' : 'dependency'
      const semanticColor = exposure ? '#ff4d6d' : permission ? '#38bdf8' : '#526176'
      return {
        id: relationship.id,
        source: relationship.source,
        target: relationship.target,
        label: performanceMode && !onPath ? undefined : relationship.label,
        animated: visited && !performanceMode,
        className: `${onPath ? (visited ? 'edge-story-active' : 'edge-story-future') : ''} edge-${semantic}`,
        labelStyle: { fill: '#91a0b8', fontSize: 10, fontWeight: 600 },
        labelBgStyle: { fill: '#080d17', fillOpacity: 0.9 },
        labelBgPadding: [6, 4] as [number, number],
        style: {
          stroke: onPath ? (visited ? '#29e8b2' : '#39465a') : semanticColor,
          strokeWidth: onPath ? 2.5 : 1.25,
          opacity: activePath && !onPath ? 0.18 : 0.85,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: onPath && visited ? '#29e8b2' : semanticColor,
          width: 14,
          height: 14,
        },
        ariaLabel: `${relationship.label}: ${relationship.source} to ${relationship.target}`,
      }
    })
}

function GraphLegend() {
  return (
    <div className="graph-legend" aria-label="Graph legend">
      <span><i className="legend-line legend-exposure" /> Exposure</span>
      <span><i className="legend-line legend-permission" /> Permission</span>
      <span><i className="legend-line legend-dependency" /> Dependency</span>
      <span><i className="legend-line legend-path" /> Active path</span>
    </div>
  )
}

function GraphView({
  resources,
  relationships,
  model,
  visibleNodeIds,
  selectedNodeId,
  activePath,
  storyStep,
  performanceMode,
  onSelectNode,
}: GraphViewProps) {
  const computedNodes = useMemo(
    () => layoutResources(resources, model, selectedNodeId, activePath, storyStep),
    [activePath, model, resources, selectedNodeId, storyStep],
  )
  const computedEdges = useMemo(
    () => buildEdges(relationships, visibleNodeIds, activePath, storyStep, performanceMode),
    [activePath, performanceMode, relationships, storyStep, visibleNodeIds],
  )
  const [positionOverrides, setPositionOverrides] = useState<Record<string, XYPosition>>({})
  const flow = useRef<ReactFlowInstance<ResourceFlowNode, Edge> | null>(null)
  const resourceSignature = useMemo(
    () => resources.map((resource) => resource.id).join('\u0000'),
    [resources],
  )
  const nodes = useMemo(
    () =>
      computedNodes.map((node) => ({
        ...node,
        position: positionOverrides[node.id] ?? node.position,
      })),
    [computedNodes, positionOverrides],
  )

  useEffect(() => {
    if (!activePath || !flow.current) return
    const currentId = activePath.resourceIds[Math.max(0, storyStep)]
    const currentNode = nodes.find((node) => node.id === currentId)
    if (!currentNode) return
    void flow.current.setCenter(currentNode.position.x + 111, currentNode.position.y + 36, {
      zoom: performanceMode ? 0.9 : 1.05,
      duration: performanceMode ? 0 : 420,
    })
  }, [activePath, nodes, performanceMode, storyStep])

  useEffect(() => {
    if (activePath || !flow.current || !resourceSignature) return undefined
    const frame = window.requestAnimationFrame(() => {
      void flow.current?.fitView({
        padding: 0.2,
        maxZoom: 1.05,
        duration: performanceMode ? 0 : 240,
      })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [activePath, performanceMode, resourceSignature])

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
        onInit={(instance) => { flow.current = instance }}
        onNodeDragStop={(_, node) => {
          setPositionOverrides((current) => ({ ...current, [node.id]: node.position }))
        }}
        onNodeClick={(_, node) => onSelectNode(node.id)}
        onPaneClick={() => onSelectNode(null)}
        fitView
        fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
        minZoom={0.25}
        maxZoom={1.8}
        nodesConnectable={false}
        nodesDraggable={!performanceMode}
        onlyRenderVisibleElements
        edgesFocusable={false}
        deleteKeyCode={null}
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1b293c" />
        {!performanceMode ? <MiniMap
          pannable
          zoomable
          position="bottom-left"
          nodeColor={(node) => {
            const data = node.data as ResourceNodeData
            return severityColor[resourceSeverity(data.resource)]
          }}
          nodeStrokeColor="#05080f"
          maskColor="rgba(3, 7, 13, 0.72)"
        /> : null}
        <Controls position="bottom-left" showInteractive={false} />
      </ReactFlow>
      <GraphLegend />
    </div>
  )
}

export default memo(GraphView)
