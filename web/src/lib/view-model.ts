import type {
  AttackPath,
  Finding,
  RelationshipEdge,
  ResourceNode,
  Severity,
  Snapshot,
} from '../types'
import type { AtlasFilters } from './atlas'

export type GraphMode = 'overview' | 'attack-path' | 'neighborhood'

export interface GraphPosition {
  x: number
  y: number
}

export interface AtlasViewModel {
  snapshot: Snapshot
  resourceById: Map<string, ResourceNode>
  findingById: Map<string, Finding>
  pathById: Map<string, AttackPath>
  findingsByResourceId: Map<string, Finding[]>
  pathsByResourceId: Map<string, AttackPath[]>
  relationshipsByResourceId: Map<string, RelationshipEdge[]>
  neighborsByResourceId: Map<string, Set<string>>
  riskByResourceId: Map<string, number>
  searchTextByResourceId: Map<string, string>
  positionByResourceId: Map<string, GraphPosition>
  resourceTypes: string[]
}

export interface VisibleAtlas {
  resources: ResourceNode[]
  visibleResourceIds: Set<string>
  totalMatching: number
  truncated: boolean
}

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

const fallbackRisk: Record<Severity, number> = {
  critical: 90,
  high: 72,
  medium: 48,
  low: 24,
  info: 8,
}

function stableColumn(resource: ResourceNode): number {
  const known = categoryColumns[resource.category.toLowerCase()]
  if (known !== undefined) return known
  let hash = 0
  for (const character of resource.category) hash = (hash * 31 + character.charCodeAt(0)) | 0
  return 1 + Math.abs(hash % 5)
}

function buildPositions(resources: ResourceNode[]): Map<string, GraphPosition> {
  const rowsByColumn = new Map<number, number>()
  const positions = new Map<string, GraphPosition>()
  for (const resource of resources) {
    const column = stableColumn(resource)
    const row = rowsByColumn.get(column) ?? 0
    rowsByColumn.set(column, row + 1)
    positions.set(resource.id, {
      x: 70 + column * 260,
      y: 70 + row * 155 + (column % 2) * 34,
    })
  }
  return positions
}

function appendToIndex<T>(index: Map<string, T[]>, key: string, value: T): void {
  const existing = index.get(key)
  if (existing) existing.push(value)
  else index.set(key, [value])
}

export function createAtlasViewModel(snapshot: Snapshot): AtlasViewModel {
  const resourceById = new Map(snapshot.resources.map((resource) => [resource.id, resource]))
  const findingById = new Map(snapshot.findings.map((finding) => [finding.id, finding]))
  const pathById = new Map(snapshot.attackPaths.map((path) => [path.id, path]))
  const findingsByResourceId = new Map<string, Finding[]>()
  const pathsByResourceId = new Map<string, AttackPath[]>()
  const relationshipsByResourceId = new Map<string, RelationshipEdge[]>()
  const neighborsByResourceId = new Map<string, Set<string>>()
  const riskByResourceId = new Map(
    snapshot.resources.map((resource) => [resource.id, fallbackRisk[resource.criticality ?? 'info']]),
  )

  for (const finding of snapshot.findings) {
    for (const resourceId of finding.resourceIds) {
      appendToIndex(findingsByResourceId, resourceId, finding)
      riskByResourceId.set(resourceId, Math.max(riskByResourceId.get(resourceId) ?? 0, finding.score))
    }
  }
  for (const path of snapshot.attackPaths) {
    for (const resourceId of path.resourceIds) appendToIndex(pathsByResourceId, resourceId, path)
  }
  for (const relationship of snapshot.relationships) {
    appendToIndex(relationshipsByResourceId, relationship.source, relationship)
    appendToIndex(relationshipsByResourceId, relationship.target, relationship)
    const sourceNeighbors = neighborsByResourceId.get(relationship.source) ?? new Set<string>()
    sourceNeighbors.add(relationship.target)
    neighborsByResourceId.set(relationship.source, sourceNeighbors)
    const targetNeighbors = neighborsByResourceId.get(relationship.target) ?? new Set<string>()
    targetNeighbors.add(relationship.source)
    neighborsByResourceId.set(relationship.target, targetNeighbors)
  }

  const searchTextByResourceId = new Map(
    snapshot.resources.map((resource) => [
      resource.id,
      [
        resource.name,
        resource.type,
        resource.category,
        resource.location,
        resource.id,
        ...Object.values(resource.properties ?? {}),
      ].join(' ').toLocaleLowerCase(),
    ]),
  )

  return {
    snapshot,
    resourceById,
    findingById,
    pathById,
    findingsByResourceId,
    pathsByResourceId,
    relationshipsByResourceId,
    neighborsByResourceId,
    riskByResourceId,
    searchTextByResourceId,
    positionByResourceId: buildPositions(snapshot.resources),
    resourceTypes: [...new Set(snapshot.resources.map((resource) => resource.type))].toSorted(),
  }
}

export function selectVisibleAtlas(
  model: AtlasViewModel,
  filters: AtlasFilters,
  options: {
    mode: GraphMode
    selectedResourceId: string | null
    pathId: string | null
    limit: number
  },
): VisibleAtlas {
  const query = filters.query.trim().toLocaleLowerCase()
  const path = model.pathById.get(options.pathId ?? filters.attackPathId)
  let focusedIds: Set<string> | null = null

  if (options.mode === 'attack-path' && path) focusedIds = new Set(path.resourceIds)
  if (options.mode === 'neighborhood' && options.selectedResourceId) {
    focusedIds = new Set([
      options.selectedResourceId,
      ...(model.neighborsByResourceId.get(options.selectedResourceId) ?? []),
    ])
  }
  if (filters.attackPathId !== 'all') {
    const filteredPath = model.pathById.get(filters.attackPathId)
    if (filteredPath) focusedIds = new Set(filteredPath.resourceIds)
  }

  const matching: ResourceNode[] = []
  for (const resource of model.snapshot.resources) {
    if (focusedIds && !focusedIds.has(resource.id)) continue
    if (filters.severity !== 'all' && (resource.criticality ?? 'info') !== filters.severity) continue
    if (filters.type !== 'all' && resource.type !== filters.type) continue
    if (query && !model.searchTextByResourceId.get(resource.id)?.includes(query)) continue
    matching.push(resource)
  }

  const resources = matching.slice(0, Math.max(1, options.limit))
  return {
    resources,
    visibleResourceIds: new Set(resources.map((resource) => resource.id)),
    totalMatching: matching.length,
    truncated: matching.length > resources.length,
  }
}
