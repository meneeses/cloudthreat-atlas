import type {
  AttackPath,
  Finding,
  ResourceNode,
  Severity,
  SimulationPreset,
  Snapshot,
} from '../types'
import { severityOrder } from './severity'

export interface AtlasFilters {
  query: string
  severity: Severity | 'all'
  type: string
  attackPathId: string
}

export interface FilteredAtlas {
  resources: ResourceNode[]
  visibleResourceIds: Set<string>
}

export function resourceSeverity(resource: ResourceNode): Severity {
  return resource.criticality ?? 'info'
}

export function riskForResource(resource: ResourceNode, findings: Finding[]): number {
  let maxFindingScore = 0
  for (const finding of findings) {
    if (finding.resourceIds.includes(resource.id) && finding.score > maxFindingScore) {
      maxFindingScore = finding.score
    }
  }
  if (maxFindingScore > 0) return maxFindingScore

  const fallback: Record<Severity, number> = {
    critical: 90,
    high: 72,
    medium: 48,
    low: 24,
    info: 8,
  }
  return fallback[resourceSeverity(resource)]
}

export function filterAtlas(snapshot: Snapshot, filters: AtlasFilters): FilteredAtlas {
  const query = filters.query.trim().toLocaleLowerCase()
  const activePath = snapshot.attackPaths.find((path) => path.id === filters.attackPathId)
  const pathResources = activePath ? new Set(activePath.resourceIds) : null

  const resources = snapshot.resources.filter((resource) => {
    if (filters.severity !== 'all' && resourceSeverity(resource) !== filters.severity) return false
    if (filters.type !== 'all' && resource.type !== filters.type) return false
    if (pathResources && !pathResources.has(resource.id)) return false
    if (!query) return true

    return [
      resource.name,
      resource.type,
      resource.category,
      resource.location,
      resource.id,
      ...Object.values(resource.properties ?? {}),
    ]
      .join(' ')
      .toLocaleLowerCase()
      .includes(query)
  })

  return {
    resources,
    visibleResourceIds: new Set(resources.map((resource) => resource.id)),
  }
}

export function findingsForNode(findings: Finding[], resourceId: string): Finding[] {
  return findings
    .filter((finding) => finding.resourceIds.includes(resourceId))
    .toSorted((a, b) => severityOrder[b.severity] - severityOrder[a.severity])
}

export function pathsForNode(paths: AttackPath[], resourceId: string): AttackPath[] {
  return paths.filter((path) => path.resourceIds.includes(resourceId))
}

export function countExposedResources(snapshot: Snapshot): number {
  const internetEntryIds = new Set(
    snapshot.resources
      .filter((resource) => resource.type.toLowerCase() === 'external.internet')
      .map((resource) => resource.id),
  )
  const exposedIds = new Set(
    snapshot.relationships
      .filter(
        (relationship) =>
          internetEntryIds.has(relationship.source) && relationship.exploitable,
      )
      .map((relationship) => relationship.target),
  )

  for (const resource of snapshot.resources) {
    if (internetEntryIds.has(resource.id)) continue
    const properties = resource.properties ?? {}
    if (
      properties.public === 'true' ||
      properties.internetFacing === 'true' ||
      properties.exposure === 'public' ||
      properties.publicNetworkAccess?.toLowerCase() === 'enabled'
    ) {
      exposedIds.add(resource.id)
    }
  }

  return exposedIds.size
}

export function deriveSimulations(snapshot: Snapshot): SimulationPreset[] {
  return snapshot.simulations ?? []
}

export function compareSimulation(
  snapshot: Snapshot,
  simulation: SimulationPreset,
): { originalScore: number; projectedScore: number; remainingPaths: number } {
  const removed = new Set(simulation.removedAttackPaths)

  return {
    originalScore: snapshot.riskScore,
    projectedScore: simulation.riskScoreAfter,
    remainingPaths: Math.max(0, snapshot.attackPaths.length - removed.size),
  }
}
