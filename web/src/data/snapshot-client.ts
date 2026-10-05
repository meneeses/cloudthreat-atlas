import type {
  AzureScanEvent,
  AzureScanJob,
  AzureScanScope,
  SimulationChange,
  SimulationImpact,
  SimulationResult,
  Snapshot,
  SnapshotComparison,
  SnapshotEnvelope,
  SnapshotSummary,
  TriageRecord,
  TriageStatus,
  WorkspaceBootstrap,
} from '../types'
import { parseSimulationResult, parseSnapshot } from './validation'

const FIXTURE_FILE = 'contoso-health.json'
const FULL_SNAPSHOT_RESOURCE_LIMIT = 500
const FULL_SNAPSHOT_RELATIONSHIP_LIMIT = 2_000
const BOUNDED_GRAPH_RESOURCE_LIMIT = 500
const BOUNDED_GRAPH_RELATIONSHIP_LIMIT = 2_000
const BOUNDED_FINDING_LIMIT = 200
const BOUNDED_ATTACK_PATH_LIMIT = 100
const EXPLICIT_GRAPH_QUERY_LENGTH = 8_000
const FOLLOW_UP_REQUEST_CONCURRENCY = 4
const SESSION_FRAGMENT_KEY = 'atlas-session'
const SESSION_HEADER = 'X-Atlas-Session-Token'

let workspaceSessionToken: string | undefined

class HTTPError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

export const WORKSPACE_SESSION_EXPIRED_MESSAGE = 'The local workspace session is missing or has expired. Reopen the private URL printed by Atlas in your terminal.'

export class WorkspaceSessionExpiredError extends Error {
  constructor() {
    super(WORKSPACE_SESSION_EXPIRED_MESSAGE)
    this.name = 'WorkspaceSessionExpiredError'
  }
}

export interface WorkspaceLoadResult {
  bootstrap: WorkspaceBootstrap
  initialSnapshot?: SnapshotEnvelope
}

function apiBase(): string {
  return (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
}

function isAPIMode(): boolean {
  return import.meta.env.VITE_DATA_SOURCE === 'api'
}

function isWorkspaceAPIRequest(url: string): boolean {
  const base = typeof window === 'undefined' ? 'http://localhost' : window.location.href
  const target = new URL(url, base)
  return target.pathname === '/healthz' || target.pathname.startsWith('/api/')
}

function responseError(url: string, status: number, message: string): Error {
  if (status === 401 && isWorkspaceAPIRequest(url)) return new WorkspaceSessionExpiredError()
  return new HTTPError(status, message)
}

function captureWorkspaceSessionToken(): string | undefined {
  if (typeof window === 'undefined') return workspaceSessionToken
  const fragment = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash
  if (!fragment) return workspaceSessionToken
  const parameters = new URLSearchParams(fragment)
  const candidate = parameters.get(SESSION_FRAGMENT_KEY)
  if (candidate === null) return workspaceSessionToken

  parameters.delete(SESSION_FRAGMENT_KEY)
  const remainingFragment = parameters.toString()
  const cleanURL = `${window.location.pathname}${window.location.search}${remainingFragment ? `#${remainingFragment}` : ''}`
  window.history.replaceState(window.history.state, '', cleanURL)
  if (/^[A-Za-z0-9_-]{43}$/.test(candidate)) workspaceSessionToken = candidate
  return workspaceSessionToken
}

function requestHeaders(url: string, initial?: HeadersInit): Headers {
  const headers = new Headers(initial)
  const token = captureWorkspaceSessionToken()
  if (!token || typeof window === 'undefined') return headers
  const target = new URL(url, window.location.href)
  if (isWorkspaceAPIRequest(url) && target.origin === window.location.origin) {
    headers.set(SESSION_HEADER, token)
  }
  return headers
}

async function fetchJSON(url: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    signal,
    headers: requestHeaders(url, { Accept: 'application/json' }),
  })
  if (!response.ok) {
    throw responseError(url, response.status, `Request failed with status ${response.status}.`)
  }
  try {
    return await response.json()
  } catch {
    throw new Error('The data request returned invalid JSON.')
  }
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`Invalid ${field}.`)
  return value
}

function finiteNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function requiredFiniteNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`Invalid ${field}.`)
  return value
}

export function summarizeSnapshot(
  snapshot: Snapshot,
  origin: SnapshotSummary['origin'],
): SnapshotSummary {
  return {
    id: snapshot.id,
    name: snapshot.name,
    provider: snapshot.provider,
    generatedAt: snapshot.generatedAt,
    riskScore: snapshot.riskScore,
    resourceCount: snapshot.resources.length,
    relationshipCount: snapshot.relationships.length,
    findingCount: snapshot.findings.length,
    attackPathCount: snapshot.attackPaths.length,
    origin,
  }
}

function parseSummary(value: unknown): SnapshotSummary {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid snapshot catalog entry.')
  }
  const candidate = value as Record<string, unknown>
  const counts = typeof candidate.counts === 'object' && candidate.counts !== null
    ? candidate.counts as Record<string, unknown>
    : {}
  return {
    id: requiredString(candidate.id, 'snapshot id'),
    environmentId: typeof candidate.environmentId === 'string' && candidate.environmentId !== ''
      ? candidate.environmentId
      : undefined,
    name: requiredString(candidate.name ?? candidate.id, 'snapshot name'),
    provider: requiredString(candidate.provider ?? 'azure', 'snapshot provider'),
    generatedAt: requiredString(candidate.generatedAt, 'snapshot timestamp'),
    riskScore: finiteNumber(candidate.riskScore),
    resourceCount: finiteNumber(candidate.resourceCount ?? counts.resources),
    relationshipCount: finiteNumber(candidate.relationshipCount ?? counts.relationships),
    findingCount: finiteNumber(candidate.findingCount ?? counts.findings),
    attackPathCount: finiteNumber(candidate.attackPathCount ?? counts.attackPaths),
    origin: 'api',
  }
}

function parseBootstrap(value: unknown): WorkspaceBootstrap {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid workspace bootstrap response.')
  }
  const candidate = value as Record<string, unknown>
  const snapshots = Array.isArray(candidate.snapshots) ? candidate.snapshots.map(parseSummary) : []
  const capabilities = typeof candidate.capabilities === 'object' && candidate.capabilities !== null
    ? candidate.capabilities as Record<string, unknown>
    : {}
  const current = candidate.currentSnapshotId
  return {
    snapshots,
    currentSnapshotId: typeof current === 'string' ? current : snapshots[0]?.id ?? null,
    source: 'api',
    capabilities: {
      history: capabilities.history === true || snapshots.length > 1,
      comparison: capabilities.comparison === true,
      import: capabilities.import === true,
      triage: capabilities.triage === true,
      azureScans: capabilities.azureScans === true,
    },
    csrfToken: typeof candidate.csrfToken === 'string' ? candidate.csrfToken : undefined,
  }
}

function parseSession(value: unknown): { csrfToken?: string } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid local API session response.')
  }
  const candidate = value as Record<string, unknown>
  return {
    csrfToken: typeof candidate.csrfToken === 'string' && candidate.csrfToken !== ''
      ? candidate.csrfToken
      : undefined,
  }
}

function parseCatalog(value: unknown, csrfToken?: string): WorkspaceBootstrap {
  const candidate = Array.isArray(value)
    ? { snapshots: value }
    : typeof value === 'object' && value !== null
      ? value as Record<string, unknown>
      : null
  if (!candidate || !Array.isArray(candidate.snapshots)) {
    throw new Error('Invalid snapshot catalog response.')
  }
  const snapshots = candidate.snapshots.map(parseSummary)
  const requestedCurrent = candidate.currentSnapshotId
  const currentSnapshotId = typeof requestedCurrent === 'string'
    && snapshots.some((snapshot) => snapshot.id === requestedCurrent)
    ? requestedCurrent
    : snapshots[0]?.id ?? null
  return {
    snapshots,
    currentSnapshotId,
    source: 'api',
    capabilities: {
      history: snapshots.length > 1,
      comparison: true,
      import: Boolean(csrfToken),
      triage: false,
      azureScans: false,
    },
    csrfToken,
  }
}

async function loadFixture(signal?: AbortSignal): Promise<Snapshot> {
  return parseSnapshot(await fetchJSON(`${import.meta.env.BASE_URL}${FIXTURE_FILE}`, signal))
}

async function loadFromAPI(snapshotId: string, signal?: AbortSignal): Promise<Snapshot> {
  const payload = await fetchJSON(
    `${apiBase()}/api/v1/snapshots/${encodeURIComponent(snapshotId)}`,
    signal,
  )
  const candidate = typeof payload === 'object' && payload !== null && 'data' in payload
    ? (payload as { data: unknown }).data
    : payload
  return parseSnapshot(candidate)
}

function responseRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Invalid ${label} response.`)
  }
  return value as Record<string, unknown>
}

function responseArray(
  response: Record<string, unknown>,
  field: string,
  label: string,
): unknown[] {
  if (!Array.isArray(response[field])) throw new Error(`Invalid ${label} response: missing ${field}.`)
  return response[field]
}

function assertSnapshotResponse(
  response: Record<string, unknown>,
  snapshotId: string,
  label: string,
): void {
  if (requiredString(response.snapshotId, `${label} snapshot id`) !== snapshotId) {
    throw new Error(`The ${label} response referenced a different snapshot.`)
  }
}

function recordID(value: unknown, label: string): string {
  return requiredString(responseRecord(value, label).id, `${label} id`)
}

function recordStringArray(
  value: unknown,
  field: string,
  label: string,
  optional = false,
): string[] {
  const record = responseRecord(value, label)
  const candidate = record[field]
  if (optional && candidate === undefined) return []
  if (!Array.isArray(candidate) || candidate.some((item) => typeof item !== 'string' || item === '')) {
    throw new Error(`Invalid ${label}: ${field} must contain string identifiers.`)
  }
  return candidate as string[]
}

function uniqueRecordsByID(values: unknown[], label: string): Map<string, unknown> {
  const records = new Map<string, unknown>()
  for (const value of values) {
    const id = recordID(value, label)
    if (records.has(id)) throw new Error(`Invalid ${label} response: duplicate id “${id}”.`)
    records.set(id, value)
  }
  return records
}

interface GraphSlice {
  resources: unknown[]
  relationships: unknown[]
}

function parseGraphSlice(value: unknown, snapshotId: string): GraphSlice {
  const response = responseRecord(value, 'graph slice')
  assertSnapshotResponse(response, snapshotId, 'graph slice')
  return {
    resources: responseArray(response, 'resources', 'graph slice'),
    relationships: responseArray(response, 'relationships', 'graph slice'),
  }
}

function graphURL(snapshotId: string, resourceIds?: string[]): string {
  const query = new URLSearchParams({
    limit: String(BOUNDED_GRAPH_RESOURCE_LIMIT),
    relationship_limit: String(BOUNDED_GRAPH_RELATIONSHIP_LIMIT),
  })
  for (const resourceId of resourceIds ?? []) query.append('resource_id', resourceId)
  return `${apiBase()}/api/v1/snapshots/${encodeURIComponent(snapshotId)}/graph?${query}`
}

function boundedCollectionURL(
  path: string,
  snapshotId: string,
  pageSize: number,
): string {
  const query = new URLSearchParams({
    snapshot_id: snapshotId,
    page: '1',
    page_size: String(pageSize),
  })
  return `${apiBase()}${path}?${query}`
}

function exactFindingsURL(snapshotId: string, findingIds: string[]): string {
  const query = new URLSearchParams({ snapshot_id: snapshotId })
  for (const findingId of findingIds) query.append('finding_id', findingId)
  return `${apiBase()}/api/v1/findings?${query}`
}

function selectBoundedPaths(values: unknown[]): {
  paths: unknown[]
  resourceIds: string[]
  findingIds: string[]
} {
  const paths: unknown[] = []
  const resourceIds: string[] = []
  const findingIds: string[] = []
  const selectedResources = new Set<string>()
  const selectedFindings = new Set<string>()
  for (const value of values) {
    const pathResourceIds = [...new Set(recordStringArray(value, 'resourceIds', 'attack path'))]
    const pathFindingIds = [...new Set(
      recordStringArray(value, 'findingIds', 'attack path', true),
    )]
    const additionalResources = pathResourceIds.filter((id) => !selectedResources.has(id))
    const additionalFindings = pathFindingIds.filter((id) => !selectedFindings.has(id))
    if (selectedResources.size + additionalResources.length > BOUNDED_GRAPH_RESOURCE_LIMIT) continue
    if (selectedFindings.size + additionalFindings.length > BOUNDED_FINDING_LIMIT) continue
    if (graphURL('snapshot', pathResourceIds).length > EXPLICIT_GRAPH_QUERY_LENGTH) continue
    paths.push(value)
    for (const id of additionalResources) {
      selectedResources.add(id)
      resourceIds.push(id)
    }
    for (const id of additionalFindings) {
      selectedFindings.add(id)
      findingIds.push(id)
    }
  }
  return { paths, resourceIds, findingIds }
}

function explicitResourceBatches(groups: string[][]): string[][] {
  const batches: string[][] = []
  let batch: string[] = []
  let selected = new Set<string>()
  for (const group of groups) {
    const groupIDs = [...new Set(group)]
    const candidate = [...batch, ...groupIDs.filter((id) => !selected.has(id))]
    const candidateLength = graphURL('snapshot', candidate).length
    if (batch.length > 0 && candidateLength > EXPLICIT_GRAPH_QUERY_LENGTH) {
      batches.push(batch)
      batch = groupIDs
      selected = new Set(groupIDs)
      continue
    }
    batch = candidate
    selected = new Set(candidate)
  }
  if (batch.length > 0) batches.push(batch)
  return batches
}

function explicitGraphBatches(paths: unknown[]): string[][] {
  return explicitResourceBatches(paths.map((path) =>
    recordStringArray(path, 'resourceIds', 'attack path')))
}

interface BoundedPathContext {
  paths: unknown[]
  resourceIds: string[]
  relationshipIds: string[]
  findingIds: string[]
  graphGroups: string[][]
}

function selectPathsWithFindingContext(
  paths: unknown[],
  findingById: ReadonlyMap<string, unknown>,
): BoundedPathContext {
  const selectedPaths: unknown[] = []
  const resourceIds: string[] = []
  const relationshipIds: string[] = []
  const findingIds: string[] = []
  const graphGroups: string[][] = []
  const selectedResources = new Set<string>()
  const selectedRelationships = new Set<string>()
  const selectedFindings = new Set<string>()

  for (const path of paths) {
    const pathFindingIds = recordStringArray(path, 'findingIds', 'attack path', true)
    const referencedFindings = pathFindingIds.map((id) => {
      const finding = findingById.get(id)
      if (!finding) throw new Error(`Attack path referenced unavailable finding “${id}”.`)
      return finding
    })
    const groupResourceIds = [...new Set([
      ...recordStringArray(path, 'resourceIds', 'attack path'),
      ...referencedFindings.flatMap((finding) =>
        recordStringArray(finding, 'resourceIds', 'finding')),
    ])]
    const groupRelationshipIds = [...new Set([
      ...recordStringArray(path, 'relationshipIds', 'attack path'),
      ...referencedFindings.flatMap((finding) =>
        recordStringArray(finding, 'relationshipIds', 'finding', true)),
    ])]
    const additionalResources = groupResourceIds.filter((id) => !selectedResources.has(id))
    const additionalRelationships = groupRelationshipIds.filter(
      (id) => !selectedRelationships.has(id),
    )
    const additionalFindings = pathFindingIds.filter((id) => !selectedFindings.has(id))
    if (selectedResources.size + additionalResources.length > BOUNDED_GRAPH_RESOURCE_LIMIT) continue
    if (selectedRelationships.size + additionalRelationships.length > BOUNDED_GRAPH_RELATIONSHIP_LIMIT) continue
    if (selectedFindings.size + additionalFindings.length > BOUNDED_FINDING_LIMIT) continue
    if (graphURL('snapshot', groupResourceIds).length > EXPLICIT_GRAPH_QUERY_LENGTH) continue

    selectedPaths.push(path)
    graphGroups.push(groupResourceIds)
    for (const id of additionalResources) {
      selectedResources.add(id)
      resourceIds.push(id)
    }
    for (const id of additionalRelationships) {
      selectedRelationships.add(id)
      relationshipIds.push(id)
    }
    for (const id of additionalFindings) {
      selectedFindings.add(id)
      findingIds.push(id)
    }
  }
  return { paths: selectedPaths, resourceIds, relationshipIds, findingIds, graphGroups }
}

function exactFindingBatches(snapshotId: string, findingIds: string[]): string[][] {
  const batches: string[][] = []
  let batch: string[] = []
  for (const findingId of findingIds) {
    const candidate = [...batch, findingId]
    if (batch.length > 0 && exactFindingsURL(snapshotId, candidate).length > EXPLICIT_GRAPH_QUERY_LENGTH) {
      batches.push(batch)
      batch = [findingId]
    } else {
      batch = candidate
    }
    if (exactFindingsURL(snapshotId, batch).length > EXPLICIT_GRAPH_QUERY_LENGTH) {
      throw new Error('A finding identifier exceeds the bounded request URL limit.')
    }
  }
  if (batch.length > 0) batches.push(batch)
  return batches
}

async function mapWithConcurrency<Input, Output>(
  values: Input[],
  concurrency: number,
  mapper: (value: Input) => Promise<Output>,
  signal?: AbortSignal,
): Promise<Output[]> {
  if (values.length === 0) return []
  const results = new Array<Output>(values.length)
  let cursor = 0
  let failed = false
  const worker = async (): Promise<void> => {
    while (!failed) {
      signal?.throwIfAborted()
      const index = cursor
      cursor += 1
      if (index >= values.length) return
      try {
        results[index] = await mapper(values[index]!)
      } catch (error) {
        failed = true
        throw error
      }
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, values.length) }, () => worker()),
  )
  return results
}

function clonePathWithKnownFindings(path: unknown, findingIds: Set<string>): unknown {
  const record = responseRecord(path, 'attack path')
  const referencedFindings = recordStringArray(path, 'findingIds', 'attack path', true)
  if (record.findingIds === undefined) return path
  return {
    ...record,
    findingIds: referencedFindings.filter((id) => findingIds.has(id)),
  }
}

function cloneFindingWithKnownContext(
  finding: unknown,
  resourceIds: ReadonlySet<string>,
  relationshipIds: ReadonlySet<string>,
): { finding: unknown | null; omittedReferences: number } {
  const record = responseRecord(finding, 'finding')
  const originalResources = recordStringArray(finding, 'resourceIds', 'finding')
  const originalRelationships = recordStringArray(
    finding,
    'relationshipIds',
    'finding',
    true,
  )
  const knownResources = originalResources.filter((id) => resourceIds.has(id))
  const knownRelationships = originalRelationships.filter((id) => relationshipIds.has(id))
  const omittedReferences = originalResources.length - knownResources.length
    + originalRelationships.length - knownRelationships.length
  if (knownResources.length === 0) return { finding: null, omittedReferences }
  if (omittedReferences === 0) return { finding, omittedReferences: 0 }
  return {
    finding: {
      ...record,
      resourceIds: knownResources,
      ...(record.relationshipIds === undefined ? {} : { relationshipIds: knownRelationships }),
    },
    omittedReferences,
  }
}

async function loadBoundedFromAPI(
  summary: SnapshotSummary,
  signal?: AbortSignal,
): Promise<SnapshotEnvelope> {
  const snapshotId = summary.id
  const [overviewValue, findingsValue, pathsValue] = await Promise.all([
    fetchJSON(graphURL(snapshotId), signal),
    fetchJSON(
      boundedCollectionURL('/api/v1/findings', snapshotId, BOUNDED_FINDING_LIMIT),
      signal,
    ),
    fetchJSON(
      boundedCollectionURL('/api/v1/attack-paths', snapshotId, BOUNDED_ATTACK_PATH_LIMIT),
      signal,
    ),
  ])

  const overview = parseGraphSlice(overviewValue, snapshotId)
  const findingsResponse = responseRecord(findingsValue, 'findings page')
  const pathsResponse = responseRecord(pathsValue, 'attack paths page')
  assertSnapshotResponse(findingsResponse, snapshotId, 'findings page')
  assertSnapshotResponse(pathsResponse, snapshotId, 'attack paths page')
  const findings = responseArray(findingsResponse, 'findings', 'findings page')
  const pathCandidates = responseArray(pathsResponse, 'attackPaths', 'attack paths page')
  const boundedPaths = selectBoundedPaths(pathCandidates)
  const overviewResourceIds = new Set(
    overview.resources.map((resource) => recordID(resource, 'graph resource')),
  )
  const overviewRelationshipIds = new Set(
    overview.relationships.map((relationship) => recordID(relationship, 'graph relationship')),
  )
  const pathsNeedingGraph = boundedPaths.paths.filter((path) =>
    recordStringArray(path, 'resourceIds', 'attack path').some((id) =>
      !overviewResourceIds.has(id))
    || recordStringArray(path, 'relationshipIds', 'attack path').some((id) =>
      !overviewRelationshipIds.has(id)))

  const findingById = uniqueRecordsByID(findings, 'finding')
  const missingFindingIds = boundedPaths.findingIds.filter((id) => !findingById.has(id))
  const [pathGraphs, exactFindingPages] = await Promise.all([
    mapWithConcurrency(
      explicitGraphBatches(pathsNeedingGraph),
      FOLLOW_UP_REQUEST_CONCURRENCY,
      async (ids) => parseGraphSlice(
        await fetchJSON(graphURL(snapshotId, ids), signal),
        snapshotId,
      ),
      signal,
    ),
    mapWithConcurrency(
      exactFindingBatches(snapshotId, missingFindingIds),
      FOLLOW_UP_REQUEST_CONCURRENCY,
      async (ids) => {
        const value = await fetchJSON(exactFindingsURL(snapshotId, ids), signal)
        const response = responseRecord(value, 'exact findings')
        assertSnapshotResponse(response, snapshotId, 'exact findings')
        const requested = new Set(ids)
        const records = responseArray(response, 'findings', 'exact findings')
        const indexed = uniqueRecordsByID(records, 'finding')
        for (const id of indexed.keys()) {
          if (!requested.has(id)) {
            throw new Error(`The exact findings response included unrequested finding “${id}”.`)
          }
        }
        return indexed
      },
      signal,
    ),
  ])

  for (const page of exactFindingPages) {
    for (const [id, finding] of page) findingById.set(id, finding)
  }
  for (const id of missingFindingIds) {
    if (!findingById.has(id)) {
      throw new Error(`The exact findings response omitted finding “${id}”.`)
    }
  }
  const boundedContext = selectPathsWithFindingContext(boundedPaths.paths, findingById)

  const resourceById = uniqueRecordsByID(overview.resources, 'graph resource')
  const relationshipById = uniqueRecordsByID(
    overview.relationships,
    'graph relationship',
  )
  for (const graph of pathGraphs) {
    for (const resource of graph.resources) {
      const id = recordID(resource, 'graph resource')
      resourceById.set(id, resource)
    }
    for (const relationship of graph.relationships) {
      const id = recordID(relationship, 'graph relationship')
      relationshipById.set(id, relationship)
    }
  }

  const contextGroupsNeedingGraph = boundedContext.graphGroups.filter((group, index) => {
    if (group.some((id) => !resourceById.has(id))) return true
    const path = boundedContext.paths[index]!
    const findingIds = recordStringArray(path, 'findingIds', 'attack path', true)
    const requiredRelationships = [
      ...recordStringArray(path, 'relationshipIds', 'attack path'),
      ...findingIds.flatMap((id) => recordStringArray(
        findingById.get(id),
        'relationshipIds',
        'finding',
        true,
      )),
    ]
    return requiredRelationships.some((id) => !relationshipById.has(id))
  })
  const contextGraphs = await mapWithConcurrency(
    explicitResourceBatches(contextGroupsNeedingGraph),
    FOLLOW_UP_REQUEST_CONCURRENCY,
    async (ids) => parseGraphSlice(
      await fetchJSON(graphURL(snapshotId, ids), signal),
      snapshotId,
    ),
    signal,
  )
  for (const graph of contextGraphs) {
    for (const resource of graph.resources) {
      const id = recordID(resource, 'graph resource')
      resourceById.set(id, resource)
    }
    for (const relationship of graph.relationships) {
      const id = recordID(relationship, 'graph relationship')
      relationshipById.set(id, relationship)
    }
  }

  const selectedResourceIds = new Set<string>()
  for (const id of boundedContext.resourceIds) {
    if (resourceById.has(id)) selectedResourceIds.add(id)
  }
  for (const resource of overview.resources) {
    if (selectedResourceIds.size === BOUNDED_GRAPH_RESOURCE_LIMIT) break
    selectedResourceIds.add(recordID(resource, 'graph resource'))
  }
  const selectedRelationshipIds = new Set<string>()
  const addRelationship = (id: string): void => {
    if (selectedRelationshipIds.size === BOUNDED_GRAPH_RELATIONSHIP_LIMIT) return
    const relationship = relationshipById.get(id)
    if (!relationship) return
    const record = responseRecord(relationship, 'graph relationship')
    const source = requiredString(record.source, 'graph relationship source')
    const target = requiredString(record.target, 'graph relationship target')
    if (selectedResourceIds.has(source) && selectedResourceIds.has(target)) {
      selectedRelationshipIds.add(id)
    }
  }
  for (const path of boundedContext.paths) {
    for (const id of recordStringArray(path, 'relationshipIds', 'attack path')) addRelationship(id)
  }
  for (const findingId of boundedContext.findingIds) {
    const finding = findingById.get(findingId)
    if (!finding) continue
    for (const id of recordStringArray(finding, 'relationshipIds', 'finding', true)) {
      addRelationship(id)
    }
  }
  for (const id of relationshipById.keys()) addRelationship(id)

  let omittedFindingReferences = 0
  let omittedFindings = 0
  const selectedFindings = [...findingById.values()].flatMap((finding) => {
    const selected = cloneFindingWithKnownContext(
      finding,
      selectedResourceIds,
      selectedRelationshipIds,
    )
    omittedFindingReferences += selected.omittedReferences
    if (!selected.finding) {
      omittedFindings += 1
      return []
    }
    return [selected.finding]
  })
  const selectedFindingIds = new Set(
    selectedFindings.map((finding) => recordID(finding, 'finding')),
  )
  const selectedPaths = boundedContext.paths
    .filter((path) => {
      const resourceIds = recordStringArray(path, 'resourceIds', 'attack path')
      const relationshipIds = recordStringArray(path, 'relationshipIds', 'attack path')
      return resourceIds.every((id) => selectedResourceIds.has(id))
        && relationshipIds.every((id) => selectedRelationshipIds.has(id))
    })
    .map((path) => clonePathWithKnownFindings(path, selectedFindingIds))

  const snapshot = parseSnapshot({
    schemaVersion: '1.0',
    id: snapshotId,
    name: summary.name,
    provider: summary.provider,
    generatedAt: summary.generatedAt,
    resources: [...selectedResourceIds].map((id) => resourceById.get(id)),
    relationships: [...selectedRelationshipIds].map((id) => relationshipById.get(id)),
    findings: selectedFindings,
    attackPaths: selectedPaths,
    riskScore: summary.riskScore,
    analysis: pathsResponse.analysis,
  })
  const count = (value: number): string => value.toLocaleString('en-US')
  const omittedFindingMessage = omittedFindings > 0
    ? `${count(omittedFindings)} finding${omittedFindings === 1 ? ' was' : 's were'} omitted and `
    : ''
  const partialContext = omittedFindingReferences > 0
    ? ` ${omittedFindingMessage}${count(omittedFindingReferences)} finding context reference${omittedFindingReferences === 1 ? ' was' : 's were'} omitted because the referenced graph data was outside this bounded response.`
    : ''
  const notice = `Performance view: showing an attack-path-prioritized slice of ${count(snapshot.resources.length)} of ${count(summary.resourceCount)} resources, ${count(snapshot.relationships.length)} of ${count(summary.relationshipCount)} relationships, ${count(snapshot.findings.length)} of ${count(summary.findingCount)} findings, and ${count(snapshot.attackPaths.length)} of ${count(summary.attackPathCount)} attack paths.${partialContext} The complete snapshot remains in the local workspace.`
  return { snapshot, source: 'api', notice }
}

export async function loadAPIWorkspace(signal?: AbortSignal): Promise<WorkspaceLoadResult> {
  const [sessionAttempt, catalogAttempt, bootstrapAttempt] = await Promise.allSettled([
    fetchJSON(`${apiBase()}/api/v1/session`, signal),
    fetchJSON(`${apiBase()}/api/v1/snapshots`, signal),
    fetchJSON(`${apiBase()}/api/v1/bootstrap`, signal),
  ])
  let csrfToken: string | undefined
  if (sessionAttempt.status === 'fulfilled') {
    csrfToken = parseSession(sessionAttempt.value).csrfToken
  } else if (!(sessionAttempt.reason instanceof HTTPError) || sessionAttempt.reason.status !== 404) {
    throw sessionAttempt.reason
  }

  if (bootstrapAttempt.status === 'fulfilled') {
    const bootstrap = parseBootstrap(bootstrapAttempt.value)
    return { bootstrap: { ...bootstrap, csrfToken } }
  }
  if (!(bootstrapAttempt.reason instanceof HTTPError) || bootstrapAttempt.reason.status !== 404) {
    if (catalogAttempt.status === 'rejected') throw bootstrapAttempt.reason
  }

  if (catalogAttempt.status === 'fulfilled') {
    return { bootstrap: parseCatalog(catalogAttempt.value, csrfToken) }
  }
  if (!(catalogAttempt.reason instanceof HTTPError) || catalogAttempt.reason.status !== 404) {
    throw catalogAttempt.reason
  }

  // Backward-compatible discovery: the v1 health endpoint exposes the active
  // ID even before catalog/history endpoints are available.
  const health = await fetchJSON(`${apiBase()}/healthz`, signal)
  if (typeof health !== 'object' || health === null) throw new Error('Invalid health response.')
  const snapshotId = requiredString((health as Record<string, unknown>).snapshotId, 'active snapshot id')
  const snapshot = await loadFromAPI(snapshotId, signal)
  return {
    bootstrap: {
      snapshots: [summarizeSnapshot(snapshot, 'api')],
      currentSnapshotId: snapshot.id,
      source: 'api',
      capabilities: {
        history: false,
        comparison: false,
        import: false,
        triage: false,
        azureScans: false,
      },
      csrfToken,
    },
    initialSnapshot: { snapshot, source: 'api' },
  }
}

export async function loadWorkspace(signal?: AbortSignal): Promise<WorkspaceLoadResult> {
  if (isAPIMode()) {
    try {
      return await loadAPIWorkspace(signal)
    } catch (error) {
      if (signal?.aborted) throw error
      if (error instanceof WorkspaceSessionExpiredError) throw error
      const snapshot = await loadFixture(signal)
      const notice = 'The local API is unavailable. Showing the safe public fixture instead.'
      return {
        bootstrap: {
          snapshots: [summarizeSnapshot(snapshot, 'demo')],
          currentSnapshotId: snapshot.id,
          source: 'fixture-fallback',
          capabilities: {
            history: false,
            comparison: false,
            import: true,
            triage: false,
            azureScans: false,
          },
          notice,
        },
        initialSnapshot: { snapshot, source: 'fixture-fallback', notice },
      }
    }
  }

  const snapshot = await loadFixture(signal)
  return {
    bootstrap: {
      snapshots: [summarizeSnapshot(snapshot, 'demo')],
      currentSnapshotId: snapshot.id,
      source: 'fixture',
      capabilities: {
        history: false,
        comparison: false,
        import: true,
        triage: false,
        azureScans: false,
      },
    },
    initialSnapshot: { snapshot, source: 'fixture' },
  }
}

export async function loadSnapshotById(
  summary: SnapshotSummary,
  signal?: AbortSignal,
): Promise<SnapshotEnvelope> {
  if (summary.origin === 'api') {
    if (summary.resourceCount > FULL_SNAPSHOT_RESOURCE_LIMIT
      || summary.relationshipCount > FULL_SNAPSHOT_RELATIONSHIP_LIMIT) {
      return loadBoundedFromAPI(summary, signal)
    }
    return { snapshot: await loadFromAPI(summary.id, signal), source: 'api' }
  }
  if (summary.origin === 'demo') return { snapshot: await loadFixture(signal), source: 'fixture' }
  throw new Error('Imported snapshots are held in local memory and must be selected from the workspace cache.')
}

export async function persistImportedSnapshot(
  snapshot: Snapshot,
  csrfToken: string,
  signal?: AbortSignal,
): Promise<SnapshotSummary> {
  const url = `${apiBase()}/api/v1/snapshots`
  const response = await fetch(url, {
    method: 'POST',
    signal,
    headers: requestHeaders(url, {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Atlas-CSRF-Token': csrfToken,
    }),
    body: JSON.stringify({ snapshot }),
  })
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null
    throw responseError(
      url,
      response.status,
      payload?.error ?? `Snapshot import failed with status ${response.status}.`,
    )
  }
  return parseSummary(await response.json())
}

export async function persistAndLoadImportedSnapshot(
  snapshot: Snapshot,
  csrfToken: string,
  signal?: AbortSignal,
): Promise<{ summary: SnapshotSummary; envelope: SnapshotEnvelope }> {
  const summary = await persistImportedSnapshot(snapshot, csrfToken, signal)
  const envelope = await loadSnapshotById(summary, signal)
  return { summary, envelope }
}

export async function parseImportedSnapshot(file: File): Promise<Snapshot> {
  if (file.size > 64 * 1024 * 1024) throw new Error('Snapshot files must be 64 MB or smaller.')
  let payload: unknown
  try {
    payload = JSON.parse(await file.text())
  } catch {
    throw new Error('The selected file is not valid JSON.')
  }
  return parseSnapshot(payload)
}

export function compareSnapshots(base: Snapshot, target: Snapshot): SnapshotComparison {
  const baseResources = new Set(base.resources.map((resource) => resource.id))
  const targetResources = new Set(target.resources.map((resource) => resource.id))
  return {
    baseSnapshotId: base.id,
    targetSnapshotId: target.id,
    riskScoreDelta: target.riskScore - base.riskScore,
    resourceDelta: target.resources.length - base.resources.length,
    findingDelta: target.findings.length - base.findings.length,
    attackPathDelta: target.attackPaths.length - base.attackPaths.length,
    addedResourceIds: target.resources.filter((resource) => !baseResources.has(resource.id)).map((resource) => resource.id),
    removedResourceIds: base.resources.filter((resource) => !targetResources.has(resource.id)).map((resource) => resource.id),
  }
}

export async function loadServerComparison(
  baseSnapshotId: string,
  targetSnapshotId: string,
  signal?: AbortSignal,
): Promise<SnapshotComparison> {
  const query = new URLSearchParams({ base: baseSnapshotId, target: targetSnapshotId })
  const payload = await fetchJSON(`${apiBase()}/api/v1/comparisons?${query}`, signal)
  if (typeof payload !== 'object' || payload === null) throw new Error('Invalid comparison response.')
  const value = payload as Record<string, unknown>
  const difference = (key: string): { delta: number; added: string[]; removed: string[] } => {
    const nested = typeof value[key] === 'object' && value[key] !== null
      ? value[key] as Record<string, unknown>
      : {}
    const added = Array.isArray(nested.added)
      ? nested.added.filter((id): id is string => typeof id === 'string')
      : []
    const removed = Array.isArray(nested.removed)
      ? nested.removed.filter((id): id is string => typeof id === 'string')
      : []
    return { delta: added.length - removed.length, added, removed }
  }
  const resources = difference('resources')
  const findings = difference('findings')
  const paths = difference('attackPaths')
  return {
    baseSnapshotId,
    targetSnapshotId,
    riskScoreDelta: finiteNumber(value.riskScoreDelta),
    resourceDelta: finiteNumber(value.resourceDelta, resources.delta),
    findingDelta: finiteNumber(value.findingDelta, findings.delta),
    attackPathDelta: finiteNumber(value.attackPathDelta, paths.delta),
    addedResourceIds: Array.isArray(value.addedResourceIds)
      ? value.addedResourceIds.filter((id): id is string => typeof id === 'string')
      : resources.added,
    removedResourceIds: Array.isArray(value.removedResourceIds)
      ? value.removedResourceIds.filter((id): id is string => typeof id === 'string')
      : resources.removed,
  }
}

function parseCompactSimulation(
  value: unknown,
  requestedChanges: SimulationChange[],
): SimulationImpact {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('The simulation endpoint returned an invalid impact summary.')
  }
  const candidate = value as Record<string, unknown>
  if (!Array.isArray(candidate.removedAttackPathIds)
    || candidate.removedAttackPathIds.some((id) => typeof id !== 'string')) {
    throw new Error('Invalid removed attack path identifiers.')
  }
  const removedAttackPathIds = candidate.removedAttackPathIds as string[]
  const remainingAttackPathCount = requiredFiniteNumber(
    candidate.remainingAttackPathCount,
    'remaining attack path count',
  )
  if (!Number.isSafeInteger(remainingAttackPathCount) || remainingAttackPathCount < 0) {
    throw new Error('Invalid remaining attack path count.')
  }
  return {
    snapshotId: requiredString(candidate.snapshotId, 'simulation snapshot id'),
    changes: requestedChanges,
    removedAttackPathIds,
    remainingAttackPathCount,
    riskScoreBefore: requiredFiniteNumber(candidate.riskScoreBefore, 'simulation risk score before'),
    riskScoreAfter: requiredFiniteNumber(candidate.riskScoreAfter, 'simulation risk score after'),
  }
}

function simulationImpact(result: SimulationResult): SimulationImpact {
  return {
    snapshotId: result.snapshotId,
    changes: result.changes,
    removedAttackPathIds: result.removedAttackPathIds,
    remainingAttackPathCount: result.remainingAttackPaths.length,
    riskScoreBefore: result.riskScoreBefore,
    riskScoreAfter: result.riskScoreAfter,
  }
}

export async function runSimulation(
  snapshotId: string,
  changes: SimulationChange[],
  signal?: AbortSignal,
  csrfToken?: string,
): Promise<SimulationImpact> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  }
  if (csrfToken) headers['X-Atlas-CSRF-Token'] = csrfToken
  const url = `${apiBase()}/api/v1/simulations`
  const response = await fetch(url, {
    method: 'POST',
    signal,
    headers: requestHeaders(url, headers),
    body: JSON.stringify(csrfToken
      ? { snapshotId, changes, compact: true }
      : { snapshotId, changes }),
  })
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null
    throw responseError(
      url,
      response.status,
      payload?.error ?? `Simulation request failed with status ${response.status}.`,
    )
  }
  try {
    const payload = await response.json() as unknown
    const result = typeof payload === 'object' && payload !== null && 'resultingSnapshot' in payload
      ? simulationImpact(parseSimulationResult(payload))
      : parseCompactSimulation(payload, changes)
    if (result.snapshotId !== snapshotId) {
      throw new Error('The simulation response referenced a different snapshot.')
    }
    return result
  } catch (error) {
    if (error instanceof Error) throw error
    throw new Error('The simulation endpoint returned invalid JSON.', { cause: error })
  }
}

const scanStatuses = new Set([
  'queued',
  'running',
  'completed',
  'failed',
  'cancelled',
  'interrupted',
])
const triageStatuses = new Set(['open', 'acknowledged', 'accepted-risk', 'resolved'])

function scanStatus(value: unknown): AzureScanJob['status'] {
  if (typeof value !== 'string' || !scanStatuses.has(value)) throw new Error('Invalid scan status.')
  return value as AzureScanJob['status']
}

function parseScanJob(value: unknown): AzureScanJob {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid Azure scan job response.')
  }
  const candidate = value as Record<string, unknown>
  const scope = typeof candidate.scope === 'object' && candidate.scope !== null
    ? candidate.scope as Record<string, unknown>
    : {}
  return {
    id: requiredString(candidate.id, 'scan job id'),
    provider: requiredString(candidate.provider, 'scan provider'),
    scope: {
      subscriptionId: requiredString(scope.subscriptionId, 'scan subscription id'),
      resourceGroup: typeof scope.resourceGroup === 'string' && scope.resourceGroup !== ''
        ? scope.resourceGroup
        : undefined,
    },
    status: scanStatus(candidate.status),
    phase: requiredString(candidate.phase, 'scan phase'),
    error: typeof candidate.error === 'string' && candidate.error !== '' ? candidate.error : undefined,
    snapshotId: typeof candidate.snapshotId === 'string' && candidate.snapshotId !== ''
      ? candidate.snapshotId
      : undefined,
    revision: requiredFiniteNumber(candidate.revision, 'scan revision'),
    createdAt: requiredString(candidate.createdAt, 'scan creation time'),
    startedAt: typeof candidate.startedAt === 'string' ? candidate.startedAt : undefined,
    updatedAt: requiredString(candidate.updatedAt, 'scan update time'),
    completedAt: typeof candidate.completedAt === 'string' ? candidate.completedAt : undefined,
  }
}

function parseScanEvent(value: unknown): AzureScanEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid Azure scan progress event.')
  }
  const candidate = value as Record<string, unknown>
  return {
    sequence: requiredFiniteNumber(candidate.sequence, 'scan event sequence'),
    jobId: requiredString(candidate.jobId, 'scan event job id'),
    status: scanStatus(candidate.status),
    phase: requiredString(candidate.phase, 'scan event phase'),
    message: typeof candidate.message === 'string' ? candidate.message : undefined,
    createdAt: requiredString(candidate.createdAt, 'scan event creation time'),
  }
}

function isTerminalScan(status: AzureScanJob['status']): boolean {
  return status === 'completed'
    || status === 'failed'
    || status === 'cancelled'
    || status === 'interrupted'
}

export async function startAzureScan(
  scope: AzureScanScope,
  csrfToken: string,
  signal?: AbortSignal,
): Promise<{ jobId: string; status: AzureScanJob['status'] }> {
  const url = `${apiBase()}/api/v1/scans/azure`
  const response = await fetch(url, {
    method: 'POST',
    signal,
    headers: requestHeaders(url, {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Atlas-CSRF-Token': csrfToken,
    }),
    body: JSON.stringify({
      subscriptionId: scope.subscriptionId.trim(),
      ...(scope.resourceGroup?.trim() ? { resourceGroup: scope.resourceGroup.trim() } : {}),
    }),
  })
  const payload = await response.json().catch(() => null) as Record<string, unknown> | null
  if (!response.ok) {
    throw responseError(
      url,
      response.status,
      typeof payload?.error === 'string'
        ? payload.error
        : `Azure scan request failed with status ${response.status}.`,
    )
  }
  return {
    jobId: requiredString(payload?.jobId, 'scan job id'),
    status: scanStatus(payload?.status),
  }
}

export async function getAzureScanJob(
  jobId: string,
  signal?: AbortSignal,
): Promise<AzureScanJob> {
  return parseScanJob(await fetchJSON(
    `${apiBase()}/api/v1/scans/${encodeURIComponent(jobId)}`,
    signal,
  ))
}

export async function cancelAzureScan(
  jobId: string,
  csrfToken: string,
  signal?: AbortSignal,
): Promise<void> {
  const url = `${apiBase()}/api/v1/scans/${encodeURIComponent(jobId)}`
  const response = await fetch(url, {
    method: 'DELETE',
    signal,
    headers: requestHeaders(url, {
      Accept: 'application/json',
      'X-Atlas-CSRF-Token': csrfToken,
    }),
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string } | null
    throw responseError(
      url,
      response.status,
      payload?.error ?? `Scan cancellation failed with status ${response.status}.`,
    )
  }
}

async function streamAzureScanEvents(
  jobId: string,
  onEvent: (event: AzureScanEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const url = `${apiBase()}/api/v1/scans/${encodeURIComponent(jobId)}/events`
  const response = await fetch(url, {
    signal,
    headers: requestHeaders(url, { Accept: 'text/event-stream' }),
  })
  if (!response.ok) {
    throw responseError(
      url,
      response.status,
      `Scan event stream failed with status ${response.status}.`,
    )
  }
  if (!response.body) throw new Error('Scan event streaming is unavailable.')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  const dispatch = (frame: string): void => {
    let eventName = 'message'
    const data: string[] = []
    for (const line of frame.split('\n')) {
      if (line.startsWith('event:')) eventName = line.slice(6).trim()
      if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
    }
    if (eventName !== 'progress' || data.length === 0) return
    const event = parseScanEvent(JSON.parse(data.join('\n')))
    if (event.jobId !== jobId) throw new Error('Scan event referenced a different job.')
    onEvent(event)
  }

  try {
    while (true) {
      const { value, done } = await reader.read()
      buffer += decoder.decode(value, { stream: !done })
      buffer = buffer.replace(/\r\n/g, '\n')
      let boundary = buffer.indexOf('\n\n')
      while (boundary >= 0) {
        dispatch(buffer.slice(0, boundary))
        buffer = buffer.slice(boundary + 2)
        boundary = buffer.indexOf('\n\n')
      }
      if (done) {
        if (buffer.trim()) dispatch(buffer)
        return
      }
    }
  } finally {
    reader.releaseLock()
  }
}

export function monitorAzureScan(
  jobId: string,
  handlers: {
    onJob: (job: AzureScanJob) => void
    onEvent: (event: AzureScanEvent) => void
    onTransport: (transport: 'events' | 'polling') => void
    onError: (error: Error) => void
  },
  signal: AbortSignal,
): () => void {
  let streamController: AbortController | null = null
  let timer: number | undefined
  let stopped = false
  let polling = false

  const stop = () => {
    if (stopped) return
    stopped = true
    streamController?.abort()
    if (timer !== undefined) window.clearTimeout(timer)
    signal.removeEventListener('abort', stop)
  }

  const poll = async () => {
    if (stopped) return
    try {
      const job = await getAzureScanJob(jobId, signal)
      if (stopped) return
      handlers.onJob(job)
      if (isTerminalScan(job.status)) {
        stop()
        return
      }
    } catch (error) {
      if (!signal.aborted) {
        const reason = error instanceof Error ? error : new Error('Scan polling failed.')
        handlers.onError(reason)
        if (reason instanceof WorkspaceSessionExpiredError) {
          stop()
          return
        }
      }
    }
    if (!stopped) timer = window.setTimeout(() => { void poll() }, 900)
  }

  const startPolling = () => {
    if (stopped || polling) return
    polling = true
    streamController?.abort()
    handlers.onTransport('polling')
    void poll()
  }

  const connect = async () => {
    try {
      const job = await getAzureScanJob(jobId, signal)
      if (stopped) return
      handlers.onJob(job)
      if (isTerminalScan(job.status)) {
        stop()
        return
      }
    } catch (error) {
      if (!signal.aborted) {
        const reason = error instanceof Error ? error : new Error('Scan status failed.')
        handlers.onError(reason)
        if (reason instanceof WorkspaceSessionExpiredError) {
          stop()
          return
        }
      }
      startPolling()
      return
    }

    handlers.onTransport('events')
    streamController = new AbortController()
    try {
      await streamAzureScanEvents(jobId, (event) => {
        if (stopped) return
        handlers.onEvent(event)
      }, streamController.signal)
      if (!stopped) startPolling()
    } catch (error) {
      if (stopped || signal.aborted) return
      const reason = error instanceof Error ? error : new Error('Scan event streaming failed.')
      if (!(reason instanceof DOMException && reason.name === 'AbortError')) {
        handlers.onError(reason)
      }
      if (reason instanceof WorkspaceSessionExpiredError) {
        stop()
        return
      }
      startPolling()
    }
  }

  signal.addEventListener('abort', stop, { once: true })
  void connect()
  return stop
}

function parseTriageRecord(value: unknown): TriageRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid finding triage record.')
  }
  const candidate = value as Record<string, unknown>
  const status = candidate.status
  if (typeof status !== 'string' || !triageStatuses.has(status)) {
    throw new Error('Invalid finding triage status.')
  }
  return {
    snapshotId: requiredString(candidate.snapshotId, 'triage snapshot id'),
    environmentId: requiredString(candidate.environmentId, 'triage environment id'),
    findingId: requiredString(candidate.findingId, 'triage finding id'),
    fingerprint: requiredString(candidate.fingerprint, 'triage fingerprint'),
    status: status as TriageStatus,
    notes: typeof candidate.notes === 'string' ? candidate.notes : '',
    firstSeenSnapshotId: requiredString(candidate.firstSeenSnapshotId, 'triage first snapshot id'),
    lastSeenSnapshotId: requiredString(candidate.lastSeenSnapshotId, 'triage last snapshot id'),
    updatedAt: requiredString(candidate.updatedAt, 'triage update time'),
  }
}

export async function loadTriage(
  snapshotId: string,
  signal?: AbortSignal,
): Promise<TriageRecord[]> {
  const query = new URLSearchParams({ snapshot_id: snapshotId })
  const payload = await fetchJSON(`${apiBase()}/api/v1/triage?${query}`, signal)
  if (typeof payload !== 'object' || payload === null || !Array.isArray((payload as Record<string, unknown>).triage)) {
    throw new Error('Invalid finding triage response.')
  }
  return ((payload as Record<string, unknown>).triage as unknown[]).map(parseTriageRecord)
}

export async function updateTriage(
  snapshotId: string,
  findingId: string,
  status: TriageStatus,
  notes: string,
  csrfToken: string,
  signal?: AbortSignal,
): Promise<TriageRecord> {
  const url = `${apiBase()}/api/v1/triage`
  const response = await fetch(url, {
    method: 'PATCH',
    signal,
    headers: requestHeaders(url, {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Atlas-CSRF-Token': csrfToken,
    }),
    body: JSON.stringify({ snapshotId, findingId, status, notes }),
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string } | null
    throw responseError(
      url,
      response.status,
      payload?.error ?? `Triage update failed with status ${response.status}.`,
    )
  }
  return parseTriageRecord(await response.json())
}
