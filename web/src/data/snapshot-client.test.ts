import { afterEach, describe, expect, it, vi } from 'vitest'
import { demoSnapshot } from '../test/fixture'
import {
  cancelAzureScan,
  loadAPIWorkspace,
  loadSnapshotById,
  loadServerComparison,
  loadTriage,
  loadWorkspace,
  monitorAzureScan,
  persistAndLoadImportedSnapshot,
  persistImportedSnapshot,
  runSimulation,
  startAzureScan,
  updateTriage,
  WorkspaceSessionExpiredError,
} from './snapshot-client'

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

describe('workspace API client', () => {
  it('bootstraps the CSRF session and snapshot catalog', async () => {
    const accessToken = 'A'.repeat(43)
    window.history.replaceState({}, '', `/#atlas-session=${accessToken}`)
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void init
      const url = String(input)
      if (url.endsWith('/api/v1/session')) return jsonResponse({ csrfToken: 'local-token' })
      if (url.endsWith('/api/v1/bootstrap')) {
        return jsonResponse({
          currentSnapshotId: demoSnapshot.id,
          snapshots: [
            {
              id: demoSnapshot.id,
              environmentId: 'azure-production',
              name: demoSnapshot.name,
              provider: demoSnapshot.provider,
              generatedAt: demoSnapshot.generatedAt,
              riskScore: demoSnapshot.riskScore,
              resourceCount: demoSnapshot.resources.length,
              relationshipCount: demoSnapshot.relationships.length,
              findingCount: demoSnapshot.findings.length,
              attackPathCount: demoSnapshot.attackPaths.length,
            },
          ],
          capabilities: {
            history: false,
            comparison: true,
            import: true,
            triage: true,
            azureScans: true,
          },
        })
      }
      if (url.endsWith('/api/v1/snapshots')) {
        return jsonResponse({
          snapshots: [
            {
              id: demoSnapshot.id,
              name: demoSnapshot.name,
              provider: demoSnapshot.provider,
              generatedAt: demoSnapshot.generatedAt,
              riskScore: demoSnapshot.riskScore,
              resourceCount: demoSnapshot.resources.length,
              relationshipCount: demoSnapshot.relationships.length,
              findingCount: demoSnapshot.findings.length,
              attackPathCount: demoSnapshot.attackPaths.length,
            },
          ],
        })
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadAPIWorkspace()

    expect(result.bootstrap.currentSnapshotId).toBe(demoSnapshot.id)
    expect(result.bootstrap.snapshots[0]?.environmentId).toBe('azure-production')
    expect(result.bootstrap.csrfToken).toBe('local-token')
    expect(result.bootstrap.capabilities).toEqual({
      history: false,
      comparison: true,
      import: true,
      triage: true,
      azureScans: true,
    })
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(window.location.hash).toBe('')
    for (const call of fetchMock.mock.calls) {
      expect(new Headers(call[1]?.headers).get('X-Atlas-Session-Token')).toBe(accessToken)
    }
  })

  it('does not replace an expired API session with the public fixture', async () => {
    vi.stubEnv('VITE_DATA_SOURCE', 'api')
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      void input
      return jsonResponse({ error: 'unauthorized' }, 401)
    })
    vi.stubGlobal('fetch', fetchMock)

    const request = loadWorkspace()
    await expect(request).rejects.toBeInstanceOf(WorkspaceSessionExpiredError)
    await expect(request).rejects.toThrow(/reopen the private URL printed by Atlas/i)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls.every(([input]) => !String(input).includes('contoso-health.json')))
      .toBe(true)
  })

  it('normalizes the nested comparison contract', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({
      baseSnapshotId: 'before',
      targetSnapshotId: 'after',
      riskScoreDelta: -18,
      resources: { added: ['new'], removed: ['old-a', 'old-b'] },
      findings: { added: [], removed: ['finding-a'] },
      attackPaths: { added: [], removed: ['path-a', 'path-b'] },
    })))

    const result = await loadServerComparison('before', 'after')

    expect(result).toMatchObject({
      riskScoreDelta: -18,
      resourceDelta: -1,
      findingDelta: -1,
      attackPathDelta: -2,
      addedResourceIds: ['new'],
      removedResourceIds: ['old-a', 'old-b'],
    })
  })

  it('loads the complete portable snapshot when it fits the graph budget', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      void input
      return jsonResponse({ data: demoSnapshot })
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: demoSnapshot.resources.length,
      relationshipCount: demoSnapshot.relationships.length,
      findingCount: demoSnapshot.findings.length,
      attackPathCount: demoSnapshot.attackPaths.length,
      origin: 'api',
    })

    expect(result).toEqual({ snapshot: demoSnapshot, source: 'api' })
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
      `/api/v1/snapshots/${encodeURIComponent(demoSnapshot.id)}`,
    )
  })

  it('assembles a coherent attack-path-prioritized slice for a large snapshot', async () => {
    const originalPath = demoSnapshot.attackPaths[0]!
    const originalPathFinding = demoSnapshot.findings.find((finding) =>
      originalPath.findingIds?.includes(finding.id))!
    const pathFinding = {
      ...originalPathFinding,
      id: 'finding/outside first page ? owner=platform & region=eu',
    }
    const path = { ...originalPath, findingIds: [pathFinding.id] }
    const pathResourceIds = new Set(path.resourceIds)
    const pathRelationshipIds = new Set(path.relationshipIds)
    const pathResources = demoSnapshot.resources.filter((resource) => pathResourceIds.has(resource.id))
    const pathRelationships = demoSnapshot.relationships.filter((relationship) =>
      pathRelationshipIds.has(relationship.id))
    const overviewResources = Array.from({ length: 500 }, (_, index) => ({
      id: `overview-${String(index).padStart(3, '0')}`,
      name: `Overview resource ${index}`,
      type: 'Microsoft.Resources/resourceGroups',
      category: 'scope',
      provider: 'azure',
      criticality: 'low' as const,
    }))
    const unrelatedFinding = demoSnapshot.findings.find((finding) =>
      finding.id !== pathFinding.id)!
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname.endsWith('/graph')) {
        expect(url.searchParams.get('limit')).toBe('500')
        expect(url.searchParams.get('relationship_limit')).toBe('2000')
      }
      if (url.pathname.endsWith('/graph') && url.searchParams.has('resource_id')) {
        expect(url.searchParams.getAll('resource_id')).toEqual(path.resourceIds)
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: pathResources,
          relationships: pathRelationships,
          truncated: false,
        })
      }
      if (url.pathname.endsWith('/graph')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: overviewResources,
          relationships: [],
          truncated: true,
          totalResources: 5_000,
        })
      }
      if (url.pathname.endsWith('/findings')) {
        if (url.searchParams.has('finding_id')) {
          expect(url.searchParams.get('snapshot_id')).toBe(demoSnapshot.id)
          expect(url.searchParams.getAll('finding_id')).toEqual([pathFinding.id])
          return jsonResponse({
            snapshotId: demoSnapshot.id,
            findings: [pathFinding],
            page: 1,
            pageSize: 1,
            total: 1,
          })
        }
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          findings: [unrelatedFinding],
          page: 1,
          pageSize: 200,
          total: 201,
        })
      }
      if (url.pathname.endsWith('/attack-paths')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          attackPaths: [path],
          page: 1,
          pageSize: 100,
          total: 1,
          analysis: demoSnapshot.analysis,
        })
      }
      return jsonResponse({ error: 'full snapshot should not be requested' }, 500)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: 5_000,
      relationshipCount: 20_000,
      findingCount: 2,
      attackPathCount: 1,
      origin: 'api',
    })

    expect(result.snapshot.resources).toHaveLength(500)
    expect(result.snapshot.resources.slice(0, path.resourceIds.length).map((resource) =>
      resource.id)).toEqual(path.resourceIds)
    expect(result.snapshot.resources.some((resource) => resource.id === 'overview-494')).toBe(true)
    expect(result.snapshot.resources.some((resource) => resource.id === 'overview-495')).toBe(false)
    expect(result.snapshot.attackPaths).toEqual([path])
    expect(result.snapshot.findings).toEqual([pathFinding])
    expect(result.notice).toContain('500 of 5,000 resources')
    expect(result.notice).toContain('4 of 20,000 relationships')
    expect(result.notice).toContain('attack-path-prioritized')
    const knownResources = new Set(result.snapshot.resources.map((resource) => resource.id))
    const knownRelationships = new Set(
      result.snapshot.relationships.map((relationship) => relationship.id),
    )
    expect(result.snapshot.relationships.every((relationship) =>
      knownResources.has(relationship.source) && knownResources.has(relationship.target))).toBe(true)
    expect(result.snapshot.findings.every((finding) =>
      finding.resourceIds.every((id) => knownResources.has(id))
      && (finding.relationshipIds ?? []).every((id) => knownRelationships.has(id)))).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) =>
      String(input).endsWith(`/api/v1/snapshots/${demoSnapshot.id}`))).toBe(false)
  })

  it('loads a path graph when overview nodes exist but a path relationship is missing', async () => {
    const path = demoSnapshot.attackPaths[0]!
    const resources = demoSnapshot.resources.filter((resource) =>
      path.resourceIds.includes(resource.id))
    const relationships = demoSnapshot.relationships.filter((relationship) =>
      path.relationshipIds.includes(relationship.id))
    const finding = demoSnapshot.findings.find((candidate) =>
      path.findingIds?.includes(candidate.id))!
    let explicitGraphRequests = 0
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname.endsWith('/graph') && url.searchParams.has('resource_id')) {
        explicitGraphRequests += 1
        expect(url.searchParams.getAll('resource_id')).toEqual(path.resourceIds)
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources,
          relationships,
        })
      }
      if (url.pathname.endsWith('/graph')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources,
          relationships: [],
          truncated: true,
        })
      }
      if (url.pathname.endsWith('/findings')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, findings: [finding], total: 1 })
      }
      if (url.pathname.endsWith('/attack-paths')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, attackPaths: [path], total: 1 })
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: 5_000,
      relationshipCount: 20_000,
      findingCount: 1,
      attackPathCount: 1,
      origin: 'api',
    })

    expect(explicitGraphRequests).toBe(1)
    expect(result.snapshot.attackPaths).toEqual([path])
    expect(result.snapshot.relationships.map((relationship) => relationship.id)).toEqual(
      path.relationshipIds,
    )
  })

  it('loads graph context referenced by a path-linked finding outside the path', async () => {
    const originalPath = demoSnapshot.attackPaths[0]!
    const originalFinding = demoSnapshot.findings.find((finding) =>
      originalPath.findingIds?.includes(finding.id))!
    const pathResources = demoSnapshot.resources.filter((resource) =>
      originalPath.resourceIds.includes(resource.id))
    const pathRelationships = demoSnapshot.relationships.filter((relationship) =>
      originalPath.relationshipIds.includes(relationship.id))
    const contextResource = demoSnapshot.resources.find((resource) =>
      !originalPath.resourceIds.includes(resource.id))!
    const contextRelationship = {
      id: 'finding-context-relationship',
      source: originalPath.resourceIds[0]!,
      target: contextResource.id,
      type: 'finding-context',
      label: 'supports finding evidence',
      exploitable: false,
    }
    const finding = {
      ...originalFinding,
      id: 'path-finding-with-context',
      resourceIds: [...originalFinding.resourceIds, contextResource.id],
      relationshipIds: [
        ...(originalFinding.relationshipIds ?? []),
        contextRelationship.id,
      ],
    }
    const path = { ...originalPath, findingIds: [finding.id] }
    let contextGraphRequests = 0
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname.endsWith('/graph') && url.searchParams.has('resource_id')) {
        contextGraphRequests += 1
        const requested = new Set(url.searchParams.getAll('resource_id'))
        expect(requested.has(contextResource.id)).toBe(true)
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: [...pathResources, contextResource].filter((resource) =>
            requested.has(resource.id)),
          relationships: [...pathRelationships, contextRelationship].filter((relationship) =>
            requested.has(relationship.source) && requested.has(relationship.target)),
        })
      }
      if (url.pathname.endsWith('/graph')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: pathResources,
          relationships: pathRelationships,
          truncated: true,
        })
      }
      if (url.pathname.endsWith('/findings') && url.searchParams.has('finding_id')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, findings: [finding], total: 1 })
      }
      if (url.pathname.endsWith('/findings')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, findings: [], total: 201 })
      }
      if (url.pathname.endsWith('/attack-paths')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, attackPaths: [path], total: 1 })
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: 5_000,
      relationshipCount: 20_000,
      findingCount: 201,
      attackPathCount: 1,
      origin: 'api',
    })

    expect(contextGraphRequests).toBe(1)
    expect(result.snapshot.findings).toEqual([finding])
    expect(result.snapshot.resources.some((resource) => resource.id === contextResource.id)).toBe(true)
    expect(result.snapshot.relationships.some((relationship) =>
      relationship.id === contextRelationship.id)).toBe(true)
    expect(result.notice).not.toContain('finding context reference')
  })

  it('uses bounded endpoints for a dense snapshot with few resources', async () => {
    const resource = demoSnapshot.resources[0]!
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname.endsWith('/graph')) {
        expect(url.searchParams.get('relationship_limit')).toBe('2000')
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: [resource],
          relationships: [],
          truncated: true,
          totalResources: 1,
        })
      }
      if (url.pathname.endsWith('/findings')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, findings: [], total: 0 })
      }
      if (url.pathname.endsWith('/attack-paths')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, attackPaths: [], total: 0 })
      }
      return jsonResponse({ error: 'full snapshot should not be requested' }, 500)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: 1,
      relationshipCount: 2_001,
      findingCount: 0,
      attackPathCount: 0,
      origin: 'api',
    })

    expect(result.snapshot.resources).toEqual([resource])
    expect(result.notice).toContain('0 of 2,001 relationships')
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('caps concurrent follow-up graph requests while keeping each URL bounded', async () => {
    const resources = Array.from({ length: 12 }, (_, index) => {
      const prefix = `resource-${index}-${'x'.repeat(1_700)}`
      return [
        {
          id: `${prefix}-source`, name: `Source ${index}`, type: 'test/source',
          category: 'compute', provider: 'azure', criticality: 'medium' as const,
        },
        {
          id: `${prefix}-target`, name: `Target ${index}`, type: 'test/target',
          category: 'data', provider: 'azure', criticality: 'high' as const,
        },
      ]
    }).flat()
    const relationships = Array.from({ length: 12 }, (_, index) => ({
      id: `relationship-${index}`,
      source: resources[index * 2]!.id,
      target: resources[index * 2 + 1]!.id,
      type: 'dependency',
      label: 'reaches',
      exploitable: true,
    }))
    const paths = relationships.map((relationship, index) => ({
      id: `path-${index}`,
      title: `Path ${index}`,
      description: 'Concurrency fixture.',
      severity: 'high' as const,
      score: 80,
      entryPoint: relationship.source,
      target: relationship.target,
      resourceIds: [relationship.source, relationship.target],
      relationshipIds: [relationship.id],
      findingIds: [],
      steps: [{
        order: 1,
        source: relationship.source,
        target: relationship.target,
        relationshipId: relationship.id,
        narrative: 'Reaches the target.',
      }],
    }))
    const overviewResource = {
      id: 'overview', name: 'Overview', type: 'test/overview', category: 'scope',
      provider: 'azure', criticality: 'low' as const,
    }
    let activeFollowUps = 0
    let maxActiveFollowUps = 0
    let followUpCount = 0
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = String(input)
      const url = new URL(request, 'http://localhost')
      if (url.pathname.endsWith('/graph') && url.searchParams.has('resource_id')) {
        followUpCount += 1
        activeFollowUps += 1
        maxActiveFollowUps = Math.max(maxActiveFollowUps, activeFollowUps)
        expect(request.length).toBeLessThanOrEqual(8_000)
        await new Promise((resolve) => window.setTimeout(resolve, 5))
        activeFollowUps -= 1
        const requested = new Set(url.searchParams.getAll('resource_id'))
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: resources.filter((resource) => requested.has(resource.id)),
          relationships: relationships.filter((relationship) =>
            requested.has(relationship.source) && requested.has(relationship.target)),
          truncated: false,
        })
      }
      if (url.pathname.endsWith('/graph')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          resources: [overviewResource],
          relationships: [],
          truncated: true,
          totalResources: 5_000,
        })
      }
      if (url.pathname.endsWith('/findings')) {
        return jsonResponse({ snapshotId: demoSnapshot.id, findings: [], total: 0 })
      }
      if (url.pathname.endsWith('/attack-paths')) {
        return jsonResponse({
          snapshotId: demoSnapshot.id,
          attackPaths: paths,
          total: paths.length,
        })
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadSnapshotById({
      id: demoSnapshot.id,
      name: demoSnapshot.name,
      provider: demoSnapshot.provider,
      generatedAt: demoSnapshot.generatedAt,
      riskScore: demoSnapshot.riskScore,
      resourceCount: 5_000,
      relationshipCount: 20_000,
      findingCount: 0,
      attackPathCount: paths.length,
      origin: 'api',
    })

    expect(followUpCount).toBeGreaterThan(4)
    expect(maxActiveFollowUps).toBe(4)
    expect(result.snapshot.attackPaths).toHaveLength(paths.length)
    expect(result.snapshot.resources).toHaveLength(resources.length + 1)
  })

  it('persists an import with the local CSRF token', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void input
      void init
      return jsonResponse({
        id: demoSnapshot.id,
        name: demoSnapshot.name,
        provider: demoSnapshot.provider,
        generatedAt: demoSnapshot.generatedAt,
        riskScore: demoSnapshot.riskScore,
        resourceCount: demoSnapshot.resources.length,
        relationshipCount: demoSnapshot.relationships.length,
        findingCount: demoSnapshot.findings.length,
        attackPathCount: demoSnapshot.attackPaths.length,
      }, 201)
    })
    vi.stubGlobal('fetch', fetchMock)

    const summary = await persistImportedSnapshot(demoSnapshot, 'local-token')

    expect(summary.origin).toBe('api')
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(new Headers(init.headers).get('X-Atlas-CSRF-Token')).toBe('local-token')
    expect(JSON.parse(String(init.body))).toEqual({ snapshot: demoSnapshot })
  })

  it('reloads a persisted import under the generated workspace ID', async () => {
    const persistedID = '01K6ATLASGENERATED'
    const persistedSnapshot = { ...demoSnapshot, id: persistedID }
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshots')) {
        return jsonResponse({
          id: persistedID,
          name: demoSnapshot.name,
          provider: demoSnapshot.provider,
          generatedAt: demoSnapshot.generatedAt,
          riskScore: demoSnapshot.riskScore,
          resourceCount: demoSnapshot.resources.length,
          relationshipCount: demoSnapshot.relationships.length,
          findingCount: demoSnapshot.findings.length,
          attackPathCount: demoSnapshot.attackPaths.length,
        }, 201)
      }
      if (url.endsWith(`/api/v1/snapshots/${persistedID}`)) {
        return jsonResponse(persistedSnapshot)
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await persistAndLoadImportedSnapshot(demoSnapshot, 'local-token')

    expect(result.summary.id).toBe(persistedID)
    expect(result.envelope.snapshot.id).toBe(persistedID)
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      '/api/v1/snapshots',
      `/api/v1/snapshots/${persistedID}`,
    ])
  })

  it('requests and accepts the compact simulation delta', async () => {
    const changes = [{ type: 'remove-edge' as const, targetId: 'edge-a' }]
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void input
      void init
      return jsonResponse({
        snapshotId: demoSnapshot.id,
        changes,
        removedAttackPathIds: ['path-a'],
        remainingAttackPathCount: 2,
        riskScoreBefore: 92,
        riskScoreAfter: 66,
        riskScoreDelta: -26,
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await runSimulation(demoSnapshot.id, changes, undefined, 'local-token')

    expect(result.remainingAttackPathCount).toBe(2)
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(JSON.parse(String(init.body))).toMatchObject({ compact: true })
    expect(new Headers(init.headers).get('X-Atlas-CSRF-Token')).toBe('local-token')
  })

  it('keeps the legacy simulation payload free of compact-only fields', async () => {
    const changes = [{ type: 'remove-edge' as const, targetId: 'rel-identity-vault' }]
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void input
      void init
      return jsonResponse({
        snapshotId: demoSnapshot.id,
        changes,
        removedAttackPathIds: [],
        remainingAttackPaths: demoSnapshot.attackPaths,
        riskScoreBefore: demoSnapshot.riskScore,
        riskScoreAfter: demoSnapshot.riskScore,
        resultingSnapshot: demoSnapshot,
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    await runSimulation(demoSnapshot.id, changes)

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(JSON.parse(String(init.body))).toEqual({ snapshotId: demoSnapshot.id, changes })
  })

  it('starts and cancels a scoped Azure scan with CSRF protection', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/api/v1/scans/azure')) {
        return jsonResponse({ jobId: 'scan-1', status: 'queued' }, 202)
      }
      if (url.endsWith('/api/v1/scans/scan-1') && init?.method === 'DELETE') {
        return new Response(null, { status: 202 })
      }
      return jsonResponse({ error: 'not found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(startAzureScan({
      subscriptionId: ' 00000000-0000-0000-0000-000000000001 ',
      resourceGroup: ' atlas-demo ',
    }, 'local-token')).resolves.toEqual({ jobId: 'scan-1', status: 'queued' })
    await cancelAzureScan('scan-1', 'local-token')

    const start = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(start.method).toBe('POST')
    expect(new Headers(start.headers).get('X-Atlas-CSRF-Token')).toBe('local-token')
    expect(JSON.parse(String(start.body))).toEqual({
      subscriptionId: '00000000-0000-0000-0000-000000000001',
      resourceGroup: 'atlas-demo',
    })
    const cancellation = fetchMock.mock.calls[1]?.[1] as RequestInit
    expect(cancellation.method).toBe('DELETE')
    expect(new Headers(cancellation.headers).get('X-Atlas-CSRF-Token')).toBe('local-token')
  })

  it('falls back to polling when the authenticated event stream is unavailable', async () => {
    const baseJob = {
      id: 'scan-2',
      provider: 'azure',
      scope: { subscriptionId: '00000000-0000-0000-0000-000000000002' },
      revision: 1,
      createdAt: '2026-10-05T00:00:00Z',
      updatedAt: '2026-10-05T00:00:00Z',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ...baseJob, status: 'running', phase: 'resources' }))
      .mockResolvedValueOnce(jsonResponse({ error: 'stream unavailable' }, 503))
      .mockResolvedValueOnce(jsonResponse({
        ...baseJob,
        status: 'completed',
        phase: 'complete',
        revision: 2,
        snapshotId: 'snapshot-from-scan',
      }))
    vi.stubGlobal('fetch', fetchMock)
    const onJob = vi.fn()
    const onTransport = vi.fn()
    const controller = new AbortController()

    monitorAzureScan('scan-2', {
      onJob,
      onEvent: vi.fn(),
      onTransport,
      onError: vi.fn(),
    }, controller.signal)

    await vi.waitFor(() => expect(onJob).toHaveBeenCalledTimes(2))
    expect(onTransport).toHaveBeenCalledWith('polling')
    expect(onJob).toHaveBeenLastCalledWith(expect.objectContaining({
      status: 'completed',
      snapshotId: 'snapshot-from-scan',
    }))
    const eventRequest = fetchMock.mock.calls[1]?.[1] as RequestInit
    expect(new Headers(eventRequest.headers).get('X-Atlas-Session-Token')).toBe('A'.repeat(43))
    expect(new Headers(eventRequest.headers).get('Accept')).toBe('text/event-stream')
  })

  it('stops scan monitoring when the workspace session expires', async () => {
    const baseJob = {
      id: 'scan-expired',
      provider: 'azure',
      scope: { subscriptionId: '00000000-0000-0000-0000-000000000003' },
      status: 'running',
      phase: 'resources',
      revision: 1,
      createdAt: '2026-10-05T00:00:00Z',
      updatedAt: '2026-10-05T00:00:00Z',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(baseJob))
      .mockResolvedValueOnce(jsonResponse({ error: 'unauthorized' }, 401))
    vi.stubGlobal('fetch', fetchMock)
    const onError = vi.fn()
    const onTransport = vi.fn()
    const controller = new AbortController()

    monitorAzureScan('scan-expired', {
      onJob: vi.fn(),
      onEvent: vi.fn(),
      onTransport,
      onError,
    }, controller.signal)

    await vi.waitFor(() => expect(onError).toHaveBeenCalledOnce())
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WorkspaceSessionExpiredError)
    expect(onTransport).not.toHaveBeenCalledWith('polling')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('loads and patches carried-forward finding triage', async () => {
    const record = {
      snapshotId: demoSnapshot.id,
      environmentId: 'azure:subscription:demo',
      findingId: demoSnapshot.findings[0]!.id,
      fingerprint: 'rule|resource',
      status: 'accepted-risk',
      notes: 'Reviewed with the service owner.',
      firstSeenSnapshotId: 'older-snapshot',
      lastSeenSnapshotId: demoSnapshot.id,
      updatedAt: '2026-10-05T00:00:00Z',
    }
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'PATCH') return jsonResponse(record)
      return jsonResponse({ snapshotId: demoSnapshot.id, triage: [record] })
    })
    vi.stubGlobal('fetch', fetchMock)

    const loaded = await loadTriage(demoSnapshot.id)
    expect(loaded).toEqual([record])
    await expect(updateTriage(
      demoSnapshot.id,
      record.findingId,
      'accepted-risk',
      record.notes,
      'local-token',
    )).resolves.toEqual(record)

    expect(String(fetchMock.mock.calls[0]?.[0])).toContain(
      `/api/v1/triage?snapshot_id=${encodeURIComponent(demoSnapshot.id)}`,
    )
    const patch = fetchMock.mock.calls[1]?.[1] as RequestInit
    expect(patch.method).toBe('PATCH')
    expect(new Headers(patch.headers).get('X-Atlas-CSRF-Token')).toBe('local-token')
    expect(JSON.parse(String(patch.body))).toEqual({
      snapshotId: demoSnapshot.id,
      findingId: record.findingId,
      status: 'accepted-risk',
      notes: record.notes,
    })
  })
})
