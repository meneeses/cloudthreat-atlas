import { describe, expect, it } from 'vitest'
import type { Snapshot } from '../types'
import {
  compareSimulation,
  countExposedResources,
  deriveSimulations,
  filterAtlas,
} from './atlas'

const snapshot: Snapshot = {
  id: 'test',
  name: 'Test tenant',
  provider: 'azure',
  generatedAt: '2026-01-01T00:00:00Z',
  schemaVersion: '1.0',
  riskScore: 84,
  resources: [
    {
      id: 'internet',
      name: 'Internet',
      type: 'Internet',
      category: 'external',
      criticality: 'critical',
      properties: { exposure: 'public' },
    },
    {
      id: 'vault',
      name: 'Patient Vault',
      type: 'Key Vault',
      category: 'data',
      criticality: 'high',
      properties: { purpose: 'Stores application secrets' },
    },
    {
      id: 'logs',
      name: 'Audit Logs',
      type: 'Log Analytics',
      category: 'security',
      criticality: 'low',
    },
  ],
  relationships: [
    {
      id: 'edge-1',
      source: 'internet',
      target: 'vault',
      type: 'public_exposure',
      label: 'public endpoint',
      exploitable: true,
    },
  ],
  findings: [],
  attackPaths: [
    {
      id: 'path-1',
      title: 'Public app to vault',
      severity: 'critical',
      score: 90,
      entryPoint: 'internet',
      target: 'vault',
      resourceIds: ['internet', 'vault'],
      relationshipIds: ['edge-1'],
      description: 'A direct path',
      steps: [
        {
          order: 1,
          source: 'internet',
          target: 'vault',
          relationshipId: 'edge-1',
          narrative: 'A public request reaches the vault.',
        },
      ],
    },
  ],
  simulations: [
    {
      id: 'sim-path-1',
      name: 'Remove direct access',
      description: 'A precomputed fixture result.',
      changes: [{ type: 'remove-edge', targetId: 'edge-1' }],
      riskScoreAfter: 0,
      removedAttackPaths: ['path-1'],
    },
  ],
}

describe('atlas filtering', () => {
  it('combines search, severity, type and attack-path constraints', () => {
    const result = filterAtlas(snapshot, {
      query: 'secrets',
      severity: 'high',
      type: 'Key Vault',
      attackPathId: 'path-1',
    })

    expect(result.resources.map((resource) => resource.id)).toEqual(['vault'])
    expect(result.visibleResourceIds.has('logs')).toBe(false)
  })

  it('uses only verified simulation presets embedded in the snapshot', () => {
    const simulation = deriveSimulations(snapshot)[0]
    expect(simulation?.removedAttackPaths).toEqual(['path-1'])
    expect(simulation?.changes[0]?.targetId).toBe('edge-1')
    expect(deriveSimulations({ ...snapshot, simulations: undefined })).toEqual([])
  })

  it('reports simulation impact without mutating the original snapshot', () => {
    const before = structuredClone(snapshot)
    const simulation = deriveSimulations(snapshot)[0]
    expect(simulation).toBeDefined()
    const comparison = compareSimulation(snapshot, simulation!)

    expect(comparison.remainingPaths).toBe(0)
    expect(comparison.projectedScore).toBeLessThan(comparison.originalScore)
    expect(snapshot).toEqual(before)
  })

  it('counts exposed assets from explicit metadata without counting the internet node', () => {
    expect(countExposedResources(snapshot)).toBe(1)
  })
})
