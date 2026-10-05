import { describe, expect, it } from 'vitest'
import fixturePayload from '../../../demo/contoso-health.json'
import { parseSimulationResult, parseSnapshot } from './validation'

function fixtureClone(): unknown {
  return structuredClone(fixturePayload)
}

describe('snapshot runtime validation', () => {
  it('accepts the complete public fixture', () => {
    const snapshot = parseSnapshot(fixtureClone())

    expect(snapshot.id).toBe('contoso-health-demo')
    expect(snapshot.attackPaths).toHaveLength(3)
  })

  it('preserves evidence provenance and bounded-analysis metadata', () => {
    const payload = fixtureClone() as Record<string, unknown>
    const relationships = payload.relationships as Array<Record<string, unknown>>
    const findings = payload.findings as Array<Record<string, unknown>>
    relationships[0]!.origin = 'observed'
    relationships[0]!.confidence = 'high'
    relationships[0]!.evidence = [{
      source: 'Azure Resource Graph',
      resourceId: '/subscriptions/demo/resourceGroups/atlas',
      field: 'properties.publicNetworkAccess',
      value: 'Enabled',
    }]
    findings[0]!.evidenceDetails = [{
      source: 'normalized relationship',
      field: 'exploitable',
      value: 'true',
    }]
    payload.analysis = {
      pathSearch: {
        maxDepth: 8,
        maxPaths: 1000,
        maxPathsPerTarget: 30,
        maxExpansions: 100000,
        expansions: 418,
        truncated: false,
      },
    }
    payload.scope = {
      subscriptionId: '11111111-2222-3333-4444-555555555555',
      resourceGroup: 'clinical-prod',
    }

    const snapshot = parseSnapshot(payload)

    expect(snapshot.relationships[0]).toMatchObject({
      origin: 'observed',
      confidence: 'high',
      evidence: [expect.objectContaining({ field: 'properties.publicNetworkAccess' })],
    })
    expect(snapshot.findings[0]?.evidenceDetails).toEqual([
      expect.objectContaining({ source: 'normalized relationship' }),
    ])
    expect(snapshot.analysis?.pathSearch).toMatchObject({ expansions: 418, truncated: false })
    expect(snapshot.scope).toEqual({
      subscriptionId: '11111111-2222-3333-4444-555555555555',
      resourceGroup: 'clinical-prod',
    })
  })

  it('reports the exact nested path for an invalid enum', () => {
    const payload = fixtureClone() as typeof fixturePayload
    payload.findings[1]!.severity = 'urgent' as 'critical'

    expect(() => parseSnapshot(payload)).toThrow(
      'Invalid data at snapshot.findings[1].severity: expected critical, high, medium, low, or info.',
    )
  })

  it('rejects duplicate identifiers and dangling relationships', () => {
    const duplicate = fixtureClone() as typeof fixturePayload
    duplicate.resources[1]!.id = duplicate.resources[0]!.id
    expect(() => parseSnapshot(duplicate)).toThrow(/duplicate identifier/)

    const dangling = fixtureClone() as typeof fixturePayload
    dangling.relationships[0]!.target = 'missing-resource'
    expect(() => parseSnapshot(dangling)).toThrow(
      /snapshot\.relationships\[0\]\.target: unknown resource identifier/,
    )
  })

  it('validates nested simulation results and rejects divergent path copies', () => {
    const snapshot = parseSnapshot(fixtureClone())
    const result = {
      snapshotId: snapshot.id,
      changes: [{ type: 'set-property', targetId: snapshot.resources[0]!.id, property: 'enabled', value: 'true' }],
      removedAttackPathIds: [],
      remainingAttackPaths: structuredClone(snapshot.attackPaths),
      riskScoreBefore: snapshot.riskScore,
      riskScoreAfter: snapshot.riskScore,
      resultingSnapshot: structuredClone(snapshot),
    }

    expect(parseSimulationResult(result).remainingAttackPaths).toHaveLength(3)
    result.remainingAttackPaths[0]!.steps[0]!.narrative = 'Tampered narrative'
    expect(() => parseSimulationResult(result)).toThrow(/differs from the resulting snapshot/)
  })

  it('rejects non-finite and out-of-range scores', () => {
    const notFinite = fixtureClone() as typeof fixturePayload
    notFinite.riskScore = Number.NaN
    expect(() => parseSnapshot(notFinite)).toThrow(/expected a finite number/)

    const outOfRange = fixtureClone() as typeof fixturePayload
    outOfRange.attackPaths[0]!.score = 101
    expect(() => parseSnapshot(outOfRange)).toThrow(/expected a number from 0 through 100/)
  })
})
