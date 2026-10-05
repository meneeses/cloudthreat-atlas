import type {
  AttackPath,
  Finding,
  RelationshipEdge,
  ResourceNode,
  Severity,
  SimulationChange,
  SimulationPreset,
  SimulationResult,
  Snapshot,
} from '../types'

const severities = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info'])
const changeTypes = new Set<SimulationChange['type']>([
  'remove-edge',
  'disable-node',
  'set-property',
])

type JSONObject = Record<string, unknown>

function invalid(path: string, expectation: string): never {
  throw new Error(`Invalid data at ${path}: ${expectation}.`)
}

function objectAt(value: unknown, path: string): JSONObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return invalid(path, 'expected an object')
  }
  return value as JSONObject
}

function arrayAt(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) return invalid(path, 'expected an array')
  return value
}

function stringAt(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    return invalid(path, 'expected a non-empty string')
  }
  return value
}

function optionalStringAt(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined
  return stringAt(value, path)
}

function booleanAt(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') return invalid(path, 'expected a boolean')
  return value
}

function boundedNumberAt(value: unknown, path: string, minimum = 0, maximum = 100): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return invalid(path, 'expected a finite number')
  }
  if (value < minimum || value > maximum) {
    return invalid(path, `expected a number from ${minimum} through ${maximum}`)
  }
  return value
}

function positiveIntegerAt(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return invalid(path, 'expected a positive integer')
  }
  return value
}

function severityAt(value: unknown, path: string): Severity {
  if (typeof value !== 'string' || !severities.has(value as Severity)) {
    return invalid(path, 'expected critical, high, medium, low, or info')
  }
  return value as Severity
}

function optionalSeverityAt(value: unknown, path: string): Severity | undefined {
  if (value === undefined) return undefined
  return severityAt(value, path)
}

function stringArrayAt(value: unknown, path: string, allowEmpty = true): string[] {
  const result = arrayAt(value, path).map((item, index) => stringAt(item, `${path}[${index}]`))
  if (!allowEmpty && result.length === 0) return invalid(path, 'expected at least one item')
  return result
}

function unique(values: string[], path: string): void {
  const seen = new Set<string>()
  for (const value of values) {
    if (seen.has(value)) invalid(path, `duplicate identifier “${value}”`)
    seen.add(value)
  }
}

function stringValueAt(value: unknown, path: string): string {
  if (typeof value !== 'string') return invalid(path, 'expected a string')
  return value
}

function optionalStringValueAt(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined
  return stringValueAt(value, path)
}

function propertiesAt(value: unknown, path: string): Record<string, string> | undefined {
  if (value === undefined) return undefined
  const candidate = objectAt(value, path)
  const properties: Record<string, string> = {}
  for (const [key, propertyValue] of Object.entries(candidate)) {
    if (key.trim() === '') invalid(path, 'property names must not be empty')
    properties[key] = stringValueAt(propertyValue, `${path}.${key}`)
  }
  return properties
}

function resourceAt(value: unknown, path: string): ResourceNode {
  const candidate = objectAt(value, path)
  return {
    id: stringAt(candidate.id, `${path}.id`),
    name: stringAt(candidate.name, `${path}.name`),
    type: stringAt(candidate.type, `${path}.type`),
    category: stringAt(candidate.category, `${path}.category`),
    provider: optionalStringAt(candidate.provider, `${path}.provider`),
    location: optionalStringAt(candidate.location, `${path}.location`),
    criticality: optionalSeverityAt(candidate.criticality, `${path}.criticality`),
    properties: propertiesAt(candidate.properties, `${path}.properties`),
  }
}

function relationshipAt(value: unknown, path: string): RelationshipEdge {
  const candidate = objectAt(value, path)
  return {
    id: stringAt(candidate.id, `${path}.id`),
    source: stringAt(candidate.source, `${path}.source`),
    target: stringAt(candidate.target, `${path}.target`),
    type: stringAt(candidate.type, `${path}.type`),
    label: stringAt(candidate.label, `${path}.label`),
    description: optionalStringAt(candidate.description, `${path}.description`),
    exploitable: booleanAt(candidate.exploitable, `${path}.exploitable`),
    properties: propertiesAt(candidate.properties, `${path}.properties`),
  }
}

function findingAt(value: unknown, path: string): Finding {
  const candidate = objectAt(value, path)
  const remediation = objectAt(candidate.remediation, `${path}.remediation`)
  return {
    id: stringAt(candidate.id, `${path}.id`),
    ruleId: stringAt(candidate.ruleId, `${path}.ruleId`),
    title: stringAt(candidate.title, `${path}.title`),
    description: stringAt(candidate.description, `${path}.description`),
    severity: severityAt(candidate.severity, `${path}.severity`),
    score: boundedNumberAt(candidate.score, `${path}.score`),
    resourceIds: stringArrayAt(candidate.resourceIds, `${path}.resourceIds`, false),
    relationshipIds:
      candidate.relationshipIds === undefined
        ? undefined
        : stringArrayAt(candidate.relationshipIds, `${path}.relationshipIds`),
    evidence: stringArrayAt(candidate.evidence, `${path}.evidence`),
    remediation: {
      summary: stringAt(remediation.summary, `${path}.remediation.summary`),
      steps: stringArrayAt(remediation.steps, `${path}.remediation.steps`),
    },
  }
}

function attackPathAt(value: unknown, path: string): AttackPath {
  const candidate = objectAt(value, path)
  const steps = arrayAt(candidate.steps, `${path}.steps`).map((step, index) => {
    const itemPath = `${path}.steps[${index}]`
    const item = objectAt(step, itemPath)
    return {
      order: positiveIntegerAt(item.order, `${itemPath}.order`),
      source: stringAt(item.source, `${itemPath}.source`),
      target: stringAt(item.target, `${itemPath}.target`),
      relationshipId: stringAt(item.relationshipId, `${itemPath}.relationshipId`),
      narrative: stringAt(item.narrative, `${itemPath}.narrative`),
    }
  })

  return {
    id: stringAt(candidate.id, `${path}.id`),
    title: stringAt(candidate.title, `${path}.title`),
    description: stringAt(candidate.description, `${path}.description`),
    severity: severityAt(candidate.severity, `${path}.severity`),
    score: boundedNumberAt(candidate.score, `${path}.score`),
    entryPoint: stringAt(candidate.entryPoint, `${path}.entryPoint`),
    target: stringAt(candidate.target, `${path}.target`),
    resourceIds: stringArrayAt(candidate.resourceIds, `${path}.resourceIds`, false),
    relationshipIds: stringArrayAt(candidate.relationshipIds, `${path}.relationshipIds`, false),
    findingIds:
      candidate.findingIds === undefined
        ? undefined
        : stringArrayAt(candidate.findingIds, `${path}.findingIds`),
    steps,
  }
}

function simulationChangeAt(value: unknown, path: string): SimulationChange {
  const candidate = objectAt(value, path)
  if (typeof candidate.type !== 'string' || !changeTypes.has(candidate.type as SimulationChange['type'])) {
    invalid(`${path}.type`, 'expected remove-edge, disable-node, or set-property')
  }

  const change: SimulationChange = {
    id: optionalStringAt(candidate.id, `${path}.id`),
    type: candidate.type as SimulationChange['type'],
    targetId: stringAt(candidate.targetId, `${path}.targetId`),
    property: optionalStringAt(candidate.property, `${path}.property`),
    value: optionalStringValueAt(candidate.value, `${path}.value`),
    description: optionalStringAt(candidate.description, `${path}.description`),
  }
  if (change.type === 'set-property' && (!change.property || change.value === undefined)) {
    invalid(path, 'set-property requires both property and value')
  }
  return change
}

function simulationPresetAt(value: unknown, path: string): SimulationPreset {
  const candidate = objectAt(value, path)
  return {
    id: stringAt(candidate.id, `${path}.id`),
    name: stringAt(candidate.name, `${path}.name`),
    description: stringAt(candidate.description, `${path}.description`),
    changes: arrayAt(candidate.changes, `${path}.changes`).map((change, index) =>
      simulationChangeAt(change, `${path}.changes[${index}]`),
    ),
    riskScoreAfter: boundedNumberAt(candidate.riskScoreAfter, `${path}.riskScoreAfter`),
    removedAttackPaths: stringArrayAt(
      candidate.removedAttackPaths,
      `${path}.removedAttackPaths`,
    ),
  }
}

function assertKnown(ids: string[], known: Set<string>, path: string, kind: string): void {
  unique(ids, path)
  for (const id of ids) {
    if (!known.has(id)) invalid(path, `unknown ${kind} identifier “${id}”`)
  }
}

function validateAttackPath(
  attackPath: AttackPath,
  path: string,
  resources: Set<string>,
  relationships: Map<string, RelationshipEdge>,
  findings: Set<string>,
): void {
  assertKnown(attackPath.resourceIds, resources, `${path}.resourceIds`, 'resource')
  assertKnown(
    attackPath.relationshipIds,
    new Set(relationships.keys()),
    `${path}.relationshipIds`,
    'relationship',
  )
  assertKnown(attackPath.findingIds ?? [], findings, `${path}.findingIds`, 'finding')

  if (attackPath.resourceIds.length < 2) invalid(`${path}.resourceIds`, 'expected at least two resources')
  if (attackPath.steps.length !== attackPath.resourceIds.length - 1) {
    invalid(`${path}.steps`, 'expected one step between every adjacent resource')
  }
  if (attackPath.relationshipIds.length !== attackPath.steps.length) {
    invalid(`${path}.relationshipIds`, 'expected one relationship for every step')
  }
  if (attackPath.entryPoint !== attackPath.resourceIds[0]) {
    invalid(`${path}.entryPoint`, 'expected the first resource in the path')
  }
  if (attackPath.target !== attackPath.resourceIds.at(-1)) {
    invalid(`${path}.target`, 'expected the last resource in the path')
  }

  attackPath.steps.forEach((step, index) => {
    const stepPath = `${path}.steps[${index}]`
    if (step.order !== index + 1) invalid(`${stepPath}.order`, `expected ${index + 1}`)
    if (step.source !== attackPath.resourceIds[index]) {
      invalid(`${stepPath}.source`, 'expected the matching resource in the path')
    }
    if (step.target !== attackPath.resourceIds[index + 1]) {
      invalid(`${stepPath}.target`, 'expected the next resource in the path')
    }
    if (step.relationshipId !== attackPath.relationshipIds[index]) {
      invalid(`${stepPath}.relationshipId`, 'expected the matching path relationship')
    }
    const relationship = relationships.get(step.relationshipId)
    if (relationship?.source !== step.source || relationship.target !== step.target) {
      invalid(stepPath, 'relationship endpoints do not match the step')
    }
  })
}

function validateChangeTarget(
  change: SimulationChange,
  path: string,
  resources: Set<string>,
  relationships: Set<string>,
): void {
  const known = change.type === 'remove-edge' ? relationships : resources
  const kind = change.type === 'remove-edge' ? 'relationship' : 'resource'
  if (!known.has(change.targetId)) invalid(`${path}.targetId`, `unknown ${kind} identifier “${change.targetId}”`)
}

interface SnapshotValidationContext {
  historicalTargets?: Set<string>
  historicalAttackPaths?: Set<string>
}

function parseSnapshotWithContext(
  value: unknown,
  root: string,
  context: SnapshotValidationContext,
): Snapshot {
  const candidate = objectAt(value, root)
  const schemaVersion = stringAt(candidate.schemaVersion, `${root}.schemaVersion`)
  if (schemaVersion !== '1.0') invalid(`${root}.schemaVersion`, 'expected supported version 1.0')

  const generatedAt = stringAt(candidate.generatedAt, `${root}.generatedAt`)
  if (!generatedAt.includes('T') || !Number.isFinite(Date.parse(generatedAt))) {
    invalid(`${root}.generatedAt`, 'expected an ISO-8601 timestamp')
  }

  const resources = arrayAt(candidate.resources, `${root}.resources`).map((resource, index) =>
    resourceAt(resource, `${root}.resources[${index}]`),
  )
  const relationships = arrayAt(candidate.relationships, `${root}.relationships`).map(
    (relationship, index) => relationshipAt(relationship, `${root}.relationships[${index}]`),
  )
  const findings = arrayAt(candidate.findings, `${root}.findings`).map((finding, index) =>
    findingAt(finding, `${root}.findings[${index}]`),
  )
  const attackPaths = arrayAt(candidate.attackPaths, `${root}.attackPaths`).map(
    (attackPath, index) => attackPathAt(attackPath, `${root}.attackPaths[${index}]`),
  )
  const simulations =
    candidate.simulations === undefined
      ? undefined
      : arrayAt(candidate.simulations, `${root}.simulations`).map((simulation, index) =>
          simulationPresetAt(simulation, `${root}.simulations[${index}]`),
        )

  const resourceIds = new Set(resources.map((resource) => resource.id))
  const relationshipById = new Map(
    relationships.map((relationship) => [relationship.id, relationship] as const),
  )
  const findingIds = new Set(findings.map((finding) => finding.id))
  const attackPathIds = new Set(attackPaths.map((attackPath) => attackPath.id))

  unique(resources.map((resource) => resource.id), `${root}.resources`)
  unique(relationships.map((relationship) => relationship.id), `${root}.relationships`)
  unique(findings.map((finding) => finding.id), `${root}.findings`)
  unique(attackPaths.map((attackPath) => attackPath.id), `${root}.attackPaths`)

  relationships.forEach((relationship, index) => {
    const path = `${root}.relationships[${index}]`
    if (!resourceIds.has(relationship.source)) invalid(`${path}.source`, `unknown resource identifier “${relationship.source}”`)
    if (!resourceIds.has(relationship.target)) invalid(`${path}.target`, `unknown resource identifier “${relationship.target}”`)
  })

  findings.forEach((finding, index) => {
    const path = `${root}.findings[${index}]`
    assertKnown(finding.resourceIds, resourceIds, `${path}.resourceIds`, 'resource')
    assertKnown(
      finding.relationshipIds ?? [],
      new Set(relationshipById.keys()),
      `${path}.relationshipIds`,
      'relationship',
    )
  })

  attackPaths.forEach((attackPath, index) =>
    validateAttackPath(
      attackPath,
      `${root}.attackPaths[${index}]`,
      resourceIds,
      relationshipById,
      findingIds,
    ),
  )

  if (simulations) {
    unique(simulations.map((simulation) => simulation.id), `${root}.simulations`)
    simulations.forEach((simulation, index) => {
      const path = `${root}.simulations[${index}]`
      if (simulation.changes.length === 0) invalid(`${path}.changes`, 'expected at least one change')
      const changeIds = simulation.changes.flatMap((change) => (change.id ? [change.id] : []))
      unique(changeIds, `${path}.changes`)
      simulation.changes.forEach((change, changeIndex) => {
        if (!context.historicalTargets?.has(change.targetId)) {
          validateChangeTarget(
            change,
            `${path}.changes[${changeIndex}]`,
            resourceIds,
            new Set(relationshipById.keys()),
          )
        }
      })
      unique(simulation.removedAttackPaths, `${path}.removedAttackPaths`)
      for (const attackPathId of simulation.removedAttackPaths) {
        if (!attackPathIds.has(attackPathId) && !context.historicalAttackPaths?.has(attackPathId)) {
          invalid(`${path}.removedAttackPaths`, `unknown attack path identifier “${attackPathId}”`)
        }
      }
    })
  }

  return {
    schemaVersion,
    id: stringAt(candidate.id, `${root}.id`),
    name: stringAt(candidate.name, `${root}.name`),
    provider: stringAt(candidate.provider, `${root}.provider`),
    generatedAt,
    description: optionalStringAt(candidate.description, `${root}.description`),
    resources,
    relationships,
    findings,
    attackPaths,
    riskScore: boundedNumberAt(candidate.riskScore, `${root}.riskScore`),
    simulations,
  }
}

export function parseSnapshot(value: unknown, root = 'snapshot'): Snapshot {
  return parseSnapshotWithContext(value, root, {})
}

export function parseSimulationResult(value: unknown): SimulationResult {
  const root = 'simulationResult'
  const candidate = objectAt(value, root)
  const changes = arrayAt(candidate.changes, `${root}.changes`).map((change, index) =>
    simulationChangeAt(change, `${root}.changes[${index}]`),
  )
  if (changes.length === 0) invalid(`${root}.changes`, 'expected at least one change')

  const removedAttackPathIds = stringArrayAt(
    candidate.removedAttackPathIds,
    `${root}.removedAttackPathIds`,
  )
  unique(removedAttackPathIds, `${root}.removedAttackPathIds`)

  const resultingSnapshot = parseSnapshotWithContext(
    candidate.resultingSnapshot,
    `${root}.resultingSnapshot`,
    {
      historicalTargets: new Set(changes.map((change) => change.targetId)),
      historicalAttackPaths: new Set(removedAttackPathIds),
    },
  )

  const remainingAttackPaths = arrayAt(
    candidate.remainingAttackPaths,
    `${root}.remainingAttackPaths`,
  ).map((attackPath, index) => attackPathAt(attackPath, `${root}.remainingAttackPaths[${index}]`))
  unique(remainingAttackPaths.map((attackPath) => attackPath.id), `${root}.remainingAttackPaths`)

  const snapshotId = stringAt(candidate.snapshotId, `${root}.snapshotId`)
  if (snapshotId !== resultingSnapshot.id) {
    invalid(`${root}.snapshotId`, 'expected the resulting snapshot identifier')
  }
  const snapshotPathIds = new Set(resultingSnapshot.attackPaths.map((attackPath) => attackPath.id))
  const remainingIds = new Set(remainingAttackPaths.map((attackPath) => attackPath.id))
  if (remainingIds.size !== snapshotPathIds.size || [...remainingIds].some((id) => !snapshotPathIds.has(id))) {
    invalid(`${root}.remainingAttackPaths`, 'expected the attack paths in the resulting snapshot')
  }
  for (const attackPath of remainingAttackPaths) {
    const snapshotPath = resultingSnapshot.attackPaths.find((candidatePath) => candidatePath.id === attackPath.id)
    if (JSON.stringify(attackPath) !== JSON.stringify(snapshotPath)) {
      invalid(`${root}.remainingAttackPaths`, `attack path “${attackPath.id}” differs from the resulting snapshot`)
    }
  }
  for (const id of removedAttackPathIds) {
    if (remainingIds.has(id)) invalid(`${root}.removedAttackPathIds`, `attack path “${id}” is still present`)
  }

  const riskScoreAfter = boundedNumberAt(candidate.riskScoreAfter, `${root}.riskScoreAfter`)
  if (riskScoreAfter !== resultingSnapshot.riskScore) {
    invalid(`${root}.riskScoreAfter`, 'expected the resulting snapshot risk score')
  }

  return {
    snapshotId,
    changes,
    removedAttackPathIds,
    remainingAttackPaths,
    riskScoreBefore: boundedNumberAt(candidate.riskScoreBefore, `${root}.riskScoreBefore`),
    riskScoreAfter,
    resultingSnapshot,
  }
}
