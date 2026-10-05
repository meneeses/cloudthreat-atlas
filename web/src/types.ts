export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ResourceNode {
  id: string
  name: string
  type: string
  category: string
  provider?: string
  location?: string
  criticality?: Severity
  properties?: Record<string, string>
}

export interface RelationshipEdge {
  id: string
  source: string
  target: string
  type: string
  label: string
  description?: string
  exploitable: boolean
  properties?: Record<string, string>
}

export interface Remediation {
  summary: string
  steps: string[]
}

export interface Finding {
  id: string
  ruleId: string
  title: string
  description: string
  severity: Severity
  score: number
  resourceIds: string[]
  relationshipIds?: string[]
  evidence: string[]
  remediation: Remediation
}

export interface AttackStep {
  order: number
  source: string
  target: string
  relationshipId: string
  narrative: string
}

export interface AttackPath {
  id: string
  title: string
  description: string
  severity: Severity
  score: number
  entryPoint: string
  target: string
  resourceIds: string[]
  relationshipIds: string[]
  findingIds?: string[]
  steps: AttackStep[]
}

export interface SimulationChange {
  id?: string
  type: 'remove-edge' | 'disable-node' | 'set-property'
  targetId: string
  property?: string
  value?: string
  description?: string
}

export interface SimulationPreset {
  id: string
  name: string
  description: string
  changes: SimulationChange[]
  riskScoreAfter: number
  removedAttackPaths: string[]
}

export interface Snapshot {
  schemaVersion: string
  id: string
  name: string
  provider: string
  generatedAt: string
  description?: string
  resources: ResourceNode[]
  relationships: RelationshipEdge[]
  findings: Finding[]
  attackPaths: AttackPath[]
  riskScore: number
  simulations?: SimulationPreset[]
}

export interface SimulationResult {
  snapshotId: string
  changes: SimulationChange[]
  removedAttackPathIds: string[]
  remainingAttackPaths: AttackPath[]
  riskScoreBefore: number
  riskScoreAfter: number
  resultingSnapshot: Snapshot
}

export type DataSource = 'fixture' | 'api' | 'fixture-fallback'

export interface SnapshotEnvelope {
  snapshot: Snapshot
  source: DataSource
  notice?: string
}
