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

export interface EvidenceRecord {
  source?: string
  resourceId?: string
  field?: string
  value?: string
}

export type RelationshipOrigin = 'observed' | 'derived' | 'heuristic'
export type Confidence = 'high' | 'medium' | 'low'

export interface RelationshipEdge {
  id: string
  source: string
  target: string
  type: string
  label: string
  description?: string
  exploitable: boolean
  properties?: Record<string, string>
  origin?: RelationshipOrigin
  confidence?: Confidence
  evidence?: EvidenceRecord[]
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
  evidenceDetails?: EvidenceRecord[]
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
  scope?: AzureScanScope
  generatedAt: string
  description?: string
  resources: ResourceNode[]
  relationships: RelationshipEdge[]
  findings: Finding[]
  attackPaths: AttackPath[]
  riskScore: number
  simulations?: SimulationPreset[]
  analysis?: AnalysisMetadata
}

export interface AnalysisMetadata {
  pathSearch: PathSearchMetadata
}

export interface PathSearchMetadata {
  maxDepth: number
  maxPaths: number
  maxPathsPerTarget: number
  maxExpansions: number
  expansions: number
  truncated: boolean
  reason?: string
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

export interface SimulationImpact {
  snapshotId: string
  changes: SimulationChange[]
  removedAttackPathIds: string[]
  remainingAttackPathCount: number
  riskScoreBefore: number
  riskScoreAfter: number
}

export type DataSource = 'fixture' | 'api' | 'import' | 'fixture-fallback'

export interface SnapshotEnvelope {
  snapshot: Snapshot
  source: DataSource
  notice?: string
}

export interface SnapshotSummary {
  id: string
  environmentId?: string
  name: string
  provider: string
  generatedAt: string
  riskScore: number
  resourceCount: number
  relationshipCount: number
  findingCount: number
  attackPathCount: number
  origin: 'demo' | 'api' | 'import'
}

export interface WorkspaceCapabilities {
  history: boolean
  comparison: boolean
  import: boolean
  triage: boolean
  azureScans: boolean
}

export interface WorkspaceBootstrap {
  snapshots: SnapshotSummary[]
  currentSnapshotId: string | null
  source: DataSource
  capabilities: WorkspaceCapabilities
  csrfToken?: string
  notice?: string
}

export interface SnapshotComparison {
  baseSnapshotId: string
  targetSnapshotId: string
  riskScoreDelta: number
  resourceDelta: number
  findingDelta: number
  attackPathDelta: number
  addedResourceIds?: string[]
  removedResourceIds?: string[]
}

export type TriageStatus = 'open' | 'acknowledged' | 'accepted-risk' | 'resolved'

export interface TriageRecord {
  snapshotId: string
  environmentId: string
  findingId: string
  fingerprint: string
  status: TriageStatus
  notes: string
  firstSeenSnapshotId: string
  lastSeenSnapshotId: string
  updatedAt: string
}

export type ScanJobStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'interrupted'

export interface AzureScanScope {
  subscriptionId: string
  resourceGroup?: string
}

export interface AzureScanJob {
  id: string
  provider: string
  scope: AzureScanScope
  status: ScanJobStatus
  phase: string
  error?: string
  snapshotId?: string
  revision: number
  createdAt: string
  startedAt?: string
  updatedAt: string
  completedAt?: string
}

export interface AzureScanEvent {
  sequence: number
  jobId: string
  status: ScanJobStatus
  phase: string
  message?: string
  createdAt: string
}
