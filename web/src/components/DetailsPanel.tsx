import { useEffect, useRef, useState } from 'react'
import type {
  EvidenceRecord,
  Finding,
  ResourceNode,
  TriageRecord,
  TriageStatus,
} from '../types'
import { resourceSeverity } from '../lib/atlas'
import { formatSeverity } from '../lib/severity'
import type { AtlasViewModel } from '../lib/view-model'

interface DetailsPanelProps {
  snapshotName: string
  model: AtlasViewModel
  selectedNode: ResourceNode | null
  open: boolean
  onClose: () => void
  onSelectNode: (nodeId: string) => void
  onOpenPath: (pathId: string) => void
  triageByFindingId?: ReadonlyMap<string, TriageRecord>
  triageEnabled?: boolean
  triagePendingIds?: ReadonlySet<string>
  triageError?: string | null
  onUpdateTriage?: (findingId: string, status: TriageStatus, notes: string) => void
}

const triageLabels: Record<TriageStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  'accepted-risk': 'Accepted risk',
  resolved: 'Resolved',
}
const emptyTriageRecords = new Map<string, TriageRecord>()
const emptyPendingTriage = new Set<string>()

function EvidenceRecords({ records }: { records: EvidenceRecord[] }) {
  if (records.length === 0) return null
  return (
    <ul className="evidence-records" aria-label="Structured evidence">
      {records.map((record, index) => (
        <li key={`${record.source ?? 'evidence'}:${record.resourceId ?? ''}:${record.field ?? ''}:${index}`}>
          <span>{record.source || 'collector evidence'}</span>
          {record.resourceId ? <code title={record.resourceId}>{record.resourceId}</code> : null}
          {record.field || record.value ? (
            <strong>{record.field || 'value'}{record.value ? ` = ${record.value}` : ''}</strong>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

function FindingTriage({
  record,
  pending,
  snapshotId,
  onSave,
}: {
  record: TriageRecord
  pending: boolean
  snapshotId: string
  onSave: (status: TriageStatus, notes: string) => void
}) {
  const [status, setStatus] = useState(record.status)
  const [notes, setNotes] = useState(record.notes)
  const carried = record.firstSeenSnapshotId !== snapshotId
  const dirty = status !== record.status || notes !== record.notes

  return (
    <form
      className="finding-triage"
      onSubmit={(event) => {
        event.preventDefault()
        onSave(status, notes)
      }}
    >
      <div className="triage-heading">
        <span className="eyebrow">TRIAGE</span>
        <span className={carried ? 'triage-carried' : 'triage-new'}>
          {carried ? 'Carried forward' : 'First seen here'}
        </span>
      </div>
      <small title={record.environmentId}>
        Environment history · first snapshot {record.firstSeenSnapshotId.slice(0, 12)}
      </small>
      <label>
        <span>Status</span>
        <select
          value={status}
          disabled={pending}
          onChange={(event) => setStatus(event.target.value as TriageStatus)}
        >
          {(Object.keys(triageLabels) as TriageStatus[]).map((value) => (
            <option key={value} value={value}>{triageLabels[value]}</option>
          ))}
        </select>
      </label>
      <label>
        <span>Notes</span>
        <textarea
          maxLength={8000}
          rows={3}
          value={notes}
          disabled={pending}
          placeholder="Owner, decision, expiry, or follow-up…"
          onChange={(event) => setNotes(event.target.value)}
        />
      </label>
      <button type="submit" disabled={!dirty || pending}>
        {pending ? 'Saving…' : 'Save triage'}
      </button>
    </form>
  )
}

function Metadata({ metadata }: { metadata: Record<string, string> }) {
  const rows = Object.entries(metadata)

  if (rows.length === 0) return null

  return (
    <dl className="metadata-grid">
      {rows.slice(0, 8).map(([key, value]) => (
        <div key={key}>
          <dt>{key.replace(/([A-Z])/g, ' $1')}</dt>
          <dd>{String(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

function FindingCard({
  finding,
  model,
  onSelectNode,
  triage,
  triagePending,
  snapshotId,
  onUpdateTriage,
}: {
  finding: Finding
  model: AtlasViewModel
  onSelectNode: (nodeId: string) => void
  triage?: TriageRecord
  triagePending: boolean
  snapshotId: string
  onUpdateTriage?: (findingId: string, status: TriageStatus, notes: string) => void
}) {
  const firstResource = finding.resourceIds
    .map((resourceId) => model.resourceById.get(resourceId))
    .find((resource): resource is ResourceNode => Boolean(resource))
  return (
    <article className={`finding-card finding-${finding.severity}`}>
      <div className="finding-heading">
        <span className={`severity-badge severity-${finding.severity}`}>
          {formatSeverity(finding.severity)}
        </span>
        <code>{finding.ruleId}</code>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.description}</p>
      {firstResource ? (
        <button
          className="asset-link"
          type="button"
          onClick={() => onSelectNode(firstResource.id)}
        >
          <span aria-hidden="true">⬡</span> {firstResource.name}
        </button>
      ) : null}
      <details>
        <summary>Evidence &amp; remediation</summary>
        <div className="evidence-block">
          <span className="eyebrow">EVIDENCE</span>
          {finding.evidence.map((evidence) => <p key={evidence}>{evidence}</p>)}
          {finding.evidenceDetails ? <EvidenceRecords records={finding.evidenceDetails} /> : null}
          <span className="eyebrow">RECOMMENDED FIX</span>
          <p>{finding.remediation.summary}</p>
          {finding.remediation.steps.length > 0 ? (
            <ol>{finding.remediation.steps.map((step) => <li key={step}>{step}</li>)}</ol>
          ) : null}
        </div>
      </details>
      {triage && onUpdateTriage ? (
        <FindingTriage
          record={triage}
          pending={triagePending}
          snapshotId={snapshotId}
          onSave={(status, notes) => onUpdateTriage(finding.id, status, notes)}
        />
      ) : null}
    </article>
  )
}

export function DetailsPanel({
  snapshotName,
  model,
  selectedNode,
  open,
  onClose,
  onSelectNode,
  onOpenPath,
  triageByFindingId = emptyTriageRecords,
  triageEnabled = false,
  triagePendingIds = emptyPendingTriage,
  triageError = null,
  onUpdateTriage,
}: DetailsPanelProps) {
  const panel = useRef<HTMLElement>(null)
  const previousFocus = useRef<HTMLElement | null>(null)
  const [mobile, setMobile] = useState(false)
  const scopedFindings = selectedNode
    ? model.findingsByResourceId.get(selectedNode.id) ?? []
    : model.snapshot.findings
  const scopedPaths = selectedNode ? model.pathsByResourceId.get(selectedNode.id) ?? [] : []
  const provenanceRelationships = selectedNode
    ? (model.relationshipsByResourceId.get(selectedNode.id) ?? []).filter(
        (relationship) => relationship.origin || relationship.confidence || relationship.evidence?.length,
      ).slice(0, 12)
    : []
  const selectedSeverity = selectedNode ? resourceSeverity(selectedNode) : 'info'
  const selectedRisk = selectedNode ? model.riskByResourceId.get(selectedNode.id) ?? 0 : 0
  const visibleFindings = scopedFindings.slice(0, 100)

  useEffect(() => {
    const query = window.matchMedia('(max-width: 1080px)')
    const update = () => setMobile(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  useEffect(() => {
    if (!open) return
    previousFocus.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null
    const handleKeyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
      if (event.key !== 'Tab' || !mobile || !panel.current) return
      const focusable = [...panel.current.querySelectorAll<HTMLElement>(
        'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), details > summary, [tabindex]:not([tabindex="-1"])',
      )]
      if (focusable.length === 0) {
        event.preventDefault()
        panel.current.focus()
        return
      }
      const first = focusable[0]
      const last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
    window.addEventListener('keydown', handleKeyboard)
    if (mobile) panel.current?.focus()
    return () => {
      window.removeEventListener('keydown', handleKeyboard)
      if (mobile && previousFocus.current?.isConnected) previousFocus.current.focus()
    }
  }, [mobile, onClose, open])

  return (
    <aside
      ref={panel}
      className={`details-panel ${open ? 'is-open' : ''}`}
      aria-label="Asset intelligence"
      aria-hidden={!open}
      aria-modal={mobile && open ? true : undefined}
      inert={!open}
      role={mobile ? 'dialog' : 'complementary'}
      tabIndex={-1}
    >
      <div className="details-header">
        <div>
          <span className="eyebrow">{selectedNode ? 'ASSET INTELLIGENCE' : 'THREAT INTELLIGENCE'}</span>
          <h2>{selectedNode?.name ?? snapshotName}</h2>
        </div>
        <button className="panel-close" type="button" onClick={onClose} aria-label="Close panel">
          ×
        </button>
      </div>

      <div className="details-scroll">
        {selectedNode ? (
          <section className="asset-overview">
            <div className="asset-type-line">
              <span>{selectedNode.type}</span>
              <span className={`severity-badge severity-${selectedSeverity}`}>
                {formatSeverity(selectedSeverity)}
              </span>
            </div>
            <div className="large-risk">
              <strong>{selectedRisk}</strong>
              <span>asset risk<br />out of 100</span>
            </div>
            <p>{selectedNode.properties?.description ?? selectedNode.properties?.purpose ?? `${selectedNode.type} resource in ${selectedNode.location ?? 'the analyzed environment'}.`}</p>
            <Metadata metadata={selectedNode.properties ?? {}} />
          </section>
        ) : (
          <section className="panel-intro">
            <div className="signal-animation" aria-hidden="true"><i /><i /><i /></div>
            <p>
              Select a resource on the graph to inspect its evidence, permissions, and attack-path exposure.
            </p>
          </section>
        )}

        {selectedNode && provenanceRelationships.length > 0 ? (
          <section className="provenance-list" aria-label="Relationship provenance">
            <div className="section-heading">
              <span>EVIDENCE PROVENANCE</span>
              <strong>{provenanceRelationships.length}</strong>
            </div>
            {provenanceRelationships.map((relationship) => {
              const source = model.resourceById.get(relationship.source)?.name ?? relationship.source
              const target = model.resourceById.get(relationship.target)?.name ?? relationship.target
              return (
                <article key={relationship.id}>
                  <div>
                    <strong>{relationship.label}</strong>
                    <span>{source} → {target}</span>
                  </div>
                  <div className="provenance-badges">
                    {relationship.origin ? <span>{relationship.origin}</span> : null}
                    {relationship.confidence ? <span>{relationship.confidence} confidence</span> : null}
                  </div>
                  {relationship.evidence ? <EvidenceRecords records={relationship.evidence} /> : null}
                </article>
              )
            })}
          </section>
        ) : null}

        {!selectedNode && model.snapshot.analysis ? (
          <section className="analysis-coverage" aria-label="Attack-path analysis coverage">
            <div className="section-heading">
              <span>ANALYSIS COVERAGE</span>
              <strong>{model.snapshot.analysis.pathSearch.truncated ? 'BOUNDED' : 'COMPLETE'}</strong>
            </div>
            <p>
              {model.snapshot.analysis.pathSearch.expansions.toLocaleString('en')} graph expansions · depth {model.snapshot.analysis.pathSearch.maxDepth} · up to {model.snapshot.analysis.pathSearch.maxPaths.toLocaleString('en')} paths
            </p>
            {model.snapshot.analysis.pathSearch.truncated ? (
              <small>{model.snapshot.analysis.pathSearch.reason || 'The configured search safety bound was reached.'}</small>
            ) : null}
          </section>
        ) : null}

        {scopedPaths.length > 0 ? (
          <section className="path-memberships">
            <div className="section-heading">
              <span>ATTACK PATH MEMBERSHIP</span>
              <strong>{scopedPaths.length}</strong>
            </div>
            {scopedPaths.map((path, index) => (
              <button key={path.id} type="button" onClick={() => onOpenPath(path.id)}>
                <span className={`path-number path-${path.severity}`}>{index + 1}</span>
                <span><strong>{path.title}</strong><small>{path.steps.length} hops · inspect story</small></span>
                <span aria-hidden="true">→</span>
              </button>
            ))}
          </section>
        ) : null}

        <section className="findings-list">
          <div className="section-heading">
            <span>{selectedNode ? 'RELATED FINDINGS' : 'PRIORITIZED FINDINGS'}</span>
            <strong>{scopedFindings.length}</strong>
          </div>
          {triageError ? <p className="triage-error" role="alert">{triageError}</p> : null}
          {scopedFindings.length > 0 ? (
            visibleFindings.map((finding) => {
              const triage = triageEnabled ? triageByFindingId.get(finding.id) : undefined
              return (
              <FindingCard
                key={`${finding.id}:${triage?.updatedAt ?? 'untriaged'}`}
                finding={finding}
                model={model}
                onSelectNode={onSelectNode}
                triage={triage}
                triagePending={triagePendingIds.has(finding.id)}
                snapshotId={model.snapshot.id}
                onUpdateTriage={onUpdateTriage}
              />
              )
            })
          ) : (
            <p className="no-findings">No findings are directly attached to this asset.</p>
          )}
          {scopedFindings.length > visibleFindings.length ? (
            <p className="result-limit-note">Showing the first {visibleFindings.length} prioritized findings.</p>
          ) : null}
        </section>
      </div>
    </aside>
  )
}
