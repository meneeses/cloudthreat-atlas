import type { AttackPath, Finding, ResourceNode } from '../types'
import { findingsForNode, pathsForNode } from '../lib/atlas'
import { resourceSeverity, riskForResource } from '../lib/atlas'
import { formatSeverity } from '../lib/severity'

interface DetailsPanelProps {
  snapshotName: string
  nodes: ResourceNode[]
  findings: Finding[]
  paths: AttackPath[]
  selectedNode: ResourceNode | null
  open: boolean
  onClose: () => void
  onSelectNode: (nodeId: string) => void
  onOpenPath: (pathId: string) => void
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
  nodes,
  onSelectNode,
}: {
  finding: Finding
  nodes: ResourceNode[]
  onSelectNode: (nodeId: string) => void
}) {
  const firstResource = nodes.find((node) => finding.resourceIds.includes(node.id))
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
          <span className="eyebrow">RECOMMENDED FIX</span>
          <p>{finding.remediation.summary}</p>
          {finding.remediation.steps.length > 0 ? (
            <ol>{finding.remediation.steps.map((step) => <li key={step}>{step}</li>)}</ol>
          ) : null}
        </div>
      </details>
    </article>
  )
}

export function DetailsPanel({
  snapshotName,
  nodes,
  findings,
  paths,
  selectedNode,
  open,
  onClose,
  onSelectNode,
  onOpenPath,
}: DetailsPanelProps) {
  const scopedFindings = selectedNode ? findingsForNode(findings, selectedNode.id) : findings
  const scopedPaths = selectedNode ? pathsForNode(paths, selectedNode.id) : []
  const selectedSeverity = selectedNode ? resourceSeverity(selectedNode) : 'info'
  const selectedRisk = selectedNode ? riskForResource(selectedNode, findings) : 0

  return (
    <aside className={`details-panel ${open ? 'is-open' : ''}`} aria-label="Asset intelligence">
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
          {scopedFindings.length > 0 ? (
            scopedFindings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                nodes={nodes}
                onSelectNode={onSelectNode}
              />
            ))
          ) : (
            <p className="no-findings">No findings are directly attached to this asset.</p>
          )}
        </section>
      </div>
    </aside>
  )
}
