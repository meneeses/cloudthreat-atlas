import { useRef, type ChangeEvent } from 'react'
import type { SnapshotComparison, SnapshotSummary } from '../types'

interface WorkspaceBarProps {
  snapshots: SnapshotSummary[]
  activeSnapshotId: string
  loading: boolean
  importError: string | null
  comparison: SnapshotComparison | null
  comparisonBaseId: string
  comparisonLoading: boolean
  comparisonError: string | null
  onSelectSnapshot: (snapshotId: string) => void
  onImport: (file: File) => void
  onSelectComparisonBase: (snapshotId: string) => void
  onClearComparison: () => void
  canScanAzure?: boolean
  onOpenAzureScan?: () => void
}

function signed(value: number): string {
  if (value > 0) return `+${value}`
  return String(value)
}

export function WorkspaceBar({
  snapshots,
  activeSnapshotId,
  loading,
  importError,
  comparison,
  comparisonBaseId,
  comparisonLoading,
  comparisonError,
  onSelectSnapshot,
  onImport,
  onSelectComparisonBase,
  onClearComparison,
  canScanAzure = false,
  onOpenAzureScan,
}: WorkspaceBarProps) {
  const fileInput = useRef<HTMLInputElement>(null)
  const active = snapshots.find((snapshot) => snapshot.id === activeSnapshotId)
  const comparisonCandidates = snapshots.filter((snapshot) => (
    snapshot.id !== activeSnapshotId
    && (!active?.environmentId || snapshot.environmentId === active.environmentId)
  ))
  const snapshotGroups = new Map<string, SnapshotSummary[]>()
  for (const snapshot of snapshots) {
    const key = snapshot.environmentId ?? `standalone:${snapshot.origin}`
    const group = snapshotGroups.get(key)
    if (group) group.push(snapshot)
    else snapshotGroups.set(key, [snapshot])
  }

  const importFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) onImport(file)
    event.target.value = ''
  }

  return (
    <section className="workspace-bar" aria-label="Snapshot workspace">
      <div className="workspace-history">
        <span className="eyebrow">SNAPSHOT HISTORY</span>
        <label>
          <span className="sr-only">Active snapshot</span>
          <select
            value={activeSnapshotId}
            onChange={(event) => onSelectSnapshot(event.target.value)}
            disabled={loading}
          >
            {[...snapshotGroups.entries()].map(([environmentId, group]) => (
              <optgroup
                key={environmentId}
                label={group[0]?.name ?? 'Local environment'}
              >
                {group.map((snapshot) => (
                  <option key={`${snapshot.origin}:${snapshot.id}`} value={snapshot.id}>
                    {snapshot.name} · {new Date(snapshot.generatedAt).toLocaleDateString('en')} · risk {snapshot.riskScore}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>
        {active ? <span className={`origin-badge origin-${active.origin}`}>{active.origin}</span> : null}
      </div>

      <div className="workspace-actions">
        {comparisonCandidates.length > 0 ? (
          <label className="compare-control">
            <span>Compare with</span>
            <select
              value={comparisonBaseId}
              onChange={(event) => onSelectComparisonBase(event.target.value)}
              disabled={comparisonLoading}
            >
              <option value="">No comparison</option>
              {comparisonCandidates.map((snapshot) => (
                <option key={`${snapshot.origin}:${snapshot.id}`} value={snapshot.id}>
                  {snapshot.name} · {new Date(snapshot.generatedAt).toLocaleDateString('en')}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {canScanAzure && onOpenAzureScan ? (
          <button className="scan-button" type="button" onClick={onOpenAzureScan}>
            Scan Azure
          </button>
        ) : null}
        <button className="import-button" type="button" onClick={() => fileInput.current?.click()}>
          Import snapshot
        </button>
        <input
          ref={fileInput}
          className="sr-only"
          type="file"
          accept="application/json,.json"
          onChange={importFile}
        />
      </div>

      {loading ? <span className="workspace-status" role="status">Loading snapshot…</span> : null}
      {importError ? <span className="workspace-error" role="alert">{importError}</span> : null}
      {comparisonError ? <span className="workspace-error" role="alert">{comparisonError}</span> : null}
      {comparison ? (
        <div className="comparison-strip" aria-live="polite">
          <span><small>RISK</small><strong>{signed(comparison.riskScoreDelta)}</strong></span>
          <span><small>ASSETS</small><strong>{signed(comparison.resourceDelta)}</strong></span>
          <span><small>FINDINGS</small><strong>{signed(comparison.findingDelta)}</strong></span>
          <span><small>PATHS</small><strong>{signed(comparison.attackPathDelta)}</strong></span>
          <button type="button" onClick={onClearComparison} aria-label="Close comparison">×</button>
        </div>
      ) : null}
    </section>
  )
}

export function EmptyWorkspace({
  onImport,
  error,
  canScanAzure = false,
  onOpenAzureScan,
}: {
  onImport: (file: File) => void
  error?: string | null
  canScanAzure?: boolean
  onOpenAzureScan?: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  return (
    <main className="empty-workspace">
      <span className="empty-orbit" aria-hidden="true">◎</span>
      <span className="eyebrow">LOCAL-FIRST WORKSPACE</span>
      <h1>Bring an Azure snapshot into focus.</h1>
      <p>
        Import an Atlas JSON snapshot or start the local Go API. Files are validated in your
        browser and, when connected, stored only by your loopback Atlas workspace.
      </p>
      {error ? <p className="empty-error" role="alert">{error}</p> : null}
      <div>
        {canScanAzure && onOpenAzureScan ? (
          <button type="button" onClick={onOpenAzureScan}>Scan Azure</button>
        ) : null}
        <button type="button" onClick={() => input.current?.click()}>Import JSON snapshot</button>
        <code>atlas app</code>
      </div>
      <input
        ref={input}
        className="sr-only"
        type="file"
        accept="application/json,.json"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) onImport(file)
          event.target.value = ''
        }}
      />
    </main>
  )
}
