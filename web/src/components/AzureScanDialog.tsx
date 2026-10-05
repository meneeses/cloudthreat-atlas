import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import {
  cancelAzureScan,
  monitorAzureScan,
  startAzureScan,
} from '../data/snapshot-client'
import type { AzureScanEvent, AzureScanJob } from '../types'

const phases = ['authentication', 'resources', 'RBAC', 'normalization', 'analysis', 'save', 'complete']

function terminal(status: AzureScanJob['status']): boolean {
  return status === 'completed'
    || status === 'failed'
    || status === 'cancelled'
    || status === 'interrupted'
}

interface AzureScanDialogProps {
  open: boolean
  csrfToken: string
  onClose: () => void
  onCompleted: (snapshotId: string) => Promise<void>
}

export function AzureScanDialog({
  open,
  csrfToken,
  onClose,
  onCompleted,
}: AzureScanDialogProps) {
  const dialog = useRef<HTMLDivElement>(null)
  const previousFocus = useRef<HTMLElement | null>(null)
  const [subscriptionId, setSubscriptionId] = useState('')
  const [resourceGroup, setResourceGroup] = useState('')
  const [jobId, setJobId] = useState<string | null>(null)
  const [job, setJob] = useState<AzureScanJob | null>(null)
  const [events, setEvents] = useState<AzureScanEvent[]>([])
  const [transport, setTransport] = useState<'events' | 'polling' | null>(null)
  const [starting, setStarting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [openingSnapshot, setOpeningSnapshot] = useState(false)
  const [snapshotOpenError, setSnapshotOpenError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const handledSnapshot = useRef<string | null>(null)

  const openCompletedSnapshot = useCallback(async (snapshotId: string) => {
    if (handledSnapshot.current === snapshotId) return
    handledSnapshot.current = snapshotId
    setOpeningSnapshot(true)
    setSnapshotOpenError(null)
    setError(null)
    try {
      await onCompleted(snapshotId)
    } catch (reason) {
      handledSnapshot.current = null
      setSnapshotOpenError(
        reason instanceof Error ? reason.message : 'The completed snapshot could not be opened.',
      )
    } finally {
      setOpeningSnapshot(false)
    }
  }, [onCompleted])

  useEffect(() => {
    if (!jobId) return undefined
    const controller = new AbortController()
    const stop = monitorAzureScan(jobId, {
      onJob: (nextJob) => {
        setJob(nextJob)
        if (nextJob.status === 'completed' && nextJob.snapshotId) {
          void openCompletedSnapshot(nextJob.snapshotId)
        }
      },
      onEvent: (event) => {
        setEvents((current) => {
          if (current.some((candidate) => candidate.sequence === event.sequence)) return current
          return [...current, event].slice(-30)
        })
      },
      onTransport: setTransport,
      onError: (reason) => setError(reason.message),
    }, controller.signal)
    return () => {
      controller.abort()
      stop()
    }
  }, [jobId, openCompletedSnapshot])

  useEffect(() => {
    if (!open) return undefined
    previousFocus.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null
    window.requestAnimationFrame(() => dialog.current?.focus())
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
      if (event.key !== 'Tab' || !dialog.current) return
      const focusable = [...dialog.current.querySelectorAll<HTMLElement>(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      )]
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
    window.addEventListener('keydown', keyboard)
    return () => {
      window.removeEventListener('keydown', keyboard)
      previousFocus.current?.focus()
    }
  }, [onClose, open])

  const observedPhases = useMemo(
    () => new Set(events.map((event) => event.phase).concat(job?.phase ?? [])),
    [events, job?.phase],
  )
  const active = job ? !terminal(job.status) : Boolean(jobId)

  const start = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setStarting(true)
    setError(null)
    setJob(null)
    setEvents([])
    setTransport(null)
    setSnapshotOpenError(null)
    handledSnapshot.current = null
    try {
      const result = await startAzureScan({ subscriptionId, resourceGroup }, csrfToken)
      setJobId(result.jobId)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The Azure scan could not be started.')
    } finally {
      setStarting(false)
    }
  }

  const cancel = async () => {
    if (!jobId) return
    setCancelling(true)
    setError(null)
    try {
      await cancelAzureScan(jobId, csrfToken)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The scan could not be cancelled.')
    } finally {
      setCancelling(false)
    }
  }

  const reset = () => {
    setJobId(null)
    setJob(null)
    setEvents([])
    setTransport(null)
    setError(null)
    setSnapshotOpenError(null)
    handledSnapshot.current = null
  }

  if (!open) return null

  return (
    <div className="scan-dialog-layer">
      <button className="scan-dialog-backdrop" type="button" aria-label="Close Azure scan" onClick={onClose} />
      <div
        ref={dialog}
        className="scan-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-dialog-title"
        tabIndex={-1}
      >
        <header>
          <div>
            <span className="eyebrow">READ-ONLY AZURE DISCOVERY</span>
            <h2 id="scan-dialog-title">Scan an Azure scope</h2>
          </div>
          <button type="button" onClick={onClose} aria-label="Close Azure scan">×</button>
        </header>

        {!jobId ? (
          <form className="scan-form" onSubmit={(event) => { void start(event) }}>
            <p>
              Atlas uses your local Azure credential and Resource Graph access. It never requests
              a token here, reads secret values, or changes cloud resources.
            </p>
            <label>
              <span>Subscription ID</span>
              <input
                required
                autoFocus
                value={subscriptionId}
                placeholder="00000000-0000-0000-0000-000000000000"
                pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                spellCheck="false"
                autoComplete="off"
                onChange={(event) => setSubscriptionId(event.target.value)}
              />
            </label>
            <label>
              <span>Resource group <small>optional</small></span>
              <input
                value={resourceGroup}
                placeholder="Scan the whole subscription"
                spellCheck="false"
                autoComplete="off"
                onChange={(event) => setResourceGroup(event.target.value)}
              />
            </label>
            <button className="scan-primary" type="submit" disabled={starting}>
              {starting ? 'Starting scan…' : 'Start read-only scan'}
            </button>
          </form>
        ) : (
          <section className="scan-progress" aria-live="polite">
            <div className="scan-status-line">
              <span className={`scan-status scan-status-${job?.status ?? 'queued'}`}>
                {job?.status ?? 'queued'}
              </span>
              <span>{transport === 'events' ? 'Live progress' : transport === 'polling' ? 'Polling fallback' : 'Connecting…'}</span>
            </div>
            <ol className="scan-phases">
              {phases.map((phase) => (
                <li
                  key={phase}
                  className={`${observedPhases.has(phase) ? 'is-reached' : ''} ${job?.phase === phase ? 'is-current' : ''}`}
                >
                  <i aria-hidden="true" />
                  <span>{phase === 'RBAC' ? phase : phase.replace('-', ' ')}</span>
                </li>
              ))}
            </ol>
            <div className="scan-latest">
              <span className="eyebrow">LATEST UPDATE</span>
              <strong>{events.at(-1)?.message ?? job?.phase ?? 'Waiting for the collector…'}</strong>
            </div>
            {job?.error ? <p className="scan-error" role="alert">{job.error}</p> : null}
            {job?.status === 'completed' ? (
              <p className="scan-success" role="status">
                {openingSnapshot
                  ? 'Opening the new snapshot…'
                  : snapshotOpenError
                    ? 'Scan complete, but the new snapshot could not be opened.'
                    : 'Scan complete. The new snapshot is open.'}
              </p>
            ) : null}
            <div className="scan-dialog-actions">
              {active ? (
                <button type="button" onClick={() => { void cancel() }} disabled={cancelling}>
                  {cancelling ? 'Cancelling…' : 'Cancel scan'}
                </button>
              ) : (
                <>
                  {snapshotOpenError && job?.status === 'completed' && job.snapshotId ? (
                    <button
                      type="button"
                      onClick={() => { void openCompletedSnapshot(job.snapshotId!) }}
                      disabled={openingSnapshot}
                    >
                      {openingSnapshot ? 'Opening snapshot…' : 'Retry opening snapshot'}
                    </button>
                  ) : null}
                  <button type="button" onClick={reset} disabled={openingSnapshot}>New scan</button>
                </>
              )}
              <button type="button" onClick={onClose}>{active ? 'Run in background' : 'Done'}</button>
            </div>
          </section>
        )}
        {snapshotOpenError ? <p className="scan-error" role="alert">{snapshotOpenError}</p> : null}
        {error ? <p className="scan-error" role="alert">{error}</p> : null}
      </div>
    </div>
  )
}
