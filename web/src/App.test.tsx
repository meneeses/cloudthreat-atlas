import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { demoSnapshot } from './test/fixture'

const clientMocks = vi.hoisted(() => ({
  loadWorkspace: vi.fn(),
  loadSnapshotById: vi.fn(),
  loadTriage: vi.fn(),
  parseImportedSnapshot: vi.fn(),
  updateTriage: vi.fn(),
}))

vi.mock('./components/GraphView', () => ({
  default: () => <div aria-label="Mock attack graph" />,
}))

vi.mock('./data/snapshot-client', async () => {
  const actual = await vi.importActual<typeof import('./data/snapshot-client')>(
    './data/snapshot-client',
  )
  return { ...actual, ...clientMocks }
})

import App from './App'
import { WorkspaceSessionExpiredError } from './data/snapshot-client'

describe('App triage workflow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    clientMocks.loadTriage.mockResolvedValue([])
    clientMocks.parseImportedSnapshot.mockResolvedValue(demoSnapshot)
    clientMocks.loadWorkspace.mockResolvedValue({
      bootstrap: {
        snapshots: [{
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
        }],
        currentSnapshotId: demoSnapshot.id,
        source: 'api',
        capabilities: {
          history: false,
          comparison: true,
          import: true,
          triage: true,
          azureScans: true,
        },
        csrfToken: 'local-token',
      },
      initialSnapshot: { snapshot: demoSnapshot, source: 'api' },
    })
  })

  it('rolls an optimistic triage edit back when persistence fails', async () => {
    const finding = demoSnapshot.findings[0]!
    const record = {
      snapshotId: demoSnapshot.id,
      environmentId: 'azure:subscription:demo',
      findingId: finding.id,
      fingerprint: 'rule|resource',
      status: 'open',
      notes: 'Original review note.',
      firstSeenSnapshotId: demoSnapshot.id,
      lastSeenSnapshotId: demoSnapshot.id,
      updatedAt: '2026-10-05T00:00:00Z',
    }
    clientMocks.loadTriage.mockResolvedValue([record])
    clientMocks.updateTriage.mockRejectedValue(new Error('Workspace write failed.'))

    render(<App />)
    fireEvent.click(await screen.findByLabelText('Open intelligence panel'))
    const status = await screen.findByLabelText('Status')
    const notes = screen.getByLabelText('Notes')

    fireEvent.change(status, { target: { value: 'resolved' } })
    fireEvent.change(notes, { target: { value: 'Temporary optimistic note.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save triage' }))

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(
      'Your previous value was restored.',
    ))
    expect(screen.getByLabelText('Status')).toHaveValue('open')
    expect(screen.getByLabelText('Notes')).toHaveValue('Original review note.')
    expect(clientMocks.updateTriage).toHaveBeenCalledWith(
      demoSnapshot.id,
      finding.id,
      'resolved',
      'Temporary optimistic note.',
      'local-token',
      expect.any(AbortSignal),
    )
  })

  it('serializes triage updates and rolls B back to confirmed A when B fails', async () => {
    const finding = demoSnapshot.findings[0]!
    const record = {
      snapshotId: demoSnapshot.id,
      environmentId: 'azure:subscription:demo',
      findingId: finding.id,
      fingerprint: 'rule|resource',
      status: 'open',
      notes: 'Confirmed server note.',
      firstSeenSnapshotId: demoSnapshot.id,
      lastSeenSnapshotId: demoSnapshot.id,
      updatedAt: '2026-10-05T00:00:00Z',
    }
    const savedA = {
      ...record,
      status: 'resolved',
      notes: 'Confirmed update A.',
      updatedAt: '2026-10-05T00:01:00Z',
    }
    let resolveFirst!: (value: typeof savedA) => void
    let firstSignal: AbortSignal | undefined
    clientMocks.loadTriage.mockResolvedValue([record])
    clientMocks.updateTriage
      .mockImplementationOnce((
        _snapshotId: string,
        _findingId: string,
        _status: string,
        _notes: string,
        _csrfToken: string,
        signal: AbortSignal,
      ) => new Promise((resolve) => {
        firstSignal = signal
        resolveFirst = resolve
      }))
      .mockRejectedValueOnce(new Error('Second workspace write failed.'))

    render(<App />)
    fireEvent.click(await screen.findByLabelText('Open intelligence panel'))
    fireEvent.change(await screen.findByLabelText('Status'), { target: { value: 'resolved' } })
    fireEvent.change(screen.getByLabelText('Notes'), {
      target: { value: savedA.notes },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save triage' }))

    const pendingStatus = await screen.findByLabelText('Status')
    await waitFor(() => expect(clientMocks.updateTriage).toHaveBeenCalledTimes(1))
    fireEvent.change(pendingStatus, { target: { value: 'acknowledged' } })
    fireEvent.change(screen.getByLabelText('Notes'), {
      target: { value: 'Queued update B.' },
    })
    fireEvent.submit(pendingStatus.closest('form')!)

    expect(clientMocks.updateTriage).toHaveBeenCalledTimes(1)
    resolveFirst(savedA)
    await waitFor(() => expect(clientMocks.updateTriage).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(
      'Your previous value was restored.',
    ))
    expect(firstSignal?.aborted).toBe(false)
    expect(clientMocks.updateTriage.mock.calls[1]?.slice(0, 4)).toEqual([
      demoSnapshot.id,
      finding.id,
      'acknowledged',
      'Queued update B.',
    ])
    expect(screen.getByLabelText('Status')).toHaveValue('resolved')
    expect(screen.getByLabelText('Notes')).toHaveValue(savedA.notes)
  })

  it('keeps a bounded-view notice when returning to a cached snapshot', async () => {
    const laterSnapshot = {
      ...demoSnapshot,
      id: 'contoso-health-later',
      generatedAt: '2026-10-05T12:00:00Z',
    }
    const summary = (snapshot: typeof demoSnapshot) => ({
      id: snapshot.id,
      name: snapshot.name,
      provider: snapshot.provider,
      generatedAt: snapshot.generatedAt,
      riskScore: snapshot.riskScore,
      resourceCount: snapshot.resources.length,
      relationshipCount: snapshot.relationships.length,
      findingCount: snapshot.findings.length,
      attackPathCount: snapshot.attackPaths.length,
      origin: 'api' as const,
    })
    clientMocks.loadWorkspace.mockResolvedValue({
      bootstrap: {
        snapshots: [summary(demoSnapshot), summary(laterSnapshot)],
        currentSnapshotId: demoSnapshot.id,
        source: 'api',
        capabilities: {
          history: true,
          comparison: true,
          import: true,
          triage: true,
          azureScans: false,
        },
        csrfToken: 'local-token',
      },
      initialSnapshot: {
        snapshot: demoSnapshot,
        source: 'api',
        notice: 'Performance view: bounded resources are shown.',
      },
    })
    clientMocks.loadSnapshotById.mockResolvedValue({
      snapshot: laterSnapshot,
      source: 'api',
    })

    render(<App />)
    expect(await screen.findByText('Performance view: bounded resources are shown.')).toBeVisible()
    const selector = screen.getByLabelText('Active snapshot')

    fireEvent.change(selector, { target: { value: laterSnapshot.id } })
    await waitFor(() => expect(clientMocks.loadSnapshotById).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.queryByText(
      'Performance view: bounded resources are shown.',
    )).not.toBeInTheDocument())

    fireEvent.change(selector, { target: { value: demoSnapshot.id } })
    expect(await screen.findByText('Performance view: bounded resources are shown.')).toBeVisible()
    expect(clientMocks.loadSnapshotById).toHaveBeenCalledOnce()
  })

  it('shows an explicit expired-session screen instead of demo data', async () => {
    clientMocks.loadWorkspace.mockRejectedValue(new WorkspaceSessionExpiredError())

    render(<App />)

    expect(await screen.findByText('WORKSPACE SESSION EXPIRED')).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Reopen your private Atlas workspace.' }))
      .toBeVisible()
    expect(screen.getByText(/reopen the private URL printed by Atlas in your terminal/i))
      .toBeVisible()
    expect(screen.queryByText(/safe public fixture/i)).not.toBeInTheDocument()
  })

  it('clears snapshot loading when an import aborts a selection and then fails', async () => {
    const laterSnapshot = {
      ...demoSnapshot,
      id: 'contoso-health-later',
      generatedAt: '2026-10-05T12:00:00Z',
    }
    const summary = (snapshot: typeof demoSnapshot) => ({
      id: snapshot.id,
      name: snapshot.name,
      provider: snapshot.provider,
      generatedAt: snapshot.generatedAt,
      riskScore: snapshot.riskScore,
      resourceCount: snapshot.resources.length,
      relationshipCount: snapshot.relationships.length,
      findingCount: snapshot.findings.length,
      attackPathCount: snapshot.attackPaths.length,
      origin: 'api' as const,
    })
    clientMocks.loadWorkspace.mockResolvedValue({
      bootstrap: {
        snapshots: [summary(demoSnapshot), summary(laterSnapshot)],
        currentSnapshotId: demoSnapshot.id,
        source: 'api',
        capabilities: {
          history: true,
          comparison: true,
          import: false,
          triage: false,
          azureScans: false,
        },
      },
      initialSnapshot: { snapshot: demoSnapshot, source: 'api' },
    })
    clientMocks.loadSnapshotById.mockImplementation((
      _summary: unknown,
      signal?: AbortSignal,
    ) => new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
    }))
    clientMocks.parseImportedSnapshot.mockRejectedValue(new Error('Invalid imported snapshot.'))

    const { container } = render(<App />)
    const selector = await screen.findByLabelText('Active snapshot')
    fireEvent.change(selector, { target: { value: laterSnapshot.id } })
    expect(await screen.findByText('Loading snapshot…')).toBeVisible()

    const input = container.querySelector<HTMLInputElement>('.workspace-bar input[type="file"]')
    expect(input).not.toBeNull()
    fireEvent.change(input!, {
      target: { files: [new File(['invalid'], 'invalid.json', { type: 'application/json' })] },
    })

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid imported snapshot.')
    await waitFor(() => expect(screen.queryByText('Loading snapshot…')).not.toBeInTheDocument())
    expect(selector).not.toBeDisabled()
  })
})
