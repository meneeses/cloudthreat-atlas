import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const scanClientMocks = vi.hoisted(() => ({
  cancelAzureScan: vi.fn(),
  monitorAzureScan: vi.fn(),
  startAzureScan: vi.fn(),
}))

vi.mock('../data/snapshot-client', async () => {
  const actual = await vi.importActual<typeof import('../data/snapshot-client')>(
    '../data/snapshot-client',
  )
  return { ...actual, ...scanClientMocks }
})

import { AzureScanDialog } from './AzureScanDialog'
import { DetailsPanel } from './DetailsPanel'
import { FilterBar } from './FilterBar'
import { SimulationPanel } from './SimulationPanel'
import { StoryMode } from './StoryMode'
import { WorkspaceBar } from './WorkspaceBar'
import { deriveSimulations, type AtlasFilters } from '../lib/atlas'
import { createAtlasViewModel } from '../lib/view-model'
import { demoSnapshot } from '../test/fixture'
import type { AzureScanEvent, AzureScanJob } from '../types'

const initialFilters: AtlasFilters = {
  query: '',
  severity: 'all',
  type: 'all',
  attackPathId: 'all',
}

const filterExtras = {
  totalMatching: 13,
  truncated: false,
  graphMode: 'overview' as const,
  performanceMode: false,
  canUseNeighborhood: false,
  onGraphModeChange: vi.fn(),
  onTogglePerformance: vi.fn(),
}

describe('FilterBar', () => {
  it('emits search and combined filter changes, then clears them', () => {
    const onChange = vi.fn()
    const { rerender } = render(
      <FilterBar
        filters={initialFilters}
        resourceTypes={['Microsoft.Web/sites']}
        paths={demoSnapshot.attackPaths}
        visibleCount={13}
        totalCount={13}
        onChange={onChange}
        {...filterExtras}
      />,
    )

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search resources' }), {
      target: { value: 'clinical' },
    })
    expect(onChange).toHaveBeenLastCalledWith({ ...initialFilters, query: 'clinical' })

    screen.getByRole('searchbox', { name: 'Search resources' }).blur()
    fireEvent.keyDown(document.body, { key: '/', code: 'Slash' })
    expect(screen.getByRole('searchbox', { name: 'Search resources' })).toHaveFocus()

    const activeFilters = { ...initialFilters, severity: 'critical' as const }
    rerender(
      <FilterBar
        filters={activeFilters}
        resourceTypes={['Microsoft.Web/sites']}
        paths={demoSnapshot.attackPaths}
        visibleCount={3}
        totalCount={13}
        onChange={onChange}
        {...filterExtras}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onChange).toHaveBeenLastCalledWith(initialFilters)
  })
})

describe('DetailsPanel', () => {
  it('selects an asset from a finding and renders its intelligence view', () => {
    const onSelectNode = vi.fn()
    const props = {
      snapshotName: demoSnapshot.name,
      model: createAtlasViewModel(demoSnapshot),
      open: true,
      onClose: vi.fn(),
      onSelectNode,
      onOpenPath: vi.fn(),
    }
    const { rerender } = render(<DetailsPanel {...props} selectedNode={null} />)

    fireEvent.click(screen.getByRole('button', { name: 'Security Platform Pipeline' }))
    expect(onSelectNode).toHaveBeenCalledWith('pipeline-ci-security')

    const clinicalApi = demoSnapshot.resources.find((resource) => resource.id === 'app-clinical-api')!
    rerender(<DetailsPanel {...props} selectedNode={clinicalApi} />)
    expect(screen.getByRole('heading', { name: 'Clinical API' })).toBeInTheDocument()
    expect(screen.getByText('ATTACK PATH MEMBERSHIP')).toBeInTheDocument()
  })

  it('edits carried-forward triage with an explicit save', () => {
    const finding = demoSnapshot.findings[0]!
    const onUpdateTriage = vi.fn()
    render(
      <DetailsPanel
        snapshotName={demoSnapshot.name}
        model={createAtlasViewModel(demoSnapshot)}
        selectedNode={null}
        open
        onClose={vi.fn()}
        onSelectNode={vi.fn()}
        onOpenPath={vi.fn()}
        triageEnabled
        triageByFindingId={new Map([[finding.id, {
          snapshotId: demoSnapshot.id,
          environmentId: 'azure:subscription:demo',
          findingId: finding.id,
          fingerprint: 'rule|resource',
          status: 'open',
          notes: 'Awaiting owner review.',
          firstSeenSnapshotId: 'older-snapshot',
          lastSeenSnapshotId: demoSnapshot.id,
          updatedAt: '2026-10-05T00:00:00Z',
        }]])}
        onUpdateTriage={onUpdateTriage}
      />,
    )

    expect(screen.getByText('Carried forward')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'resolved' } })
    fireEvent.change(screen.getByLabelText('Notes'), { target: { value: 'Fixed in the current release.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save triage' }))
    expect(onUpdateTriage).toHaveBeenCalledWith(
      finding.id,
      'resolved',
      'Fixed in the current release.',
    )
  })

  it('shows relationship provenance, confidence, and structured evidence', () => {
    const firstRelationship = demoSnapshot.relationships[0]!
    const snapshot = {
      ...demoSnapshot,
      relationships: demoSnapshot.relationships.map((relationship, index) => index === 0 ? {
        ...relationship,
        origin: 'observed' as const,
        confidence: 'high' as const,
        evidence: [{
          source: 'Azure Resource Graph',
          resourceId: relationship.source,
          field: 'properties.publicNetworkAccess',
          value: 'Enabled',
        }],
      } : relationship),
    }
    const model = createAtlasViewModel(snapshot)
    render(
      <DetailsPanel
        snapshotName={snapshot.name}
        model={model}
        selectedNode={model.resourceById.get(firstRelationship.source) ?? null}
        open
        onClose={vi.fn()}
        onSelectNode={vi.fn()}
        onOpenPath={vi.fn()}
      />,
    )

    expect(screen.getByText('EVIDENCE PROVENANCE')).toBeInTheDocument()
    expect(screen.getByText('observed')).toBeInTheDocument()
    expect(screen.getByText('high confidence')).toBeInTheDocument()
    expect(screen.getByText('Azure Resource Graph')).toBeInTheDocument()
    expect(screen.getByText('properties.publicNetworkAccess = Enabled')).toBeInTheDocument()
  })
})

describe('WorkspaceBar', () => {
  it('selects a historical snapshot and exposes local import', () => {
    const onSelectSnapshot = vi.fn()
    const onOpenAzureScan = vi.fn()
    const snapshots = [
      { id: 'one', environmentId: 'prod', name: 'Production', provider: 'azure', generatedAt: '2026-01-01T00:00:00Z', riskScore: 90, resourceCount: 1, relationshipCount: 1, findingCount: 1, attackPathCount: 1, origin: 'api' as const },
      { id: 'two', environmentId: 'prod', name: 'Production', provider: 'azure', generatedAt: '2026-01-02T00:00:00Z', riskScore: 80, resourceCount: 2, relationshipCount: 1, findingCount: 1, attackPathCount: 1, origin: 'api' as const },
      { id: 'other', environmentId: 'dev', name: 'Development', provider: 'azure', generatedAt: '2026-01-03T00:00:00Z', riskScore: 20, resourceCount: 3, relationshipCount: 0, findingCount: 0, attackPathCount: 0, origin: 'api' as const },
    ]
    render(
      <WorkspaceBar
        snapshots={snapshots}
        activeSnapshotId="one"
        loading={false}
        importError={null}
        comparison={null}
        comparisonBaseId=""
        comparisonLoading={false}
        comparisonError={null}
        onSelectSnapshot={onSelectSnapshot}
        onImport={vi.fn()}
        onSelectComparisonBase={vi.fn()}
        onClearComparison={vi.fn()}
        canScanAzure
        onOpenAzureScan={onOpenAzureScan}
      />,
    )
    fireEvent.change(screen.getByLabelText('Active snapshot'), { target: { value: 'two' } })
    expect(onSelectSnapshot).toHaveBeenCalledWith('two')
    const comparison = screen.getByLabelText('Compare with')
    expect(comparison).toHaveTextContent('Production')
    expect(comparison).not.toHaveTextContent('Development')
    expect(screen.getByRole('button', { name: 'Import snapshot' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Scan Azure' }))
    expect(onOpenAzureScan).toHaveBeenCalledOnce()
  })
})

describe('AzureScanDialog', () => {
  beforeEach(() => {
    scanClientMocks.cancelAzureScan.mockReset()
    scanClientMocks.monitorAzureScan.mockReset()
    scanClientMocks.startAzureScan.mockReset()
    scanClientMocks.cancelAzureScan.mockResolvedValue(undefined)
    scanClientMocks.monitorAzureScan.mockReturnValue(vi.fn())
    scanClientMocks.startAzureScan.mockResolvedValue({ jobId: 'scan-1', status: 'queued' })
  })

  it('explains local credentials and exposes only scope inputs', () => {
    const onClose = vi.fn()
    render(
      <AzureScanDialog
        open
        csrfToken="local-token"
        onClose={onClose}
        onCompleted={vi.fn()}
      />,
    )

    expect(screen.getByRole('dialog', { name: 'Scan an Azure scope' })).toBeInTheDocument()
    expect(screen.getByText(/never requests a token here/i)).toBeInTheDocument()
    expect(screen.getByLabelText('Subscription ID')).toHaveAttribute('autocomplete', 'off')
    expect(screen.getByLabelText(/Resource group/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/secret|password|credential/i)).not.toBeInTheDocument()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('retries opening a completed snapshot after a transient failure', async () => {
    const completedJob: AzureScanJob = {
      id: 'scan-1',
      provider: 'azure',
      scope: { subscriptionId: '00000000-0000-0000-0000-000000000001' },
      status: 'completed',
      phase: 'complete',
      snapshotId: 'snapshot-from-scan',
      revision: 2,
      createdAt: '2026-10-05T00:00:00Z',
      updatedAt: '2026-10-05T00:01:00Z',
      completedAt: '2026-10-05T00:01:00Z',
    }
    scanClientMocks.monitorAzureScan.mockImplementation((
      _jobId: string,
      handlers: {
        onJob: (job: AzureScanJob) => void
        onEvent: (event: AzureScanEvent) => void
        onTransport: (transport: 'events' | 'polling') => void
        onError: (error: Error) => void
      },
    ) => {
      handlers.onTransport('events')
      handlers.onJob(completedJob)
      return vi.fn()
    })
    const onCompleted = vi.fn()
      .mockRejectedValueOnce(new Error('Catalog refresh failed.'))
      .mockResolvedValueOnce(undefined)

    render(
      <AzureScanDialog
        open
        csrfToken="local-token"
        onClose={vi.fn()}
        onCompleted={onCompleted}
      />,
    )
    fireEvent.change(screen.getByLabelText('Subscription ID'), {
      target: { value: completedJob.scope.subscriptionId },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Start read-only scan' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Catalog refresh failed.')
    expect(onCompleted).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Retry opening snapshot' }))

    await waitFor(() => expect(onCompleted).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('Scan complete. The new snapshot is open.')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Retry opening snapshot' }))
      .not.toBeInTheDocument()
  })
})

describe('StoryMode', () => {
  it('starts a story and exposes navigation and exit controls', () => {
    const onStart = vi.fn()
    const controls = {
      onStart,
      onStop: vi.fn(),
      onPrevious: vi.fn(),
      onNext: vi.fn(),
      onTogglePlaying: vi.fn(),
    }
    const firstPath = demoSnapshot.attackPaths[0]!
    const { rerender } = render(
      <StoryMode
        paths={demoSnapshot.attackPaths}
        nodes={demoSnapshot.resources}
        activePath={null}
        storyStep={0}
        playing={false}
        {...controls}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: new RegExp(firstPath.title) }))
    expect(onStart).toHaveBeenCalledWith(firstPath.id)

    rerender(
      <StoryMode
        paths={demoSnapshot.attackPaths}
        nodes={demoSnapshot.resources}
        activePath={firstPath}
        storyStep={1}
        playing={false}
        {...controls}
      />,
    )
    expect(screen.getByText('Step 2 of 5')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next step' }))
    fireEvent.click(screen.getByRole('button', { name: 'Play story' }))
    fireEvent.click(screen.getByRole('button', { name: 'Exit story' }))
    expect(controls.onNext).toHaveBeenCalledOnce()
    expect(controls.onTogglePlaying).toHaveBeenCalledOnce()
    expect(controls.onStop).toHaveBeenCalledOnce()
  })
})

describe('SimulationPanel', () => {
  const simulations = deriveSimulations(demoSnapshot)
  const selectedSimulationId = simulations[0]!.id

  it('shows the verified precomputed impact for the static fixture', () => {
    render(
      <SimulationPanel
        snapshot={demoSnapshot}
        simulations={simulations}
        selectedSimulationId={selectedSimulationId}
        onSelectSimulation={vi.fn()}
        result={null}
        loading={false}
        error={null}
        source="fixture"
      />,
    )

    expect(screen.getByText('RISK SCORE')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
    expect(screen.getByText('PRECOMPUTED SAFE PREVIEW')).toBeInTheDocument()
  })

  it('does not display an estimated score after a live API failure', () => {
    render(
      <SimulationPanel
        snapshot={demoSnapshot}
        simulations={simulations}
        selectedSimulationId={selectedSimulationId}
        onSelectSimulation={vi.fn()}
        result={null}
        loading={false}
        error="Simulation request failed."
        source="api"
      />,
    )

    expect(screen.getByRole('alert')).toHaveTextContent('Live impact is unavailable')
    expect(screen.queryByText('RISK SCORE')).not.toBeInTheDocument()
    expect(screen.queryByText('80')).not.toBeInTheDocument()
  })
})
