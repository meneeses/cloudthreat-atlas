import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DetailsPanel } from './DetailsPanel'
import { FilterBar } from './FilterBar'
import { SimulationPanel } from './SimulationPanel'
import { StoryMode } from './StoryMode'
import { deriveSimulations, type AtlasFilters } from '../lib/atlas'
import { demoSnapshot } from '../test/fixture'

const initialFilters: AtlasFilters = {
  query: '',
  severity: 'all',
  type: 'all',
  attackPathId: 'all',
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
      />,
    )

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search resources' }), {
      target: { value: 'clinical' },
    })
    expect(onChange).toHaveBeenLastCalledWith({ ...initialFilters, query: 'clinical' })

    const activeFilters = { ...initialFilters, severity: 'critical' as const }
    rerender(
      <FilterBar
        filters={activeFilters}
        resourceTypes={['Microsoft.Web/sites']}
        paths={demoSnapshot.attackPaths}
        visibleCount={3}
        totalCount={13}
        onChange={onChange}
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
      nodes: demoSnapshot.resources,
      findings: demoSnapshot.findings,
      paths: demoSnapshot.attackPaths,
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
