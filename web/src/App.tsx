import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { DetailsPanel } from './components/DetailsPanel'
import { FilterBar } from './components/FilterBar'
import { Header } from './components/Header'
import { KpiRibbon } from './components/KpiRibbon'
import { SimulationPanel } from './components/SimulationPanel'
import { StoryMode } from './components/StoryMode'
import { loadSnapshot, runSimulation } from './data/snapshot-client'
import { deriveSimulations, filterAtlas, type AtlasFilters } from './lib/atlas'
import type { SimulationResult, SnapshotEnvelope } from './types'

const GraphView = lazy(() => import('./components/GraphView'))

const initialFilters: AtlasFilters = {
  query: '',
  severity: 'all',
  type: 'all',
  attackPathId: 'all',
}

function LoadingScreen() {
  return (
    <main className="loading-screen" aria-busy="true" aria-label="Loading attack surface">
      <div className="loading-brand">
        <span className="brand-mark loading-mark" aria-hidden="true"><span /><span /><span /></span>
        <span>CLOUDTHREAT <strong>ATLAS</strong></span>
      </div>
      <div className="scanner-line" />
      <div className="loading-copy">
        <span>BUILDING ATTACK GRAPH</span>
        <strong>Mapping relationships and evaluating exposure…</strong>
      </div>
    </main>
  )
}

function ErrorScreen({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <main className="error-screen">
      <span className="error-symbol" aria-hidden="true">!</span>
      <span className="eyebrow">SNAPSHOT LOAD FAILED</span>
      <h1>The attack graph could not be initialized.</h1>
      <p>{message}</p>
      <button type="button" onClick={onRetry}>Retry loading the safe demo</button>
    </main>
  )
}

export default function App() {
  const [envelope, setEnvelope] = useState<SnapshotEnvelope | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [retryKey, setRetryKey] = useState(0)
  const [filters, setFilters] = useState<AtlasFilters>(initialFilters)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [activeStoryPathId, setActiveStoryPathId] = useState<string | null>(null)
  const [storyStep, setStoryStep] = useState(0)
  const [storyPlaying, setStoryPlaying] = useState(false)
  const [selectedSimulationId, setSelectedSimulationId] = useState<string | null>(null)
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null)
  const [simulationLoading, setSimulationLoading] = useState(false)
  const [simulationError, setSimulationError] = useState<string | null>(null)
  const simulationRequest = useRef(0)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    loadSnapshot(controller.signal)
      .then(setEnvelope)
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : 'An unknown data error occurred.')
        }
      })
    return () => controller.abort()
  }, [retryKey])

  const retryLoad = () => {
    setError(null)
    setEnvelope(null)
    setRetryKey((key) => key + 1)
  }

  const snapshot = envelope?.snapshot ?? null
  const activePath = useMemo(
    () => snapshot?.attackPaths.find((path) => path.id === activeStoryPathId) ?? null,
    [activeStoryPathId, snapshot],
  )

  useEffect(() => {
    if (!storyPlaying || !activePath) return undefined
    const interval = window.setInterval(() => {
      setStoryStep((current) => {
        if (current >= activePath.resourceIds.length - 1) {
          setStoryPlaying(false)
          return current
        }
        return current + 1
      })
    }, 1800)
    return () => window.clearInterval(interval)
  }, [activePath, storyPlaying])

  const filtered = useMemo(
    () => (snapshot ? filterAtlas(snapshot, filters) : null),
    [filters, snapshot],
  )
  const resourceTypes = useMemo(
    () =>
      snapshot
        ? [...new Set(snapshot.resources.map((resource) => resource.type))].toSorted()
        : [],
    [snapshot],
  )
  const selectedNode = useMemo(
    () => snapshot?.resources.find((resource) => resource.id === selectedNodeId) ?? null,
    [selectedNodeId, snapshot],
  )
  const simulations = useMemo(
    () => (snapshot ? deriveSimulations(snapshot) : []),
    [snapshot],
  )

  if (error) {
    return <ErrorScreen message={error} onRetry={retryLoad} />
  }
  if (!snapshot || !envelope || !filtered) return <LoadingScreen />

  const startStory = (pathId: string) => {
    const path = snapshot.attackPaths.find((candidate) => candidate.id === pathId)
    if (!path) return
    setActiveStoryPathId(pathId)
    setStoryStep(0)
    setStoryPlaying(false)
    setSelectedNodeId(path.resourceIds[0] ?? null)
  }

  const stopStory = () => {
    setActiveStoryPathId(null)
    setStoryStep(0)
    setStoryPlaying(false)
  }

  const selectNode = (nodeId: string | null) => {
    setSelectedNodeId(nodeId)
    if (nodeId) setSidebarOpen(true)
  }

  const togglePlaying = () => {
    if (!activePath) return
    if (!storyPlaying && storyStep >= activePath.resourceIds.length - 1) {
      setStoryStep(0)
    }
    setStoryPlaying((playing) => !playing)
  }

  const selectSimulation = (simulationId: string | null) => {
    const requestId = simulationRequest.current + 1
    simulationRequest.current = requestId
    setSelectedSimulationId(simulationId)
    setSimulationResult(null)
    setSimulationError(null)
    setSimulationLoading(false)

    if (!simulationId || envelope.source !== 'api') return
    const simulation = simulations.find((candidate) => candidate.id === simulationId)
    if (!simulation) return

    setSimulationLoading(true)
    void runSimulation(snapshot.id, simulation.changes)
      .then((result) => {
        if (simulationRequest.current === requestId) setSimulationResult(result)
      })
      .catch((reason: unknown) => {
        if (simulationRequest.current === requestId) {
          setSimulationError(
            reason instanceof Error ? reason.message : 'The simulation could not be completed.',
          )
        }
      })
      .finally(() => {
        if (simulationRequest.current === requestId) setSimulationLoading(false)
      })
  }

  return (
    <div className="app-shell">
      <Header
        snapshot={snapshot}
        source={envelope.source}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen((open) => !open)}
      />
      <KpiRibbon snapshot={snapshot} />

      {envelope.notice ? (
        <div className="data-notice" role="status">
          <span aria-hidden="true">i</span>{envelope.notice}
        </div>
      ) : null}

      <main className="atlas-workspace">
        <section className="graph-stage" aria-label="Interactive Azure attack graph">
          <FilterBar
            filters={filters}
            resourceTypes={resourceTypes}
            paths={snapshot.attackPaths}
            visibleCount={filtered.resources.length}
            totalCount={snapshot.resources.length}
            onChange={setFilters}
          />
          <Suspense fallback={<div className="graph-loading">Initializing graph renderer…</div>}>
            <GraphView
              resources={filtered.resources}
              relationships={snapshot.relationships}
              findings={snapshot.findings}
              visibleNodeIds={filtered.visibleResourceIds}
              selectedNodeId={selectedNodeId}
              activePath={activePath}
              storyStep={storyStep}
              onSelectNode={selectNode}
            />
          </Suspense>
          <SimulationPanel
            snapshot={snapshot}
            simulations={simulations}
            selectedSimulationId={selectedSimulationId}
            onSelectSimulation={selectSimulation}
            result={simulationResult}
            loading={simulationLoading}
            error={simulationError}
            source={envelope.source}
          />
          <StoryMode
            paths={snapshot.attackPaths}
            nodes={snapshot.resources}
            activePath={activePath}
            storyStep={storyStep}
            playing={storyPlaying}
            onStart={startStory}
            onStop={stopStory}
            onPrevious={() => setStoryStep((step) => Math.max(0, step - 1))}
            onNext={() =>
              setStoryStep((step) =>
                activePath ? Math.min(activePath.resourceIds.length - 1, step + 1) : step,
              )
            }
            onTogglePlaying={togglePlaying}
          />
        </section>

        <DetailsPanel
          snapshotName={snapshot.name}
          nodes={snapshot.resources}
          findings={snapshot.findings}
          paths={snapshot.attackPaths}
          selectedNode={selectedNode}
          open={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          onSelectNode={(nodeId) => selectNode(nodeId)}
          onOpenPath={startStory}
        />
      </main>
    </div>
  )
}
