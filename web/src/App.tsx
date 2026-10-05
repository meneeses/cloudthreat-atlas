import {
  lazy,
  Suspense,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { DetailsPanel } from './components/DetailsPanel'
import { AzureScanDialog } from './components/AzureScanDialog'
import { FilterBar } from './components/FilterBar'
import { Header } from './components/Header'
import { KpiRibbon } from './components/KpiRibbon'
import { SimulationPanel } from './components/SimulationPanel'
import { StoryMode } from './components/StoryMode'
import { EmptyWorkspace, WorkspaceBar } from './components/WorkspaceBar'
import {
  compareSnapshots,
  loadAPIWorkspace,
  loadServerComparison,
  loadSnapshotById,
  loadTriage,
  loadWorkspace,
  parseImportedSnapshot,
  persistAndLoadImportedSnapshot,
  runSimulation,
  summarizeSnapshot,
  updateTriage,
  WorkspaceSessionExpiredError,
} from './data/snapshot-client'
import { deriveSimulations, type AtlasFilters } from './lib/atlas'
import {
  createAtlasViewModel,
  selectVisibleAtlas,
  type GraphMode,
} from './lib/view-model'
import type {
  SimulationImpact,
  SnapshotComparison,
  SnapshotEnvelope,
  SnapshotSummary,
  TriageRecord,
  TriageStatus,
  WorkspaceBootstrap,
} from './types'

// Start downloading the heavier graph renderer alongside the workspace
// bootstrap instead of creating a data-then-code waterfall.
const graphModule = import('./components/GraphView')
const GraphView = lazy(() => graphModule)

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

function ErrorScreen({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const sessionExpired = error instanceof WorkspaceSessionExpiredError
  return (
    <main className="error-screen">
      <span className="error-symbol" aria-hidden="true">!</span>
      <span className="eyebrow">
        {sessionExpired ? 'WORKSPACE SESSION EXPIRED' : 'WORKSPACE LOAD FAILED'}
      </span>
      <h1>
        {sessionExpired
          ? 'Reopen your private Atlas workspace.'
          : 'The attack graph could not be initialized.'}
      </h1>
      <p>{error.message}</p>
      <button type="button" onClick={onRetry}>
        {sessionExpired ? 'Retry after reopening the private URL' : 'Retry loading the workspace'}
      </button>
    </main>
  )
}

export default function App() {
  const [bootstrap, setBootstrap] = useState<WorkspaceBootstrap | null>(null)
  const [catalog, setCatalog] = useState<SnapshotSummary[]>([])
  const [envelope, setEnvelope] = useState<SnapshotEnvelope | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [retryKey, setRetryKey] = useState(0)
  const [snapshotLoading, setSnapshotLoading] = useState(false)
  const [importError, setImportError] = useState<string | null>(null)
  const snapshotCache = useRef(new Map<string, SnapshotEnvelope>())
  const snapshotRequest = useRef<AbortController | null>(null)

  const [filters, setFilters] = useState<AtlasFilters>(initialFilters)
  const deferredQuery = useDeferredValue(filters.query)
  const [graphMode, setGraphMode] = useState<GraphMode>('overview')
  const [performanceMode, setPerformanceMode] = useState(false)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [activeStoryPathId, setActiveStoryPathId] = useState<string | null>(null)
  const [storyStep, setStoryStep] = useState(0)
  const [storyPlaying, setStoryPlaying] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const [selectedSimulationId, setSelectedSimulationId] = useState<string | null>(null)
  const [simulationResult, setSimulationResult] = useState<SimulationImpact | null>(null)
  const [simulationLoading, setSimulationLoading] = useState(false)
  const [simulationError, setSimulationError] = useState<string | null>(null)
  const simulationRequest = useRef<AbortController | null>(null)

  const [comparisonBaseId, setComparisonBaseId] = useState('')
  const [comparison, setComparison] = useState<SnapshotComparison | null>(null)
  const [comparisonLoading, setComparisonLoading] = useState(false)
  const [comparisonError, setComparisonError] = useState<string | null>(null)
  const comparisonRequest = useRef<AbortController | null>(null)
  const [scanOpen, setScanOpen] = useState(false)
  const [triageByFindingId, setTriageByFindingId] = useState<Map<string, TriageRecord>>(
    () => new Map(),
  )
  const [triagePendingIds, setTriagePendingIds] = useState<Set<string>>(() => new Set())
  const [triageError, setTriageError] = useState<string | null>(null)
  const triageRecords = useRef(new Map<string, TriageRecord>())
  const confirmedTriageRecords = useRef(new Map<string, TriageRecord>())
  const triageLoadRequest = useRef<AbortController | null>(null)
  const triageUpdateRequests = useRef(new Map<string, AbortController>())
  const triageUpdateChains = useRef(new Map<string, Promise<void>>())
  const triageUpdateVersions = useRef(new Map<string, number>())
  const triageUpdateEpoch = useRef(0)

  useEffect(() => {
    const controller = new AbortController()
    loadWorkspace(controller.signal)
      .then(async (result) => {
        setBootstrap(result.bootstrap)
        setCatalog(result.bootstrap.snapshots)
        if (result.initialSnapshot) {
          snapshotCache.current.set(result.initialSnapshot.snapshot.id, result.initialSnapshot)
          setEnvelope(result.initialSnapshot)
          return
        }
        const initialId = result.bootstrap.currentSnapshotId
        const initialSummary = result.bootstrap.snapshots.find((snapshot) => snapshot.id === initialId)
        if (initialSummary) {
          const initial = await loadSnapshotById(initialSummary, controller.signal)
          snapshotCache.current.set(initial.snapshot.id, initial)
          setEnvelope(initial)
        }
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason : new Error('An unknown data error occurred.'))
        }
      })
    return () => controller.abort()
  }, [retryKey])

  useEffect(() => () => {
    triageUpdateEpoch.current += 1
    snapshotRequest.current?.abort()
    simulationRequest.current?.abort()
    comparisonRequest.current?.abort()
    triageLoadRequest.current?.abort()
    for (const controller of triageUpdateRequests.current.values()) controller.abort()
    triageUpdateChains.current.clear()
    triageUpdateVersions.current.clear()
  }, [])

  const resetWorkspaceView = useCallback(() => {
    simulationRequest.current?.abort()
    comparisonRequest.current?.abort()
    triageLoadRequest.current?.abort()
    triageUpdateEpoch.current += 1
    for (const controller of triageUpdateRequests.current.values()) controller.abort()
    triageUpdateRequests.current.clear()
    triageUpdateChains.current.clear()
    triageUpdateVersions.current.clear()
    triageRecords.current = new Map()
    confirmedTriageRecords.current = new Map()
    setFilters(initialFilters)
    setGraphMode('overview')
    setSelectedNodeId(null)
    setActiveStoryPathId(null)
    setStoryStep(0)
    setStoryPlaying(false)
    setSelectedSimulationId(null)
    setSimulationResult(null)
    setSimulationError(null)
    setSimulationLoading(false)
    setSidebarOpen(false)
    setComparisonBaseId('')
    setComparison(null)
    setComparisonError(null)
    setComparisonLoading(false)
    setTriageByFindingId(new Map())
    setTriagePendingIds(new Set())
    setTriageError(null)
  }, [])

  const retryLoad = useCallback(() => {
    setError(null)
    setBootstrap(null)
    setCatalog([])
    setEnvelope(null)
    snapshotCache.current.clear()
    setRetryKey((key) => key + 1)
  }, [])

  const selectSnapshot = useCallback(async (snapshotId: string) => {
    const summary = catalog.find((candidate) => candidate.id === snapshotId)
    if (!summary) return
    snapshotRequest.current?.abort()
    const controller = new AbortController()
    snapshotRequest.current = controller
    setSnapshotLoading(true)
    setImportError(null)
    try {
      const cached = snapshotCache.current.get(snapshotId)
      const next = cached ?? await loadSnapshotById(summary, controller.signal)
      snapshotCache.current.set(next.snapshot.id, next)
      setEnvelope(next)
      resetWorkspaceView()
    } catch (reason) {
      if (!controller.signal.aborted) {
        setImportError(reason instanceof Error ? reason.message : 'Snapshot loading failed.')
      }
    } finally {
      if (snapshotRequest.current === controller) {
        snapshotRequest.current = null
        setSnapshotLoading(false)
      }
    }
  }, [catalog, resetWorkspaceView])

  const importSnapshot = useCallback(async (file: File) => {
    snapshotRequest.current?.abort()
    snapshotRequest.current = null
    setSnapshotLoading(false)
    setImportError(null)
    try {
      const snapshot = await parseImportedSnapshot(file)
      let summary = summarizeSnapshot(snapshot, 'import')
      let activeEnvelope: SnapshotEnvelope = { snapshot, source: 'import' }
      if (bootstrap?.csrfToken && bootstrap.capabilities.import) {
        try {
          const persisted = await persistAndLoadImportedSnapshot(snapshot, bootstrap.csrfToken)
          summary = persisted.summary
          activeEnvelope = persisted.envelope
        } catch (reason) {
          setImportError(
            `${reason instanceof Error ? reason.message : 'The local API could not finish this import.'} The source snapshot remains available in this browser session.`,
          )
        }
      }
      snapshotCache.current.set(activeEnvelope.snapshot.id, activeEnvelope)
      setCatalog((current) => [summary, ...current.filter((item) => item.id !== summary.id)])
      setEnvelope(activeEnvelope)
      resetWorkspaceView()
    } catch (reason) {
      setImportError(reason instanceof Error ? reason.message : 'Snapshot import failed.')
    }
  }, [bootstrap, resetWorkspaceView])

  const snapshot = envelope?.snapshot ?? null
  const triageEnabled = Boolean(
    snapshot
    && envelope?.source === 'api'
    && bootstrap?.capabilities.triage
    && bootstrap.csrfToken,
  )
  const model = useMemo(() => snapshot ? createAtlasViewModel(snapshot) : null, [snapshot])
  const activePath = useMemo(
    () => model?.pathById.get(activeStoryPathId ?? '') ?? null,
    [activeStoryPathId, model],
  )
  const selectedNode = useMemo(
    () => model?.resourceById.get(selectedNodeId ?? '') ?? null,
    [model, selectedNodeId],
  )
  const simulations = useMemo(() => snapshot ? deriveSimulations(snapshot) : [], [snapshot])
  const effectiveFilters = useMemo(
    () => ({ ...filters, query: deferredQuery }),
    [deferredQuery, filters],
  )
  const focusPathId = activeStoryPathId
    ?? (filters.attackPathId !== 'all' ? filters.attackPathId : snapshot?.attackPaths[0]?.id ?? null)
  const visible = useMemo(
    () => model ? selectVisibleAtlas(model, effectiveFilters, {
      mode: graphMode,
      selectedResourceId: selectedNodeId,
      pathId: focusPathId,
      limit: performanceMode ? 120 : 300,
    }) : null,
    [effectiveFilters, focusPathId, graphMode, model, performanceMode, selectedNodeId],
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

  useEffect(() => {
    triageLoadRequest.current?.abort()
    triageUpdateEpoch.current += 1
    for (const controller of triageUpdateRequests.current.values()) controller.abort()
    triageUpdateRequests.current.clear()
    triageUpdateChains.current.clear()
    triageUpdateVersions.current.clear()
    triageRecords.current = new Map()
    confirmedTriageRecords.current = new Map()
    if (!triageEnabled || !snapshot) return undefined

    const controller = new AbortController()
    triageLoadRequest.current = controller
    void loadTriage(snapshot.id, controller.signal)
      .then((records) => {
        if (controller.signal.aborted) return
        const indexed = new Map(records.map((record) => [record.findingId, record]))
        triageRecords.current = indexed
        confirmedTriageRecords.current = indexed
        setTriageByFindingId(indexed)
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setTriageError(reason instanceof Error ? reason.message : 'Finding triage could not be loaded.')
        }
      })
    return () => controller.abort()
  }, [snapshot, triageEnabled])

  const selectNode = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId)
    if (nodeId) setSidebarOpen(true)
    else if (graphMode === 'neighborhood') setGraphMode('overview')
  }, [graphMode])

  const startStory = useCallback((pathId: string) => {
    const path = model?.pathById.get(pathId)
    if (!path) return
    setActiveStoryPathId(pathId)
    setGraphMode('attack-path')
    setFilters({ ...initialFilters, attackPathId: pathId })
    setStoryStep(0)
    setStoryPlaying(false)
    setSelectedNodeId(path.resourceIds[0] ?? null)
  }, [model])

  const stopStory = useCallback(() => {
    setActiveStoryPathId(null)
    setStoryStep(0)
    setStoryPlaying(false)
    setFilters((current) => ({ ...current, attackPathId: 'all' }))
    setGraphMode('overview')
  }, [])

  const selectSimulation = useCallback((simulationId: string | null) => {
    simulationRequest.current?.abort()
    setSelectedSimulationId(simulationId)
    setSimulationResult(null)
    setSimulationError(null)
    setSimulationLoading(false)
    if (!simulationId || envelope?.source !== 'api' || !snapshot) return
    const simulation = simulations.find((candidate) => candidate.id === simulationId)
    if (!simulation) return

    const controller = new AbortController()
    simulationRequest.current = controller
    setSimulationLoading(true)
    void runSimulation(snapshot.id, simulation.changes, controller.signal, bootstrap?.csrfToken)
      .then(setSimulationResult)
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setSimulationError(reason instanceof Error ? reason.message : 'The simulation could not be completed.')
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setSimulationLoading(false)
      })
  }, [bootstrap?.csrfToken, envelope?.source, simulations, snapshot])

  const selectComparisonBase = useCallback(async (baseId: string) => {
    comparisonRequest.current?.abort()
    setComparisonBaseId(baseId)
    setComparison(null)
    setComparisonError(null)
    setComparisonLoading(false)
    if (!baseId || !snapshot || !bootstrap) return
    const controller = new AbortController()
    comparisonRequest.current = controller
    setComparisonLoading(true)
    try {
      let result: SnapshotComparison
      if (bootstrap.capabilities.comparison && envelope?.source === 'api') {
        result = await loadServerComparison(baseId, snapshot.id, controller.signal)
      } else {
        let baseEnvelope = snapshotCache.current.get(baseId)
        if (!baseEnvelope) {
          const summary = catalog.find((candidate) => candidate.id === baseId)
          if (!summary) throw new Error('Comparison snapshot is unavailable.')
          baseEnvelope = await loadSnapshotById(summary, controller.signal)
          snapshotCache.current.set(baseEnvelope.snapshot.id, baseEnvelope)
        }
        result = compareSnapshots(baseEnvelope.snapshot, snapshot)
      }
      setComparison(result)
    } catch (reason) {
      if (!controller.signal.aborted) {
        setComparisonError(reason instanceof Error ? reason.message : 'Comparison failed.')
      }
    } finally {
      if (!controller.signal.aborted) setComparisonLoading(false)
    }
  }, [bootstrap, catalog, envelope, snapshot])

  const clearComparison = useCallback(() => {
    comparisonRequest.current?.abort()
    setComparisonBaseId('')
    setComparison(null)
    setComparisonError(null)
    setComparisonLoading(false)
  }, [])

  const saveTriage = useCallback((findingId: string, status: TriageStatus, notes: string) => {
    const csrfToken = bootstrap?.csrfToken
    if (!snapshot || !csrfToken) return
    const current = triageRecords.current.get(findingId)
    if (!current) return

    const version = (triageUpdateVersions.current.get(findingId) ?? 0) + 1
    const epoch = triageUpdateEpoch.current
    triageUpdateVersions.current.set(findingId, version)
    const optimistic: TriageRecord = {
      ...current,
      status,
      notes,
      updatedAt: new Date().toISOString(),
    }
    const next = new Map(triageRecords.current).set(findingId, optimistic)
    triageRecords.current = next
    setTriageByFindingId(next)
    setTriagePendingIds((current) => new Set(current).add(findingId))
    setTriageError(null)

    const previous = triageUpdateChains.current.get(findingId) ?? Promise.resolve()
    const task = previous.then(async () => {
      if (triageUpdateEpoch.current !== epoch) return
      const controller = new AbortController()
      triageUpdateRequests.current.set(findingId, controller)
      try {
        const saved = await updateTriage(
          snapshot.id,
          findingId,
          status,
          notes,
          csrfToken,
          controller.signal,
        )
        if (triageUpdateEpoch.current !== epoch) return
        confirmedTriageRecords.current = new Map(confirmedTriageRecords.current).set(
          findingId,
          saved,
        )
        if (triageUpdateVersions.current.get(findingId) !== version) return
        const savedRecords = new Map(triageRecords.current).set(findingId, saved)
        triageRecords.current = savedRecords
        setTriageByFindingId(savedRecords)
      } catch (reason) {
        if (controller.signal.aborted || triageUpdateEpoch.current !== epoch) return
        if (triageUpdateVersions.current.get(findingId) !== version) return
        const confirmed = confirmedTriageRecords.current.get(findingId)
        if (confirmed) {
          const rolledBack = new Map(triageRecords.current).set(findingId, confirmed)
          triageRecords.current = rolledBack
          setTriageByFindingId(rolledBack)
        }
        setTriageError(
          `${reason instanceof Error ? reason.message : 'Triage update failed.'} Your previous value was restored.`,
        )
      } finally {
        if (triageUpdateRequests.current.get(findingId) === controller) {
          triageUpdateRequests.current.delete(findingId)
        }
      }
    }).finally(() => {
      if (triageUpdateEpoch.current !== epoch) return
      if (triageUpdateChains.current.get(findingId) !== task) return
      triageUpdateChains.current.delete(findingId)
      triageUpdateVersions.current.delete(findingId)
      setTriagePendingIds((current) => {
        const pending = new Set(current)
        pending.delete(findingId)
        return pending
      })
    })
    triageUpdateChains.current.set(findingId, task)
  }, [bootstrap, snapshot])

  const openScannedSnapshot = useCallback(async (snapshotId: string) => {
    snapshotRequest.current?.abort()
    const controller = new AbortController()
    snapshotRequest.current = controller
    setSnapshotLoading(true)
    try {
      const workspace = await loadAPIWorkspace(controller.signal)
      const summary = workspace.bootstrap.snapshots.find((candidate) => candidate.id === snapshotId)
      if (!summary) throw new Error('The completed scan is not present in the workspace catalog.')
      const next = await loadSnapshotById(summary, controller.signal)
      snapshotCache.current.set(next.snapshot.id, next)
      setBootstrap(workspace.bootstrap)
      setCatalog(workspace.bootstrap.snapshots)
      setEnvelope(next)
      resetWorkspaceView()
    } finally {
      if (!controller.signal.aborted) setSnapshotLoading(false)
    }
  }, [resetWorkspaceView])

  const canScanAzure = Boolean(
    bootstrap?.source === 'api'
    && bootstrap.capabilities.azureScans
    && bootstrap.csrfToken,
  )
  const scanDialog = canScanAzure && bootstrap?.csrfToken ? (
    <AzureScanDialog
      open={scanOpen}
      csrfToken={bootstrap.csrfToken}
      onClose={() => setScanOpen(false)}
      onCompleted={openScannedSnapshot}
    />
  ) : null

  if (error) return <ErrorScreen error={error} onRetry={retryLoad} />
  if (!bootstrap) return <LoadingScreen />
  if (!snapshot || !envelope || !model || !visible) {
    return (
      <>
        <EmptyWorkspace
          error={importError}
          canScanAzure={canScanAzure}
          onOpenAzureScan={() => setScanOpen(true)}
          onImport={(file) => { void importSnapshot(file) }}
        />
        {scanDialog}
      </>
    )
  }

  const togglePlaying = () => {
    if (!activePath) return
    if (!storyPlaying && storyStep >= activePath.resourceIds.length - 1) setStoryStep(0)
    setStoryPlaying((playing) => !playing)
  }

  return (
    <div className={`app-shell ${performanceMode ? 'performance-mode' : ''}`}>
      <Header
        snapshot={snapshot}
        source={envelope.source}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen((open) => !open)}
      />
      <WorkspaceBar
        snapshots={catalog}
        activeSnapshotId={snapshot.id}
        loading={snapshotLoading}
        importError={importError}
        comparison={comparison}
        comparisonBaseId={comparisonBaseId}
        comparisonLoading={comparisonLoading}
        comparisonError={comparisonError}
        onSelectSnapshot={(snapshotId) => { void selectSnapshot(snapshotId) }}
        onImport={(file) => { void importSnapshot(file) }}
        onSelectComparisonBase={(snapshotId) => { void selectComparisonBase(snapshotId) }}
        onClearComparison={clearComparison}
        canScanAzure={canScanAzure}
        onOpenAzureScan={() => setScanOpen(true)}
      />
      {scanDialog}
      <KpiRibbon snapshot={snapshot} />

      {envelope.notice ?? bootstrap.notice ? (
        <div className="data-notice" role="status">
          <span aria-hidden="true">i</span>{envelope.notice ?? bootstrap.notice}
        </div>
      ) : null}

      <main className="atlas-workspace">
        <section className="graph-stage" aria-label="Interactive Azure attack graph">
          <FilterBar
            filters={filters}
            resourceTypes={model.resourceTypes}
            paths={snapshot.attackPaths.slice(0, 100)}
            visibleCount={visible.resources.length}
            totalCount={snapshot.resources.length}
            totalMatching={visible.totalMatching}
            truncated={visible.truncated}
            graphMode={graphMode}
            performanceMode={performanceMode}
            canUseNeighborhood={Boolean(selectedNodeId)}
            onChange={setFilters}
            onGraphModeChange={setGraphMode}
            onTogglePerformance={() => setPerformanceMode((enabled) => !enabled)}
          />
          {visible.truncated ? (
            <div className="graph-limit-notice" role="status">
              Showing {visible.resources.length} of {visible.totalMatching} matching assets. Use filters or a focused mode to narrow the graph.
            </div>
          ) : null}
          <Suspense fallback={<div className="graph-loading">Initializing graph renderer…</div>}>
            <GraphView
              key={snapshot.id}
              resources={visible.resources}
              relationships={snapshot.relationships}
              model={model}
              visibleNodeIds={visible.visibleResourceIds}
              selectedNodeId={selectedNodeId}
              activePath={activePath}
              storyStep={storyStep}
              performanceMode={performanceMode}
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
            paths={snapshot.attackPaths.slice(0, 12)}
            nodes={snapshot.resources}
            activePath={activePath}
            storyStep={storyStep}
            playing={storyPlaying}
            onStart={startStory}
            onStop={stopStory}
            onPrevious={() => setStoryStep((step) => Math.max(0, step - 1))}
            onNext={() => setStoryStep((step) => activePath ? Math.min(activePath.resourceIds.length - 1, step + 1) : step)}
            onTogglePlaying={togglePlaying}
          />
        </section>

        {sidebarOpen ? <button className="details-backdrop" type="button" aria-label="Close intelligence panel" onClick={() => setSidebarOpen(false)} /> : null}
        <DetailsPanel
          snapshotName={snapshot.name}
          model={model}
          selectedNode={selectedNode}
          open={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          onSelectNode={(nodeId) => selectNode(nodeId)}
          onOpenPath={startStory}
          triageByFindingId={triageByFindingId}
          triageEnabled={triageEnabled}
          triagePendingIds={triagePendingIds}
          triageError={triageError}
          onUpdateTriage={saveTriage}
        />
      </main>
    </div>
  )
}
