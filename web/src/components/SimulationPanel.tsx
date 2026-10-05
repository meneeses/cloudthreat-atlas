import type { DataSource, SimulationPreset, SimulationResult, Snapshot } from '../types'
import { compareSimulation } from '../lib/atlas'

interface SimulationPanelProps {
  snapshot: Snapshot
  simulations: SimulationPreset[]
  selectedSimulationId: string | null
  onSelectSimulation: (simulationId: string | null) => void
  result: SimulationResult | null
  loading: boolean
  error: string | null
  source: DataSource
}

export function SimulationPanel({
  snapshot,
  simulations,
  selectedSimulationId,
  onSelectSimulation,
  result,
  loading,
  error,
  source,
}: SimulationPanelProps) {
  const activeSimulation =
    simulations.find((simulation) => simulation.id === selectedSimulationId) ?? null
  const staticImpact =
    activeSimulation && source !== 'api' ? compareSimulation(snapshot, activeSimulation) : null
  const impact = result
    ? {
        originalScore: result.riskScoreBefore,
        projectedScore: result.riskScoreAfter,
        remainingPaths: result.remainingAttackPaths.length,
      }
    : staticImpact
  const removedPathCount = result
    ? result.removedAttackPathIds.length
    : activeSimulation?.removedAttackPaths.length ?? 0

  return (
    <section className={`simulation-panel ${activeSimulation ? 'has-result' : ''}`}>
      <div className="simulation-heading">
        <div>
          <span className="eyebrow">WHAT-IF LAB</span>
          <strong>Preview a remediation without touching Azure</strong>
          <small className="simulation-source">
            {source === 'api' ? 'LOCAL GO ENGINE' : 'PRECOMPUTED SAFE PREVIEW'}
          </small>
        </div>
        {activeSimulation ? (
          <button type="button" onClick={() => onSelectSimulation(null)}>Reset</button>
        ) : null}
      </div>

      <label className="simulation-select">
        <span className="sr-only">Choose a remediation simulation</span>
        <select
          value={selectedSimulationId ?? ''}
          onChange={(event) => onSelectSimulation(event.target.value || null)}
        >
          <option value="">Choose a remediation…</option>
          {simulations.map((simulation) => (
            <option key={simulation.id} value={simulation.id}>{simulation.name}</option>
          ))}
        </select>
      </label>

      {loading ? <div className="simulation-status" role="status">Running the local graph engine…</div> : null}
      {error ? (
        <div className="simulation-status simulation-error" role="alert">
          {error} Live impact is unavailable; no estimated score is shown.
        </div>
      ) : null}

      {activeSimulation && impact && !loading ? (
        <div className="simulation-result" aria-live="polite">
          <p>{activeSimulation.description}</p>
          <div className="impact-grid">
            <div>
              <span>RISK SCORE</span>
              <strong>{impact.originalScore} <i>→</i> <em>{impact.projectedScore}</em></strong>
            </div>
            <div>
              <span>PATHS REMOVED</span>
              <strong>{removedPathCount}</strong>
            </div>
            <div>
              <span>PATHS REMAINING</span>
              <strong>{impact.remainingPaths}</strong>
            </div>
          </div>
          <div className="simulation-disclaimer">
            <span aria-hidden="true">◈</span>
            Preview only. CloudThreat Atlas never changes your environment.
          </div>
        </div>
      ) : null}
    </section>
  )
}
