import type { Snapshot } from '../types'
import { countExposedResources } from '../lib/atlas'

interface KpiRibbonProps {
  snapshot: Snapshot
}

export function KpiRibbon({ snapshot }: KpiRibbonProps) {
  const riskScore = snapshot.riskScore
  const criticalFindings = snapshot.findings.filter(
    (finding) => finding.severity === 'critical',
  ).length
  const exposedResources = countExposedResources(snapshot)

  return (
    <section className="kpi-ribbon" aria-label="Environment risk summary">
      <div className="risk-gauge" aria-label={`Risk score ${riskScore} out of 100`}>
        <span className="risk-value">{riskScore}</span>
        <span className="risk-total">/100</span>
        <span className="risk-label">RISK SCORE</span>
        <svg aria-hidden="true" viewBox="0 0 46 46">
          <circle cx="23" cy="23" r="19" />
          <circle
            className="risk-gauge-progress"
            cx="23"
            cy="23"
            r="19"
            pathLength="100"
            strokeDasharray={`${riskScore} 100`}
          />
        </svg>
      </div>

      <div className="metric">
        <span className="metric-icon metric-critical">!</span>
        <div>
          <strong>{criticalFindings}</strong>
          <span>CRITICAL FINDINGS</span>
        </div>
      </div>
      <div className="metric">
        <span className="metric-icon metric-path">⌁</span>
        <div>
          <strong>{snapshot.attackPaths.length}</strong>
          <span>ATTACK PATHS</span>
        </div>
      </div>
      <div className="metric">
        <span className="metric-icon metric-exposed">◎</span>
        <div>
          <strong>{exposedResources}</strong>
          <span>EXPOSED ASSETS</span>
        </div>
      </div>
      <div className="metric metric-last">
        <span className="metric-icon metric-nodes">⬡</span>
        <div>
          <strong>{snapshot.resources.length}</strong>
          <span>MAPPED RESOURCES</span>
        </div>
      </div>
    </section>
  )
}
