import type { DataSource, Snapshot } from '../types'

interface HeaderProps {
  snapshot: Snapshot
  source: DataSource
  sidebarOpen: boolean
  onToggleSidebar: () => void
}

function sourceLabel(source: DataSource): string {
  if (source === 'api') return 'LOCAL ENGINE'
  if (source === 'fixture-fallback') return 'SAFE FALLBACK'
  return 'PUBLIC DEMO'
}

export function Header({ snapshot, source, sidebarOpen, onToggleSidebar }: HeaderProps) {
  const generated = new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(snapshot.generatedAt))

  return (
    <header className="topbar">
      <div className="brand" aria-label="CloudThreat Atlas">
        <span className="brand-mark" aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
        <div>
          <div className="brand-name">
            CLOUDTHREAT <strong>ATLAS</strong>
          </div>
          <div className="brand-subtitle">AZURE ATTACK SURFACE EXPLORER</div>
        </div>
      </div>

      <div className="environment-summary">
        <div>
          <span className="eyebrow">ENVIRONMENT</span>
          <strong>{snapshot.name}</strong>
        </div>
        <div className="scan-time">
          <span className="eyebrow">SNAPSHOT</span>
          <span>{generated}</span>
        </div>
      </div>

      <div className="topbar-actions">
        <span className={`source-pill source-${source}`}>
          <span className="source-dot" />
          {sourceLabel(source)}
        </span>
        <a
          className="icon-button github-link"
          href="https://github.com/meneeses/cloudthreat-atlas"
          target="_blank"
          rel="noreferrer"
          aria-label="Open the CloudThreat Atlas GitHub repository"
        >
          <span aria-hidden="true">↗</span>
        </a>
        <button
          className="icon-button mobile-sidebar-toggle"
          type="button"
          aria-label={sidebarOpen ? 'Close intelligence panel' : 'Open intelligence panel'}
          aria-expanded={sidebarOpen}
          onClick={onToggleSidebar}
        >
          <span aria-hidden="true">{sidebarOpen ? '×' : '☰'}</span>
        </button>
      </div>
    </header>
  )
}
