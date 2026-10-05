import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { AttackPath, Severity } from '../types'
import type { AtlasFilters } from '../lib/atlas'
import type { GraphMode } from '../lib/view-model'

interface FilterBarProps {
  filters: AtlasFilters
  resourceTypes: string[]
  paths: AttackPath[]
  visibleCount: number
  totalCount: number
  totalMatching: number
  truncated: boolean
  graphMode: GraphMode
  performanceMode: boolean
  canUseNeighborhood: boolean
  onChange: (filters: AtlasFilters) => void
  onGraphModeChange: (mode: GraphMode) => void
  onTogglePerformance: () => void
}

const severities: Array<Severity | 'all'> = [
  'all',
  'critical',
  'high',
  'medium',
  'low',
]

export function FilterBar({
  filters,
  resourceTypes,
  paths,
  visibleCount,
  totalCount,
  totalMatching,
  truncated,
  graphMode,
  performanceMode,
  canUseNeighborhood,
  onChange,
  onGraphModeChange,
  onTogglePerformance,
}: FilterBarProps) {
  const searchInput = useRef<HTMLInputElement>(null)
  const sheet = useRef<HTMLDivElement>(null)
  const filterToggle = useRef<HTMLButtonElement>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const hasFilters =
    filters.query !== '' ||
    filters.severity !== 'all' ||
    filters.type !== 'all' ||
    filters.attackPathId !== 'all'

  useLayoutEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      const target = event.target
      const isTyping = target instanceof HTMLElement
        && target.matches('input, textarea, select, [contenteditable="true"]')
      if ((event.key === '/' || event.code === 'Slash') && !isTyping) {
        event.preventDefault()
        searchInput.current?.focus()
      }
      if (event.key === 'Escape' && mobileOpen) {
        setMobileOpen(false)
        filterToggle.current?.focus()
      }
      if (event.key === 'Tab' && mobileOpen && sheet.current) {
        const focusable = [...sheet.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled)',
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
    }
    document.addEventListener('keydown', focusSearch, { capture: true })
    return () => document.removeEventListener('keydown', focusSearch, { capture: true })
  }, [mobileOpen])

  useEffect(() => {
    if (mobileOpen) sheet.current?.querySelector<HTMLElement>('button')?.focus()
  }, [mobileOpen])

  return (
    <section className={`filter-bar ${mobileOpen ? 'mobile-filters-open' : ''}`} aria-label="Graph filters">
      <label className="search-control">
        <span className="search-symbol" aria-hidden="true">⌕</span>
        <span className="sr-only">Search resources</span>
        <input
          ref={searchInput}
          type="search"
          aria-label="Search resources"
          value={filters.query}
          placeholder="Search resources, types, IDs…"
          onChange={(event) => onChange({ ...filters, query: event.target.value })}
        />
        <kbd>/</kbd>
      </label>

      <button
        ref={filterToggle}
        className="mobile-filter-toggle"
        type="button"
        aria-expanded={mobileOpen}
        aria-controls="atlas-filter-sheet"
        onClick={() => setMobileOpen((open) => !open)}
      >
        Filters {hasFilters ? '•' : ''}
      </button>

      <div className="graph-mode-switch" aria-label="Graph focus mode">
        {(['overview', 'attack-path', 'neighborhood'] as GraphMode[]).map((mode) => (
          <button
            key={mode}
            type="button"
            aria-pressed={graphMode === mode}
            disabled={mode === 'neighborhood' && !canUseNeighborhood}
            onClick={() => onGraphModeChange(mode)}
          >
            {mode === 'attack-path' ? 'Path' : mode === 'neighborhood' ? 'Nearby' : 'Overview'}
          </button>
        ))}
      </div>

      <div
        ref={sheet}
        id="atlas-filter-sheet"
        className="filter-sheet"
        role={mobileOpen ? 'dialog' : undefined}
        aria-label={mobileOpen ? 'Graph filters' : undefined}
        aria-modal={mobileOpen || undefined}
      >
      <div className="filter-sheet-heading">
        <strong>Graph filters</strong>
        <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close filters">×</button>
      </div>
      <div className="filter-group severity-filter" role="group" aria-label="Filter by severity">
        {severities.map((severity) => (
          <button
            key={severity}
            className={`severity-chip severity-chip-${severity}`}
            type="button"
            aria-pressed={filters.severity === severity}
            onClick={() => onChange({ ...filters, severity })}
          >
            {severity}
          </button>
        ))}
      </div>

      <label className="select-control">
        <span className="sr-only">Filter by resource type</span>
        <select
          value={filters.type}
          onChange={(event) => onChange({ ...filters, type: event.target.value })}
        >
          <option value="all">All resource types</option>
          {resourceTypes.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
      </label>

      <label className="select-control path-select">
        <span className="sr-only">Filter by attack path</span>
        <select
          value={filters.attackPathId}
          onChange={(event) => {
            const attackPathId = event.target.value
            onChange({ ...filters, attackPathId })
            if (attackPathId !== 'all') onGraphModeChange('attack-path')
          }}
        >
          <option value="all">All attack paths</option>
          {paths.map((path, index) => (
            <option key={path.id} value={path.id}>Path {index + 1}: {path.title}</option>
          ))}
        </select>
      </label>

      <button
        className={`performance-toggle ${performanceMode ? 'is-active' : ''}`}
        type="button"
        aria-pressed={performanceMode}
        onClick={onTogglePerformance}
      >
        Performance mode
      </button>

      {hasFilters ? (
        <button
          className="clear-button"
          type="button"
          onClick={() =>
            onChange({ query: '', severity: 'all', type: 'all', attackPathId: 'all' })
          }
        >
          Clear
        </button>
      ) : null}
      </div>

      <span className="result-count" aria-live="polite">
        {visibleCount}/{truncated ? totalMatching : totalCount} assets{truncated ? ' shown' : ''}
      </span>
      {mobileOpen ? <button className="filter-backdrop" type="button" aria-label="Close filters" onClick={() => setMobileOpen(false)} /> : null}
    </section>
  )
}
