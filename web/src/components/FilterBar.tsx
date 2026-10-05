import type { AttackPath, Severity } from '../types'
import type { AtlasFilters } from '../lib/atlas'

interface FilterBarProps {
  filters: AtlasFilters
  resourceTypes: string[]
  paths: AttackPath[]
  visibleCount: number
  totalCount: number
  onChange: (filters: AtlasFilters) => void
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
  onChange,
}: FilterBarProps) {
  const hasFilters =
    filters.query !== '' ||
    filters.severity !== 'all' ||
    filters.type !== 'all' ||
    filters.attackPathId !== 'all'

  return (
    <section className="filter-bar" aria-label="Graph filters">
      <label className="search-control">
        <span className="search-symbol" aria-hidden="true">⌕</span>
        <span className="sr-only">Search resources</span>
        <input
          type="search"
          aria-label="Search resources"
          value={filters.query}
          placeholder="Search resources, types, IDs…"
          onChange={(event) => onChange({ ...filters, query: event.target.value })}
        />
        <kbd>/</kbd>
      </label>

      <div className="filter-group severity-filter" aria-label="Filter by severity">
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
          onChange={(event) => onChange({ ...filters, attackPathId: event.target.value })}
        >
          <option value="all">All attack paths</option>
          {paths.map((path, index) => (
            <option key={path.id} value={path.id}>Path {index + 1}: {path.title}</option>
          ))}
        </select>
      </label>

      <span className="result-count" aria-live="polite">
        {visibleCount}/{totalCount} assets
      </span>

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
    </section>
  )
}
