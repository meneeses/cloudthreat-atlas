import type {
  SimulationChange,
  SimulationResult,
  Snapshot,
  SnapshotEnvelope,
} from '../types'
import { parseSimulationResult, parseSnapshot } from './validation'

const FIXTURE_FILE = 'contoso-health.json'
const DEMO_SNAPSHOT_ID = 'contoso-health-demo'

function apiBase(): string {
  return (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
}

async function fetchJSON(url: string, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    signal,
    headers: { Accept: 'application/json' },
  })

  if (!response.ok) {
    throw new Error(`Snapshot request failed with status ${response.status}.`)
  }

  try {
    return await response.json()
  } catch {
    throw new Error('The data request returned invalid JSON.')
  }
}

async function loadFixture(signal?: AbortSignal): Promise<Snapshot> {
  const payload = await fetchJSON(`${import.meta.env.BASE_URL}${FIXTURE_FILE}`, signal)
  return parseSnapshot(payload)
}

async function loadFromAPI(signal?: AbortSignal): Promise<Snapshot> {
  const payload = await fetchJSON(
    `${apiBase()}/api/v1/snapshots/${DEMO_SNAPSHOT_ID}`,
    signal,
  )
  const candidate =
    typeof payload === 'object' && payload !== null && 'data' in payload
      ? (payload as { data: unknown }).data
      : payload

  return parseSnapshot(candidate)
}

export async function runSimulation(
  snapshotId: string,
  changes: SimulationChange[],
): Promise<SimulationResult> {
  const response = await fetch(`${apiBase()}/api/v1/simulations`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ snapshotId, changes }),
  })

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null
    throw new Error(payload?.error ?? `Simulation request failed with status ${response.status}.`)
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new Error('The simulation endpoint returned invalid JSON.')
  }
  return parseSimulationResult(payload)
}

export async function loadSnapshot(signal?: AbortSignal): Promise<SnapshotEnvelope> {
  if (import.meta.env.VITE_DATA_SOURCE !== 'api') {
    return { snapshot: await loadFixture(signal), source: 'fixture' }
  }

  try {
    return { snapshot: await loadFromAPI(signal), source: 'api' }
  } catch (error) {
    if (signal?.aborted) {
      throw error
    }

    return {
      snapshot: await loadFixture(signal),
      source: 'fixture-fallback',
      notice: 'The local API is unavailable. Showing the safe public fixture instead.',
    }
  }
}
