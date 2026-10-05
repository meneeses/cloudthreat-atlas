# Architecture overview

CloudThreat Atlas separates collection, analysis, presentation, and reporting so the same security model works with both synthetic and real Azure data.

## Data flow

1. A collector emits normalized resource nodes and relationship edges.
2. The graph package builds an immutable directed multigraph.
3. native Go rules generate findings with evidence and remediation.
4. the path analyzer finds deterministic routes from exposed entry points to critical assets.
5. A versioned snapshot carries the graph and analysis results.
6. The local workspace stores immutable compressed snapshots and searchable metadata.
7. The API returns summaries, paginated intelligence, and bounded graph slices.
8. The React application reads those views from a static fixture or the local API.
9. Reporters render the same snapshot as machine- and human-readable output.

## Trust boundaries

- **Public demo:** contains synthetic identifiers only and runs entirely in the browser.
- **Local scanner:** authenticates with the user's existing Azure credential. It collects resource names and control-plane identifiers locally, never secret values, and provides deterministic redaction for shared output.
- **Local workspace:** stores raw snapshots under the operating-system user's private data directory. It is not a cloud synchronization boundary or a secret store.
- **Local browser API:** listens only on loopback and rejects invalid hosts and
  origins. Every workspace API and health request requires a high-entropy
  process-session token delivered in the launch URL fragment and retained only
  in browser memory. Mutations additionally require an independent CSRF token.
  Authenticated scan progress uses a header-bearing `fetch` stream rather than
  putting credentials in an EventSource URL or query string.
- **Azure control plane:** queried in read-only mode through Resource Graph and management APIs.
- **Repository:** excludes real snapshots, local environment files, credentials, and generated reports.

## Design properties

- The root Go package exposes the stable model and extension interfaces; engines remain implementation details.
- Snapshot output is deterministic to make review, diffing, and testing reliable.
- Azure snapshots carry their collection scope so subscription-wide and
  resource-group histories remain distinct across export and import.
- Simulations clone graph state and never modify the original snapshot.
- Rules are small Go units with stable identifiers and explicit evidence.
- `atlas scan azure --redact` replaces tenant-specific names and identifiers while preserving graph references.
- The frontend depends on a provider contract rather than a specific hosting model.
- Full environments are explored through focused graph slices; the browser does not need to render every resource at once.
- Workspace history is grouped by portable Azure collection scope, and the UI
  limits comparisons to snapshots derived from the same environment.
- Collection, analysis, comparison, and triage stay local and work without an account.
- The API-mode production frontend is versioned and embedded with `go:embed`,
  so `atlas app` and `atlas demo` are self-contained local applications. A
  filesystem build can be supplied explicitly with `--web-dir` during
  development.
