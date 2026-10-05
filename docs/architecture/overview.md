# Architecture overview

CloudThreat Atlas separates collection, analysis, presentation, and reporting so the same security model works with both synthetic and real Azure data.

## Data flow

1. A collector emits normalized resource nodes and relationship edges.
2. The graph package builds an immutable directed multigraph.
3. native Go rules generate findings with evidence and remediation.
4. the path analyzer finds deterministic routes from exposed entry points to critical assets.
5. a versioned snapshot carries the graph and analysis results.
6. the React application reads the snapshot from a static fixture or the local API.
7. reporters render the same snapshot as machine- and human-readable output.

## Trust boundaries

- **Public demo:** contains synthetic identifiers only and runs entirely in the browser.
- **Local scanner:** authenticates with the user's existing Azure credential. It collects resource names and control-plane identifiers locally, never secret values, and provides deterministic redaction for shared output.
- **Azure control plane:** queried in read-only mode through Resource Graph and management APIs.
- **Repository:** excludes real snapshots, local environment files, credentials, and generated reports.

## Design properties

- The root Go package exposes the stable model and extension interfaces; engines remain implementation details.
- Snapshot output is deterministic to make review, diffing, and testing reliable.
- Simulations clone graph state and never modify the original snapshot.
- Rules are small Go units with stable identifiers and explicit evidence.
- `atlas scan azure --redact` replaces tenant-specific names and identifiers while preserving graph references.
- The frontend depends on a provider contract rather than a specific hosting model.
