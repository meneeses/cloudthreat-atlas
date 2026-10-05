# ADR 0003: Local-first workspace and bounded graph exploration

## Status

Accepted

## Context

The first release proves the analysis and visualization model with one
synthetic snapshot. Real Azure scans are exported as JSON, but they cannot be
opened, retained, compared, or triaged in the embedded dashboard. Loading an
entire subscription into the browser also makes validation, layout, and DOM
work grow too quickly for realistic environments.

CloudThreat Atlas must stay useful without hosted infrastructure, paid cloud
resources, or uploading control-plane metadata to a third party.

## Decision

CloudThreat Atlas will become a local-first application served by the existing
single Go binary.

- A private per-user workspace stores catalog metadata and triage state in
  SQLite. Portable snapshots remain immutable, compressed JSON documents.
- The local API exposes summaries, paginated findings and attack paths, and
  bounded graph slices instead of requiring every screen to load the complete
  snapshot.
- The browser renders bounded overview, attack-path, and neighborhood views.
  The complete immutable snapshot remains available to the local CLI and
  reporting commands without forcing the browser to materialize every asset.
- Collection and analysis jobs expose named phases and cancellation. Progress
  percentages are not invented when Azure does not provide them.
- Azure access remains read-only. Remediation output is reviewable guidance;
  the product does not execute it.
- The public GitHub Pages build continues to use synthetic static data through
  the same frontend data-source contract.

The default visualization limit is 300 nodes and 2,000 relationships. Attack
path discovery is deterministic and bounded, and every truncated result
reports that fact explicitly.

## Consequences

- Raw cloud metadata stays on the user's machine and the product keeps its
  zero-cost path.
- History, comparison, and finding triage work without a hosted account.
- Full-subscription support no longer implies rendering every resource at
  once, which gives the UI a predictable performance envelope.
- Snapshot schema migrations, local database migrations, and localhost request
  protections become maintained compatibility surfaces.
- Collaboration and multi-tenant SaaS features remain a separate future
  product decision.
