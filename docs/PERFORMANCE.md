# Performance contract

CloudThreat Atlas treats performance as a product requirement. The supported
dataset target is 5,000 resources and 20,000 relationships; the interactive
canvas intentionally shows a focused slice rather than the entire dataset.

## Budgets

| Area | Budget |
| --- | --- |
| Go analysis at 5k/20k | under 5 seconds on a four-core developer laptop |
| Process memory at 5k/20k | under 512 MiB after analysis settles |
| Warm graph-slice API | under 150 ms |
| Filter, selection, or story interaction | p95 under 100 ms |
| Graph viewport | at least 45 FPS at 300 nodes / 2,000 edges |
| Initial JavaScript | at most 105 KiB gzip |
| React Flow lazy chunk | at most 75 KiB gzip |
| CSS | at most 15 KiB gzip |

These budgets are guardrails, not claims about Azure scan duration. Network
latency and Azure Resource Graph throttling are reported as collection phases
and warnings instead of being hidden behind a fabricated percentage.

## Deterministic fixtures

Performance checks use deterministic fixtures for distinct boundaries:

- the 13-node Contoso Health scenario protects portfolio behavior and browser flows;
- a 1,000-resource Azure normalization benchmark protects scope-based RBAC from
  returning to assignments-by-resources growth;
- a generated 5,000-resource / 20,000-relationship snapshot protects the Go
  analysis architecture and deterministic output;
- dense pathological graphs protect path limits, cancellation, and explicit
  truncation metadata.

Pathological dense graphs are tested separately to verify path limits,
cancellation, and truncation metadata. A performance optimization is accepted
only if deterministic findings and attack paths remain unchanged within the
configured limits.

Untrusted snapshots and tenant metadata also have fail-closed safety budgets.
Attack-path expansion, native rule traversal, containment resolution, finding
retention, and simulation change counts are bounded and context-cancelable. A
simulation accepts at most 100 changes. Before graph cloning or indexing, a
snapshot is limited to 100,000 resources, 500,000 relationships, and aggregate
budgets for properties, evidence, and simulation presets. Azure collection
separately limits pages, rows, and encoded bytes, including nested metadata.
When a safety budget is exceeded, Atlas returns an explicit error and never
presents partial results as a complete security assessment.

Run the reproducible local checks with `make performance`. On the maintainer's
reference laptop, the one-iteration 5k/20k Go benchmark completed in about 27
ms with about 24 MiB of allocations. That fixture emphasizes graph indexing and
rule traversal rather than Azure network latency, so it is a regression
baseline—not a promise about scan duration.

## Browser strategy

- Normalize snapshot data once into maps and adjacency indexes.
- Load full API snapshots only up to 500 resources and 2,000 relationships;
  larger environments use an attack-path-prioritized, structurally complete
  slice and display the loaded-versus-total counts.
- Coalesce concurrent reads of the same stored snapshot and retain one private,
  checksum-verified decoded snapshot in memory. Every caller receives an
  isolated clone, and file integrity is rechecked before a cache hit.
- Fetch follow-up graph slices and exact path-linked findings through a
  four-request worker pool instead of an unbounded request fan-out.
- Keep layout and validation work away from urgent input rendering.
- Render only visible graph elements and suppress ordinary edge labels when
  zoomed out.
- Paginate or virtualize unbounded findings, paths, and resource lists.
- Keep filtered positions stable unless the user explicitly requests a compact
  layout.
- Disable expensive blur and nonessential animation in performance mode.
