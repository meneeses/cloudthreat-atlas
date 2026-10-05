# Launch post draft

I built **CloudThreat Atlas**, an open-source, local-first Azure attack-path explorer written in Go, React, and TypeScript.

It turns cloud resources, identities, public exposure, and RBAC relationships into an interactive graph, then explains how an attacker could move from an entry point to a critical asset.

The new v0.2 release includes:

- three narrated attack paths in a safe synthetic healthcare environment;
- a deterministic Go rule and path-analysis engine;
- what-if remediation simulations that never change the source environment;
- JSON, HTML, Markdown, and SARIF reports;
- a private local workspace with immutable snapshots, history, comparison, and finding triage;
- a local, read-only Azure Resource Graph collector with scope-aware RBAC, evidence provenance, and share-safe redaction;
- bounded analysis and focused graph views designed for larger environments;
- cancelable scans, review-only remediation bundles, and cross-platform binaries;
- a static GitHub Pages demo that requires no account, credentials, or paid infrastructure.

The project was designed around three constraints: make cloud-security relationships understandable, keep tenant data on the operator's machine, and preserve a complete zero-cost open-source path. Atlas does not provision cloud resources, retrieve secret values, or apply remediation.

Live demo: https://meneeses.github.io/cloudthreat-atlas/

Source: https://github.com/meneeses/cloudthreat-atlas

I would love feedback from people working with Go, Azure architecture, cloud security, or attack-path analysis.
