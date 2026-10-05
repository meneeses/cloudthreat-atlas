# Launch post draft

I built **CloudThreat Atlas**, an open-source Azure attack-path explorer written in Go, React, and TypeScript.

It turns cloud resources, identities, public exposure, and RBAC relationships into an interactive graph, then explains how an attacker could move from an entry point to a critical asset.

The first release includes:

- three narrated attack paths in a safe synthetic healthcare environment;
- a deterministic Go rule and path-analysis engine;
- what-if remediation simulations that never change the source environment;
- JSON, HTML, Markdown, and SARIF reports;
- a local, read-only Azure Resource Graph collector with share-safe redaction;
- a static GitHub Pages demo that requires no account, credentials, or paid infrastructure.

The project was designed around two constraints: make cloud-security relationships understandable, and keep the complete open-source path free to run.

Live demo: https://meneeses.github.io/cloudthreat-atlas/

Source: https://github.com/meneeses/cloudthreat-atlas

I would love feedback from people working with Go, Azure architecture, cloud security, or attack-path analysis.
