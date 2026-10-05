# Zero-cost policy

CloudThreat Atlas must remain fully useful as a personal open-source project without requiring a credit card or paid cloud resources.

The public path uses [GitHub Pages for a public repository](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) and standard GitHub-hosted runners under the [GitHub Actions billing policy](https://docs.github.com/en/billing/concepts/product-billing/github-actions). No larger runner, paid domain, or external hosting service is required.

## Free path

| Capability | Zero-cost implementation |
| --- | --- |
| Public demo | GitHub Pages from a public repository |
| CI and Pages deployment | Standard Ubuntu GitHub-hosted runners |
| Backend and API | Local Go process |
| Persistence | Versioned JSON snapshots on the local machine |
| Azure analysis | Read-only queries against an existing subscription |
| Observability | Local structured logs and health endpoint |
| Reports | Local JSON, HTML, Markdown, and SARIF files |

## Guardrails

- No managed database, custom domain, paid telemetry, commercial API, or continuously running backend is required.
- Workflows do not use larger runners and avoid retaining build artifacts or oversized caches.
- The Azure collector must not contain provisioning or mutation operations.
- Infrastructure-as-code that can create billable resources is outside the open-source core.
- A future SaaS requires a separate architecture decision record, explicit budget, billing controls, and an opt-in deployment.

If a proposed feature cannot operate on the free path, it must remain optional and may not reduce the capabilities of the local product.
