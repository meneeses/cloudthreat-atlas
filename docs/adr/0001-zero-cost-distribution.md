# ADR 0001: Zero-cost distribution

- Status: Accepted
- Date: 2026-10-04

## Context

The project needs a polished public demo without creating recurring personal expenses or requiring visitors to authenticate.

## Decision

Publish the synthetic React build with GitHub Pages. Run the Go API and real Azure scanner locally. Do not require a hosted database, backend, paid domain, or paid observability service.

## Consequences

- The public demo uses static fixtures and precomputed simulations.
- The local application provides complete dynamic analysis and simulation.
- A future SaaS is a separate product decision and cannot replace the free local workflow.
