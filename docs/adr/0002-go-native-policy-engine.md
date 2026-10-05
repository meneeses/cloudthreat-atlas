# ADR 0002: Go-native policy engine

- Status: Accepted
- Date: 2026-10-04

## Context

The first release must demonstrate Go design skills, remain easy to debug, and avoid introducing an additional policy runtime before the domain stabilizes.

## Decision

Represent rules as Go implementations of a small `Rule` interface. Each rule has a stable identifier and returns findings with evidence and remediation.

## Consequences

- Rules compile into the single local binary and are covered by ordinary Go tests.
- The initial contribution model is simpler than embedding a second language.
- OPA/Rego or external policy packs may be evaluated after the snapshot and finding contracts stabilize.
