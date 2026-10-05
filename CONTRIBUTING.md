# Contributing

Thank you for helping make cloud security easier to understand.

## Development workflow

1. Fork and clone the repository.
2. Install Go 1.27+, Node.js 24+, and npm 12+.
3. Run `make setup`.
4. Create a focused branch and add tests with the change.
5. Run `make test` and `make verify` before opening a pull request.

Changes to graph rendering, validation, analysis, or generated asset size must
also run `make performance`. Document any intentional budget change in
`docs/PERFORMANCE.md` rather than weakening a check silently.

When frontend code changes, run `npm run build:embed` from `web/` and commit
the refreshed `internal/server/webdist/` output. CI rebuilds it and rejects
stale generated assets.

Use Conventional Commit-style messages when practical, for example `feat(graph): add identity edge details`.

## Project boundaries

Changes must preserve these guarantees:

- scanning is read-only;
- secret values are never queried and tenant metadata is redacted before sharing;
- the synthetic demo works without Azure credentials;
- the open-source core retains a zero-cost execution path;
- generated or real scan data is not committed.
- localhost endpoints do not accept cross-origin state changes;
- generated remediation material is never executed by the application.

Use a temporary `--data-dir` while developing workspace migrations. Tests must
not read or modify the user's real CloudThreat Atlas data directory.

The maintainer identity hook is a local safeguard and is not intended to rewrite contributor authorship. CI only blocks known accidental company attribution.

Maintainers can activate the repository's personal identity hooks with
`make maintainer-setup` and run the additional check with
`make verify-maintainer`. Contributors should keep their own author identity
and remotes; the generic `make verify` target does not require Joao's private
SSH alias.
