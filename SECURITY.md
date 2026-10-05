# Security policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature on this repository. Do not open a public issue containing exploit details, credentials, subscription identifiers, or scan data.

Include the affected version, impact, reproduction steps, and a minimal proof of concept that does not target systems you do not own.

## Security boundaries

CloudThreat Atlas is a defensive, read-only analysis tool. It must not:

- mutate Azure resources or permissions;
- retrieve secret values;
- execute discovered credentials;
- perform exploitation or intrusive network probing;
- upload scan data to an external service.

Azure Resource Graph responses include control-plane metadata such as resource names, resource IDs, subscription IDs, and identity object IDs. Raw output must remain local. Use the `--redact` option before attaching a snapshot to a report or issue.

## Local workspace security

The application server binds to the loopback interface and does not enable
cross-origin access. `atlas app` creates independent high-entropy workspace
session and CSRF credentials. The launch URL carries the workspace credential
in its fragment, which is never sent in the initial HTTP request; the dashboard
captures it in memory, removes it from the visible URL, and sends it in the
`X-Atlas-Session-Token` header for every API and health request. State-changing
requests additionally require the CSRF token, and any browser Origin must match
the local Host. A refresh loses the in-memory workspace credential, so reopen
the launch URL printed by `atlas app`. Do not expose the listening port through
a reverse proxy, port-forwarding service, public tunnel, or container port
mapping. The token reduces access by unrelated local processes but is not a
sandbox against software already running as the same operating-system user.

Workspace files are private to the current operating-system user. They are not
encrypted with a separate application passphrase, so the workstation account
and disk remain part of the trust boundary. Use full-disk encryption and lock
the workstation when real subscription metadata is stored locally.

Imported snapshots are untrusted input. The application applies body-size,
structural-cardinality, analysis-work, schema, identifier, and reference checks
before committing an import. Collection cardinality and aggregate nested-data
budgets are enforced while JSON is decoded, before graph cloning or indexing.
Derived findings and attack paths supplied by an import are discarded before
materialization and recomputed locally. A failed or interrupted import must not
replace an existing snapshot.

## Generated remediation guidance

Remediation bundles are review material, not an automation channel. Generated
commands are commented by default, contain no credentials, and are never
executed by CloudThreat Atlas. Review the target scope, backup and rollback
steps, and organizational change process before adapting any command.
