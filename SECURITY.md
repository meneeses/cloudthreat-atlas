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
