# Azure collection and evidence

CloudThreat Atlas uses Azure Resource Graph as a read-only metadata source. The
collector creates no Azure resources, calls no write APIs, and intentionally
projects network configuration and RBAC metadata rather than secret values,
connection strings, access keys, or application settings.

## Scope-aware RBAC

Role assignments are represented once, from a principal to the Azure scope on
the assignment. Subscription, resource-group, and resource containment edges
make the scope traversable. Rules resolve a grant to matching descendants when
they evaluate it. This avoids the former `assignments × resources` edge growth
for subscription and resource-group assignments.

Known built-in roles have explicit capability mappings. Custom roles are
classified only when their effective `actions` or `dataActions` match a small
set of security-relevant Azure actions. `notActions` and `notDataActions` are
applied before a capability is emitted. Unrecognized roles remain visible as
non-exploitable `role_assignment` relationships; the collector does not guess.

## Network normalization

The Resource Graph projection covers virtual machines, NICs, virtual networks,
subnets, public IP associations, NSGs and their security rules, and private
endpoints. It also records the network defaults used by App Service, Storage,
Key Vault, Azure SQL, and PostgreSQL Flexible Server. An exploitable
`public_exposure` edge is emitted only when the collected defaults establish
Internet-wide reachability; it does not claim that service authentication can
be bypassed. When a public endpoint exists but ACL or firewall reachability is
restricted or not proven, Atlas emits a non-exploitable `public_endpoint` edge
instead. A public-IP association is likewise evidence of addressing, not proof
that NSG ingress is allowed.

NSG allow rules and NSG-to-subnet/NIC attachments are also evidence rather
than effective-reachability claims. Azure evaluates rules by priority and
requires both subnet- and NIC-level NSGs to allow inbound traffic. Until Atlas
can join public addressing with the complete effective policy, it emits
non-exploitable `public_ingress_candidate` and `network_filter` relationships.

Each collected relationship can include:

- `origin`: `observed`, `derived`, or `heuristic`;
- `confidence`: `high`, `medium`, or `low`;
- structured `evidence` pointing to the Resource Graph field used.

These fields are optional and the emitted snapshot schema remains `1.0`, so
older snapshots and clients remain compatible. Findings retain their existing
human-readable `evidence` and may add optional `evidenceDetails`.

Azure snapshots also preserve their optional collection `scope` (subscription
and, when selected, resource group). The local workspace uses this portable
scope to keep full-subscription and resource-group histories separate after an
export and re-import. Redacted exports replace both scope identifiers with
deterministic aliases, preserving that separation without publishing tenant
identifiers. Resource-group aliases are keyed by the high-entropy subscription
identifier before that identifier is removed, preventing generic offline
dictionary lookups for common names such as `prod`.

## Query behavior and limitations

Resource, role-assignment, and role-definition queries execute independently
with bounded concurrency. Each query follows Resource Graph skip tokens,
honors context cancellation, and retries throttling, request timeouts, and 5xx
responses with bounded backoff.

Collection also has hard retention limits: 1,000 rows per page, 50 pages,
50,000 rows or 64 MiB of encoded metadata per query, and 100,000 rows or 96 MiB
across the concurrent query set. The byte budgets include nested network and
custom-role metadata, not just top-level row counts. If Azure reports more
data, repeats a pagination token, or otherwise exceeds a budget, the scan fails
closed with an explicit error. Atlas never publishes a partial snapshot that
could understate exposure.

Normalization is covered by deterministic fixture tests and does not require a
tenant. Live-subscription validation is still pending, so Azure may expose
service-specific Resource Graph shapes not represented by the current fixtures.
