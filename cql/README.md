# CQL Threat Hunts (CrowdStrike Falcon LogScale / Next-Gen SIEM)

Queries in this folder target **CrowdStrike Query Language (CQL)** using Falcon telemetry (`#event_simpleName=ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, etc.).

## Conventions
- Separate base telemetry scope, environment allowlists (`!in(...)`), `case` indicators, and aggregation/triage output into modular pipe stages.
- Use `//` or `/* ... */` for comments and keep `.cql` files free of Markdown code fences.
