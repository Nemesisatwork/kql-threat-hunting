# KQL Threat Hunts (Microsoft Sentinel & Defender XDR)

Queries in this folder target **Kusto Query Language (KQL)** across Microsoft Defender XDR (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`) and Microsoft Sentinel (`AuditLogs`, `SigninLogs`, `SecurityEvent`).

## Conventions
- Keep tunable parameters (`Lookback`, allowlists, and keyword lists) in `let` statements at the top of each `.kql` file.
- Use `//` for inline comments and keep queries free of Markdown code fences.
