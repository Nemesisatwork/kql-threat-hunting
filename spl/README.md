# SPL Threat Hunts (Splunk Enterprise)

Queries in this folder target **Splunk Search Processing Language (SPL)** across Windows Security, Sysmon, and CIM data models.

## Conventions
- Separate base `index`/`sourcetype` scope and exclusions, field normalization, behavioral detection, and numeric thresholds into clearly labeled stages.
- Use SPL macro-style comments (```` ``` comment ``` ````) rather than `//` or `#`.
