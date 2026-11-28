---
id: TH-SPL-0002
title: Certutil Web Download & Decode Abuse
platform: spl
product: Splunk Enterprise
tactic: execution
techniques:
  - T1105
  - T1140
status: production
severity: high
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  - WinEventLog:Security
query_file: lotl-certutil-web-download.spl
---

# Certutil Web Download & Decode Abuse

## Hypothesis
- **What is happening:** `certutil.exe` is a built-in Windows tool meant for managing digital certificates. Attackers abuse it as a "Living off the Land" binary to download malware from the internet (`-urlcache -split -f http://...`) or decode hidden Base64 payloads (`-decode`) onto disk without bringing their own downloader tool.
- **Why it blends in / why alerts miss it:** Because `certutil.exe` is signed by Microsoft and ships with Windows, simple binary allowlisting won't stop it—you have to inspect its command-line arguments.

## Telemetry & Data Sources
- **Platform / Schema:** Splunk (`Sysmon EventCode=1` or `WinEventLog:Security EventCode=4688`).
- **Prerequisites:** Sysmon process creation logging or Windows Event `4688` with command-line auditing enabled.

## Query Logic
1. **Tunable Scope & Exclusions:** Searches both Sysmon (`EventCode=1`) and Windows Security (`EventCode=4688`) for `certutil.exe`.
2. **Field Normalization:** Uses `coalesce()` so the query works regardless of whether your logs use Sysmon or Windows Security field names, and filters out internal CA URLs.
3. **Behavioral Classification:** Labels each event as `Remote Download`, `Payload Decode`, or `Data Staging / Encode` based on the flags used.
4. **Aggregation & Triage Output:** Groups results by host, user, and abuse type with full parent processes and command lines.

### How to Adapt This Query
- **Match your Splunk indices:** Update `(index=sysmon OR index=wineventlog)` to your environment's index names (or swap to `| tstats` against the `Endpoint.Processes` CIM data model for large environments).
- **Allowlist internal PKI:** Update `internal-ca\.corp\.local` to your organization's internal Certificate Authority domains so routine CRL checks are excluded.

## Triage & Investigation Steps
1. Read the full `command_lines` and `parent_processes` values—`certutil.exe` launched by `cmd.exe`, `powershell.exe`, or an Office app is a major red flag.
2. Check whether any downloaded or decoded file on disk was executed shortly afterward.
3. Pivot on `host` and `_time` in proxy, firewall, or Sysmon Event `3` logs to inspect the remote domain or IP contacted.

## Known False Positives
- Internal PKI scripts refreshing Certificate Revocation Lists (CRLs) via `-urlcache` from internal servers.
- Developers or installers legitimately converting `.cer` / `.pem` certificate files with `-encode` or `-decode`.

## References
- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS Project - Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
