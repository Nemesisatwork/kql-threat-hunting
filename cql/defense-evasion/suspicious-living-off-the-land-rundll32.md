---
id: TH-CQL-0002
title: Suspicious Rundll32 Proxy Execution
platform: cql
product: CrowdStrike Falcon LogScale
tactic: defense-evasion
techniques:
  - T1218.011
status: testing
severity: medium
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - ProcessRollup2
query_file: suspicious-living-off-the-land-rundll32.cql
---

# Suspicious Rundll32 Proxy Execution

## Hypothesis
- **What is happening:** `rundll32.exe` is a standard Windows program whose job is to run code stored inside `.dll` files. Attackers use it as a disguise ("proxy execution") to run malicious DLLs from temporary folders or network shares, run inline JavaScript/VBScript, or call obfuscated functions by number (`#1`) instead of a readable function name.
- **Why it blends in / why alerts miss it:** `rundll32.exe` runs legitimately all day on Windows. Unless you look closely at *where* the DLL lives, *what* protocol is on the command line, or *who* launched `rundll32.exe`, malicious runs look just like normal background Windows tasks.

## Telemetry & Data Sources
- **Platform / Schema:** CrowdStrike Falcon LogScale / Next-Gen SIEM (`#event_simpleName=ProcessRollup2`, `event_platform=Win`).
- **Prerequisites:** CrowdStrike Falcon process creation telemetry enabled.

## Query Logic
1. **Base Telemetry Scope:** Filters Windows `ProcessRollup2` events for `rundll32.exe`.
2. **Environment Exclusions:** Provides clean allowlist slots to filter out noisy known installers or enterprise tools.
3. **Modular Behavior Indicators:** Uses a `case` block to label five distinct red flags (script protocols, UNC/HTTP paths, user-writable staging folders, ordinal-only exports `#1`, and Office/script-host parents).
4. **Triage Output:** Returns up to 500 matching rows sorted newest first with host, user, indicator label, and full command line.

### How to Adapt This Query
- **Add environment allowlists:** Update `!in(field="ParentBaseFileName", values=[...])` or `CommandLine!=/.../i` in Section 2 to silence legitimate enterprise tools or printer drivers.
- **Adjust result size:** Change `limit=500` in `table(...)` to match your LogScale query window.
- **Toggle indicators:** Comment out or add lines inside `case { ... }` without affecting the rest of the pipeline.

## Triage & Investigation Steps
1. Inspect `CommandLine` to identify the exact DLL path, URL, or embedded script being executed.
2. Pivot on `TargetProcessId` and `aid` to check for outbound network connections (`NetworkConnectIP4` / `DnsRequest`) or child processes spawned by `rundll32.exe`.
3. Hash-check or retrieve any DLL located inside `AppData`, `ProgramData`, `Users\Public`, or `Temp`.

## Known False Positives
- Software installers, printer utilities, or browser/VPN updaters launching temporary DLLs from `AppData\Local\Temp` or invoking ordinal exports.
- Legitimate Windows Control Panel tools or signed enterprise apps hosted on internal UNC paths.

## References
- [MITRE ATT&CK T1218.011 - System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS Project - Rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
