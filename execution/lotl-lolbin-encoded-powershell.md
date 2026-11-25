---
id: TH-KQL-0001
title: LOLBin & Encoded PowerShell Execution
platform: kql
product: Microsoft Defender XDR
tactic: execution
techniques:
  - T1059.001
  - T1027
status: production
severity: high
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - DeviceProcessEvents
query_file: lotl-lolbin-encoded-powershell.kql
---

# LOLBin & Encoded PowerShell Execution

## Hypothesis
- **What is happening:** Attackers often hide malicious commands inside PowerShell by encoding them into unreadable Base64 text (`-EncodedCommand`), hiding the PowerShell window (`-WindowStyle Hidden`), or downloading extra malware straight into memory instead of saving a file to disk. They commonly launch this from everyday apps like Word, Excel, or Windows scripting tools (`mshta.exe`, `wscript.exe`).
- **Why it blends in / why alerts miss it:** PowerShell is used constantly by IT teams and software installers. By using built-in Windows tools ("Living off the Land") and keeping payloads in memory without dropping `.exe` files, attackers can slip past basic antivirus signatures.

## Telemetry & Data Sources
- **Platform / Schema:** Microsoft Defender XDR Advanced Hunting (`DeviceProcessEvents`).
- **Prerequisites:** Microsoft Defender for Endpoint onboarded on endpoints with process creation telemetry enabled.

## Query Logic
1. **Tunable Parameters (`let` block):** Sets the search window, target shells, risky parent apps, download keywords, and empty allowlists ready to customize.
2. **Allowlist Filtering:** Filters `DeviceProcessEvents` and removes any approved devices, service accounts, or known script paths you add to the allowlists.
3. **Behavioral Indicators:** Flags encoded Base64 arguments, hidden windows combined with download commands, or suspicious parent processes launching hidden/downloading PowerShell.
4. **Triage Output:** Projects the exact parent command line, child command line, boolean flags, and SHA256 hash sorted newest first.

### How to Adapt This Query
- **Adjust the time window:** Change `Lookback` (default `7d`) to `24h` or `30d`.
- **Suppress noisy IT automation:** Add known service accounts to `AllowedAccounts`, lab hosts to `AllowedDevices`, or approved script paths to `AllowedCommandSubstrings`.
- **Expand parent monitoring:** Add or remove process names in `SuspiciousParents` based on your environment's risk profile.

## Triage & Investigation Steps
1. Decode any Base64 string passed to `-EncodedCommand` (UTF-16LE) to read the actual script commands.
2. Review `InitiatingProcessCommandLine` to see how the parent program was triggered (e.g., an email attachment, macro document, or scheduled task).
3. Pivot on `DeviceName` and `Timestamp` in `DeviceNetworkEvents` and `DeviceFileEvents` to spot external C2 connections or dropped files.

## Known False Positives
- Software deployment platforms (Intune, SCCM/MECM, Chocolatey) or RMM tools that wrap admin scripts inside `-EncodedCommand`.
- Internal IT scripts launched from `cmd.exe` with `-WindowStyle Hidden`.

## References
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
