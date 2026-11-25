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
Adversaries and initial-access payloads frequently invoke `powershell.exe` or `pwsh.exe` from Office applications, script hosts, or system LOLBins using Base64-encoded commands (`-EncodedCommand`), hidden windows (`-WindowStyle Hidden`), or in-memory download cradles to evade signature-based script inspection.

## Telemetry & Data Sources
- **Platform / Schema:** Microsoft Defender XDR Advanced Hunting (`DeviceProcessEvents`).
- **Prerequisites:** Defender for Endpoint sensor onboarding and process creation telemetry enabled.

## Query Logic
1. Filters `DeviceProcessEvents` over the last 7 days for `powershell.exe` or `pwsh.exe`.
2. Computes boolean indicators for:
   - Short or full `-EncodedCommand` flags followed by Base64 payloads.
   - Hidden window flags (`-w hidden`, `-WindowStyle Hidden`).
   - Common in-memory download/decoding primitives (`DownloadString`, `Net.WebClient`, `FromBase64String`, `IEX`).
   - High-risk parent binaries (`winword.exe`, `mshta.exe`, `wscript.exe`, `wmiprvse.exe`, etc.).
3. Surfaces events matching encoded commands, hidden download cradles, or suspicious parent-child combinations.

## Triage & Investigation Steps
1. Decode any Base64 string passed to `-EncodedCommand` (UTF-16LE) and inspect the resulting script block.
2. Review `InitiatingProcessCommandLine` to determine how the parent process was launched (e.g., macro-enabled document, scheduled task, or WMI lateral movement).
3. Pivot on `DeviceId` and `Timestamp` in `DeviceNetworkEvents` and `DeviceFileEvents` to identify C2 endpoints or dropped payloads.

## Known False Positives
- Software deployment tools (SCCM/MECM, Intune, Chocolatey) or RMM platforms that wrap multi-line scripts in `-EncodedCommand`.
- Internal IT automation scripts launched via `cmd.exe` with `-WindowStyle Hidden`.

## References
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
