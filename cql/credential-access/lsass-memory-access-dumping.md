---
id: TH-CQL-0001
title: LSASS Memory Dumping via LOLBins & Tools
platform: cql
product: CrowdStrike Falcon LogScale
tactic: credential-access
techniques:
  - T1003.001
status: production
severity: critical
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - ProcessRollup2
query_file: lsass-memory-access-dumping.cql
---

# LSASS Memory Dumping via LOLBins & Tools

## Hypothesis
- **What is happening:** Windows keeps active user logins, NTLM hashes, and Kerberos tickets inside the memory of a core system process called `lsass.exe`. Instead of dropping noisy hacking tools like Mimikatz, attackers often abuse legitimate Microsoft tools—like `rundll32.exe` with `comsvcs.dll`, `procdump.exe`, or `sqldumper.exe`—to save a copy ("dump") of `lsass.exe` memory so they can steal passwords offline.
- **Why it blends in / why alerts miss it:** Signed troubleshooting utilities like `rundll32.exe` and `procdump.exe` are trusted on Windows, so monitoring command-line arguments and rare dump flags gives you coverage even when attackers avoid known offensive binaries.

## Telemetry & Data Sources
- **Platform / Schema:** CrowdStrike Falcon LogScale / Next-Gen SIEM (`#event_simpleName=ProcessRollup2`, `event_platform=Win`).
- **Prerequisites:** CrowdStrike Falcon sensor deployed on Windows endpoints with Falcon Data Replicator (FDR) or LogScale telemetry ingestion.

## Query Logic
1. **Base Telemetry Scope:** Filters for Windows process creation (`ProcessRollup2` where `event_platform=Win`).
2. **Target Binaries & Exclusions:** Narrows to utilities commonly abused for memory dumping and excludes authorized incident-response accounts.
3. **Modular Behavior Indicators:** Uses a `case` block to tag each match clearly (`comsvcs.dll MiniDump`, `Explicit LSASS Dump Flag`, `Known Credential Dumper Binary`, `SQLDumper Full Memory Dump`).
4. **Aggregation & Triage Output:** Groups hits by host, user, and method with parent process, full command line, and SHA256 hash.

### How to Adapt This Query
- **Tune admin exclusions:** Update `!in(field="UserName", values=["authorized_ir_admin"])` with your incident response or IT support accounts that legitimately capture crash dumps.
- **Add new dumpers:** Append new regex patterns to the `in(field="ImageFileName", ...)` list and add a matching line inside the `case { ... }` block.

## Triage & Investigation Steps
1. Check `ParentBaseFileName` and `UserName` to see who ran the command and whether it came from an interactive session, remote shell, or C2 implant.
2. Pivot on the host (`ComputerName` / `aid`) for file-write events creating `.dmp`, `.bin`, or `.zip` files in `Temp`, `Users\Public`, or `ProgramData`.
3. Look for outbound network transfers of the dump file and immediately reset credentials for any accounts active on that host if confirmed.

## Known False Positives
- Authorized troubleshooting by IT engineers taking application crash dumps with `procdump.exe` or `sqldumper.exe` (legitimate dumps almost never target `lsass.exe`).

## References
- [MITRE ATT&CK T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [LOLBAS Project - Comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/)
