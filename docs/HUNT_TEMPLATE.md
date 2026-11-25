---
id: TH-KQL-<NNNN>
title: <Concise Hunt Title>
platform: kql
product: <Microsoft Defender XDR | Microsoft Sentinel>
tactic: <mitre-tactic-slug, e.g., execution>
techniques:
  - <T1059.001>
status: experimental # experimental | testing | production
severity: medium # low | medium | high | critical
author: Nemesisatwork
date: <YYYY-MM-DD>
data_sources:
  - <Primary KQL table, e.g., DeviceProcessEvents>
query_file: <hunt-slug>.kql
---

# <Concise Hunt Title>

## Hypothesis
State a clear, falsifiable threat hunting hypothesis. What adversary behavior are you looking for, and why would standard alerts miss it?

## Telemetry & Data Sources
- **Platform / Schema:** List the tables (`DeviceProcessEvents`, `AuditLogs`, `SigninLogs`, etc.) required.
- **Prerequisites:** Mention required Defender onboarding, Sentinel connectors, or diagnostic settings.

## Query Logic
Briefly walk through how the query filters baseline noise, parses fields, and surfaces anomalies.

## Triage & Investigation Steps
1. Verify process lineage, user context, or Entra ID identity details.
2. Check whether the activity maps to known IT/admin automation.
3. Pivot to adjacent network, file, or sign-in tables around the same timestamp.

## Known False Positives
- Document legitimate admin tools, RMM agents, or expected enterprise scripts that can trigger this hunt.

## References
- Link to MITRE ATT&CK technique pages, Microsoft documentation, or threat research blogs.
