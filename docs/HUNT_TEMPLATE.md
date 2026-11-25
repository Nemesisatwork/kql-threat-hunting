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
Explain the threat in plain, everyday security terms so anyone reading can immediately understand:
- **What is happening:** Describe the attacker's goal and technique without heavy jargon.
- **Why it blends in / why alerts miss it:** Explain how this behavior looks similar to normal IT or admin activity.

## Telemetry & Data Sources
- **Platform / Schema:** List the tables (`DeviceProcessEvents`, `AuditLogs`, `SigninLogs`, etc.) required.
- **Prerequisites:** Mention required Defender onboarding, Sentinel connectors, or diagnostic settings.

## Query Logic
Break down the modular sections of the `.kql` file:
1. **Tunable Parameters (`let` statements):** Time window, thresholds, and environment allowlists.
2. **Core Signal & Enrichment:** How raw logs are filtered and labeled into clear risk indicators.
3. **Output:** Clean, analyst-ready columns sorted for quick review.

### How to Adapt This Query
- List the exact `let` variables (e.g., `Lookback`, `AllowedAccounts`, `AllowedParents`) a reader can edit to fit their environment without touching the core detection logic.

## Triage & Investigation Steps
1. Verify process lineage, user context, or Entra ID identity details.
2. Check whether the activity maps to known IT/admin automation.
3. Pivot to adjacent network, file, or sign-in tables around the same timestamp.

## Known False Positives
- Document legitimate admin tools, RMM agents, or expected enterprise scripts that can trigger this hunt.

## References
- Link to MITRE ATT&CK technique pages, Microsoft documentation, or threat research blogs.
