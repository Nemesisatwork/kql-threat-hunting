---
id: TH-<KQL|SPL|CQL>-<NNNN>
title: <Concise Hunt Title>
platform: <kql | spl | cql>
product: <e.g., Microsoft Defender XDR | Microsoft Sentinel | Splunk Enterprise | CrowdStrike Falcon LogScale>
tactic: <mitre-tactic-slug, e.g., execution>
techniques:
  - <T1059.001>
status: experimental # experimental | testing | production
severity: medium # low | medium | high | critical
author: Nemesisatwork
date: <YYYY-MM-DD>
data_sources:
  - <Primary log table / index / event_simpleName>
query_file: <hunt-slug>.<kql|spl|cql>
---

# <Concise Hunt Title>

## Hypothesis
- **What is happening:** Explain the attacker's behavior and goal in clear, plain English without unnecessary jargon.
- **Why it blends in / why alerts miss it:** Explain how this activity resembles normal IT/admin behavior or evades standard rules.

## Telemetry & Data Sources
- **Platform / Schema:** List the tables, indices, sourcetypes, or `#event_simpleName` events required.
- **Prerequisites:** Mention required audit policies, Sysmon config, Falcon telemetry, or SIEM connectors.

## Query Logic
Break down the modular sections of the query:
1. **Tunable Parameters / Scope & Exclusions:** Time windows, target indices/tables, allowlists, and thresholds.
2. **Normalization & Behavioral Indicators:** How raw logs are filtered and labeled into risk signals.
3. **Triage Output:** Analyst-ready columns sorted for quick review.

### How to Adapt This Query
- List the exact parameters (`Lookback`, `index`/`sourcetype`, allowlists, numeric thresholds) readers can customize without changing the core detection logic.

## Triage & Investigation Steps
1. Verify process lineage, user context, or identity details.
2. Check whether the activity maps to known IT/admin automation.
3. Pivot to adjacent network, file, or authentication events around the same timestamp.

## Known False Positives
- Document legitimate admin tools, RMM agents, scanners, or expected enterprise scripts that can trigger this hunt.

## References
- Link to MITRE ATT&CK technique pages, vendor docs, or threat research blogs.
