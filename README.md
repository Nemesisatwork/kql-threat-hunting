# Threat Hunting

Hypothesis-driven threat hunting queries across **KQL** (Microsoft Sentinel / Defender XDR), **SPL** (Splunk Enterprise), and **CQL** (CrowdStrike Falcon LogScale / Next-Gen SIEM).

---

## Design Philosophy: Modular & Easy to Adapt

Every hunt in this repository is built to be **readable, modular, and simple to customize**:

1. **Plain-English Hypotheses:** Each hunt explains *what* the attacker is doing, *why* it matters, and *why* standard alerts often miss it—without unnecessary jargon.
2. **Modular Query Structure:** Time windows, indices/tables, allowlists, exclusions, and numeric thresholds sit cleanly at the top of each query, separated from the core detection and triage output stages.
3. **Adaptation Guides:** Every hunt brief includes a **How to Adapt This Query** section listing the exact parameters you can tune for your own environment.

---

## Repository Structure

```text
.
├── .github/
│   └── workflows/
│       └── validate.yml          # Automated metadata & query syntax checks
├── docs/
│   └── HUNT_TEMPLATE.md          # Standard modular hunt documentation template
├── scripts/
│   └── validate_hunts.py         # Multi-platform validation script (KQL, SPL, CQL)
├── kql/                          # Microsoft Sentinel & Defender XDR (Kusto Query Language)
├── spl/                          # Splunk Enterprise (Search Processing Language)
├── cql/                          # CrowdStrike Falcon LogScale / NG-SIEM (CrowdStrike Query Language)
└── LICENSE                       # MIT License
```

Inside each platform folder, hunts are organized by **MITRE ATT&CK Enterprise Tactic** (`initial-access/`, `execution/`, `defense-evasion/`, `credential-access/`, etc.). Each hunt consists of a raw query file (`.kql`, `.spl`, `.cql`) paired with a Markdown brief (`.md`).

---

## Hunts Index

| ID | Platform | Tactic | Techniques | Hunt |
| --- | --- | --- | --- | --- |
| `TH-KQL-0001` | KQL | Execution | `T1059.001`, `T1027` | [LOLBin & Encoded PowerShell Execution](kql/execution/lotl-lolbin-encoded-powershell.md) |
| `TH-KQL-0002` | KQL | Initial Access | `T1528`, `T1550.001` | [Suspicious OAuth Application Consent Grants](kql/initial-access/suspicious-oauth-app-consent.md) |
| `TH-SPL-0001` | SPL | Credential Access | `T1558.003` | [Kerberoasting via RC4 TGS Requests (Event 4769)](spl/credential-access/kerberoasting-rc4-tgs-requests.md) |
| `TH-SPL-0002` | SPL | Execution | `T1105`, `T1140` | [Certutil Web Download & Decode Abuse](spl/execution/lotl-certutil-web-download.md) |
| `TH-CQL-0001` | CQL | Credential Access | `T1003.001` | [LSASS Memory Dumping via LOLBins & Tools](cql/credential-access/lsass-memory-access-dumping.md) |
| `TH-CQL-0002` | CQL | Defense Evasion | `T1218.011` | [Suspicious Rundll32 Proxy Execution](cql/defense-evasion/suspicious-living-off-the-land-rundll32.md) |

---

## License

Licensed under the [MIT License](LICENSE).
