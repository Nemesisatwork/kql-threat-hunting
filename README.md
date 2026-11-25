# KQL Threat Hunting

Hypothesis-driven KQL threat hunting queries for Microsoft Sentinel and Defender XDR.

---

## Design Philosophy: Modular & Easy to Adapt

Every query in this repository is built to be **readable, modular, and simple to customize**:

1. **Plain-English Hypotheses:** Each hunt explains *what* the attacker is doing, *why* it matters, and *why* standard alerts often miss it—without unnecessary jargon.
2. **Top-of-File Configuration (`let` blocks):** Time windows (`Lookback`), risk lists, and environment allowlists (`AllowedDevices`, `AllowedAccounts`, `AllowedParents`) sit cleanly at the top of every `.kql` file so you can tune them without touching the detection logic.
3. **Clean Separation of Query & Docs:** `.kql` files contain ready-to-paste KQL; `.md` briefs contain the hypothesis, adaptation guide, triage steps, and false-positive notes.

---

## Repository Structure

```text
.
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       └── validate.yml          # Automated metadata & KQL syntax checks
├── docs/
│   └── HUNT_TEMPLATE.md          # Standard template for new hunt documentation
├── scripts/
│   └── validate_hunts.py         # Local & CI validation script
├── execution/                    # MITRE ATT&CK Tactic folders
└── initial-access/
```

---

## Hunts Index

| ID | Tactic | Technique | Product | Hunt |
| --- | --- | --- | --- | --- |
| `TH-KQL-0001` | Execution | `T1059.001`, `T1027` | Microsoft Defender XDR | [LOLBin & Encoded PowerShell Execution](execution/lotl-lolbin-encoded-powershell.md) |
| `TH-KQL-0002` | Initial Access | `T1528`, `T1550.001` | Microsoft Sentinel | [Suspicious OAuth Application Consent Grants](initial-access/suspicious-oauth-app-consent.md) |

---

## Adding a New Hunt

1. Pick or create the matching MITRE ATT&CK tactic folder (lowercase kebab-case, e.g., `credential-access/`).
2. Create `<hunt-slug>.kql` with modular `let` parameters at the top and clean `//` section comments (no Markdown code fences).
3. Copy [`docs/HUNT_TEMPLATE.md`](docs/HUNT_TEMPLATE.md) to `<hunt-slug>.md` in the same folder and complete all sections.
4. Validate locally before committing:

```bash
python scripts/validate_hunts.py --summary
```

GitHub Actions automatically runs `validate_hunts.py` on every push and pull request.
