# KQL Threat Hunting

Hypothesis-driven KQL threat hunting queries for Microsoft Sentinel and Defender XDR.

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

Each top-level tactic directory follows **MITRE ATT&CK Enterprise** naming (`initial-access/`, `execution/`, `persistence/`, `privilege-escalation/`, `defense-evasion/`, `credential-access/`, `discovery/`, `lateral-movement/`, `collection/`, `command-and-control/`, `exfiltration/`, `impact/`).

Every hunt consists of a **paired `.kql` query + `.md` brief**:
- `<hunt-slug>.kql` — Clean, copy-pasteable KQL query with inline `//` comments.
- `<hunt-slug>.md` — YAML frontmatter + hypothesis, telemetry requirements, query logic, triage steps, and known false positives.

---

## Hunts Index

| ID | Tactic | Technique | Product | Hunt |
| --- | --- | --- | --- | --- |
| `TH-KQL-0001` | Execution | `T1059.001`, `T1027` | Microsoft Defender XDR | [LOLBin & Encoded PowerShell Execution](execution/lotl-lolbin-encoded-powershell.md) |
| `TH-KQL-0002` | Initial Access | `T1528`, `T1550.001` | Microsoft Sentinel | [Suspicious OAuth Application Consent Grants](initial-access/suspicious-oauth-app-consent.md) |

---

## Adding a New Hunt

1. Pick or create the matching MITRE ATT&CK tactic folder (lowercase kebab-case, e.g., `credential-access/`).
2. Create `<hunt-slug>.kql` containing only the query and `//` comments (no Markdown code fences).
3. Copy [`docs/HUNT_TEMPLATE.md`](docs/HUNT_TEMPLATE.md) to `<hunt-slug>.md` in the same folder and complete all sections.
4. Validate locally before committing:

```bash
python scripts/validate_hunts.py --summary
```

GitHub Actions automatically runs `validate_hunts.py` on every push and pull request.
