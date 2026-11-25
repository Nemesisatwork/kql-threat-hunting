## Hunt Submission Checklist

- [ ] Query file is placed under `<tactic>/<hunt-slug>.kql` with raw KQL only (no Markdown fences).
- [ ] Paired `.md` documentation file uses `docs/HUNT_TEMPLATE.md` with complete YAML frontmatter.
- [ ] Unique `id` following `TH-KQL-<NNNN>`.
- [ ] Valid MITRE ATT&CK tactic folder and technique IDs (`Txxxx` or `Txxxx.xxx`).
- [ ] Hypothesis, triage steps, and known false positives are documented.
- [ ] `python scripts/validate_hunts.py --summary` passes with zero errors.
