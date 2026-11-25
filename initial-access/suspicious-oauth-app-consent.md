---
id: TH-KQL-0002
title: Suspicious OAuth Application Consent Grants
platform: kql
product: Microsoft Sentinel
tactic: initial-access
techniques:
  - T1528
  - T1550.001
status: testing
severity: high
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - AuditLogs
query_file: suspicious-oauth-app-consent.kql
---

# Suspicious OAuth Application Consent Grants

## Hypothesis
- **What is happening:** Instead of stealing a password, an attacker tricks a user (or admin) into clicking "Accept" on a malicious third-party cloud app. That single click hands the app an OAuth token with permission to read emails, download OneDrive/SharePoint files, or even modify directory roles—without ever needing the user's password or MFA again.
- **Why it blends in / why alerts miss it:** Granting permissions to cloud apps looks like normal SaaS onboarding in Entra ID, and no traditional failed-login or malware alert fires because the user legitimately approved the prompt.

## Telemetry & Data Sources
- **Platform / Schema:** Microsoft Sentinel (`AuditLogs` from Microsoft Entra ID).
- **Prerequisites:** Microsoft Entra ID Diagnostic Settings streaming `AuditLogs` to your Log Analytics / Sentinel workspace.

## Query Logic
1. **Tunable Parameters (`let` block):** Defines the lookback window, Entra ID consent operation names, high-risk Microsoft Graph permissions, and allowlists for approved apps and admins.
2. **Allowlist Filtering:** Filters `AuditLogs` (`ApplicationManagement`) and skips any pre-approved `AllowedAppIds` or `AllowedActors`.
3. **Permission Parsing & Risk Flagging:** Expands `modifiedProperties` to inspect the exact permissions granted and sets `HasHighRiskScope = true` when sensitive scopes like `Mail.ReadWrite` or `Files.ReadWrite.All` appear.
4. **Triage Output:** Summarizes who granted consent, from what IP, for which app, and floats high-risk scopes to the top.

### How to Adapt This Query
- **Reduce noise quickly:** Set `OnlyShowHighRiskScopes = true` to focus strictly on sensitive mailbox, file, and directory permissions.
- **Allowlist known SaaS apps:** Add trusted application GUIDs to `AllowedAppIds` and identity admins to `AllowedActors`.
- **Customize risky scopes:** Add or remove Microsoft Graph scopes inside `HighRiskPermissions` (e.g., `Calendars.Read` or `Notes.Read.All`).

## Triage & Investigation Steps
1. Verify whether `AppDisplayName` and `AppId` belong to a sanctioned company tool or an unverified external publisher.
2. Check `ActorIP` and correlate with `SigninLogs` around `ConsentTimestamp` for unfamiliar locations, VPNs, or suspicious user-agents.
3. Review Microsoft 365 activity (`OfficeActivity`) for inbox rule changes, mail searches, or bulk SharePoint/OneDrive downloads tied to that user or app.

## Known False Positives
- Approved third-party productivity apps (calendar schedulers, CRM plugins) consented to by employees or IT admins.

## References
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Microsoft Guidance - Detect and Remediate Illicit Consent Grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
