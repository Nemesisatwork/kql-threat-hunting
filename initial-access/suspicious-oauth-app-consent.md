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
Threat actors conduct illicit OAuth consent phishing to trick users or admins into granting third-party Entra ID applications persistent access to mailboxes (`Mail.Read*`), SharePoint/OneDrive (`Files.Read*`), or directory roles without needing user passwords or MFA prompts on subsequent token refreshes.

## Telemetry & Data Sources
- **Platform / Schema:** Microsoft Sentinel (`AuditLogs` from Microsoft Entra ID).
- **Prerequisites:** Microsoft Entra ID Diagnostic Settings streaming `AuditLogs` to Log Analytics / Sentinel.

## Query Logic
1. Queries `AuditLogs` under `ApplicationManagement` for consent and permission grant operations (`Consent to application`, `Add delegated permission grant`, etc.).
2. Extracts the initiating user UPN, IP address, target application name/ID, and `modifiedProperties`.
3. Expands modified properties to surface granted scopes and flags any matching high-risk Microsoft Graph permissions (`Mail.ReadWrite`, `Files.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `offline_access`).

## Triage & Investigation Steps
1. Verify whether the `AppDisplayName` and `AppId` correspond to an approved enterprise SaaS integration or an unverified multi-tenant publisher.
2. Check `ActorIP` reputation and correlate with `SigninLogs` around `ConsentTimestamp` for anomalous user-agents or impossible travel.
3. Review Microsoft Graph/Exchange audit logs (`OfficeActivity`) for mail search, inbox rule creation, or bulk file access using the newly consented app.

## Known False Positives
- Legitimate productivity SaaS apps approved by users when user consent is not restricted, or IT admins onboarding new Entra ID integrations.

## References
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Microsoft Guidance - Detect and Remediate Illicit Consent Grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
