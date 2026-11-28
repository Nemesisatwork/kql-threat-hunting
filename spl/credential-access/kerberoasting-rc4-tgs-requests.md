---
id: TH-SPL-0001
title: Kerberoasting via RC4 TGS Requests (Event 4769)
platform: spl
product: Splunk Enterprise
tactic: credential-access
techniques:
  - T1558.003
status: production
severity: high
author: Nemesisatwork
date: 2026-11-26
data_sources:
  - WinEventLog:Security
query_file: kerberoasting-rc4-tgs-requests.spl
---

# Kerberoasting via RC4 TGS Requests (Event 4769)

## Hypothesis
- **What is happening:** In Active Directory, any normal user can ask a Domain Controller for a service ticket (TGS) to access things like SQL servers or web apps. During a Kerberoasting attack, an attacker requests lots of these service tickets at once—specifically asking for weaker `RC4` encryption (`0x17`)—so they can take the tickets offline and crack the service accounts' passwords.
- **Why it blends in / why alerts miss it:** Requesting a Kerberos service ticket is completely normal Windows behavior and does not trigger failed-logon alerts. You only catch it by looking for *spikes* of `RC4` ticket requests from a single user or workstation.

## Telemetry & Data Sources
- **Platform / Schema:** Splunk (`WinEventLog:Security` collected from Active Directory Domain Controllers).
- **Prerequisites:** Windows Advanced Audit Policy `Audit Kerberos Service Ticket Operations` (Success) enabled on Domain Controllers.

## Query Logic
1. **Tunable Scope & Exclusions:** Filters Event `4769` for RC4 (`0x17`), removes machine accounts (`*$`) and `krbtgt`, and excludes allowlisted service accounts.
2. **Field Normalization & Time Bucketing:** Strips IPv6 prefixes from `Client_Address` and groups events into 10-minute windows (`bin _time span=10m`).
3. **Aggregation & Tunable Thresholds:** Counts total requests and distinct target services (`unique_spn_count`) per user and source IP, keeping only activity above `min_unique_spns` or `min_total_tgs`.
4. **Triage Output:** Returns a clean summary table sorted by the highest number of unique services targeted.

### How to Adapt This Query
- **Change index/sourcetype:** Update `index=wineventlog sourcetype="WinEventLog:Security"` on line 2 to match your Splunk environment (e.g., `index=windows`).
- **Exclude legacy scanners:** Replace `"svc_vuln_scanner"` and `"svc_legacy_example"` in `NOT Account_Name IN (...)` with known accounts that legitimately use RC4.
- **Tune sensitivity:** Adjust `min_unique_spns=3`, `min_total_tgs=5`, or `bin _time span=10m` depending on your domain size.

## Triage & Investigation Steps
1. Check if `Account_Name` is a regular user or workstation that shouldn't be enumerating multiple service SPNs.
2. Pivot on `Client_IP` in endpoint logs (Sysmon Event `1` or Windows `4688`) to look for tools like `Rubeus`, `PowerView`, or Python scripts (`GetUserSPNs.py`).
3. Review `targeted_services` to prioritize high-value accounts (SQL services, backup accounts, or accounts with older passwords) for immediate password rotation.

## Known False Positives
- Legacy vulnerability scanners or monitoring tools that still negotiate RC4-HMAC (`0x17`) across multiple servers.
- Older enterprise applications in domains where AES Kerberos encryption is not yet enforced.

## References
- [MITRE ATT&CK T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Security Event 4769 Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
