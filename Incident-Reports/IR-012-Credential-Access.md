# SOC Incident Report — IR-012: Credential Access Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-012
**Category:** Credential Access / Windows Credential Store Enumeration
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Controlled lab investigation
**Severity:** Informational — Credential extraction not demonstrated
**Disposition:** Credential-related process monitoring

This exercise evaluates endpoint visibility into commands that enumerate Windows credential-related stores or targets.

The lab observed a `VaultCmd.exe /list` process event and also tested `cmdkey.exe /list`.

The available evidence demonstrates credential-related enumeration activity. It does not demonstrate that stored passwords were extracted or that credentials were compromised.

## 2. Scope and Environment

| Attribute          | Details                      |
| ------------------ | ---------------------------- |
| Endpoint           | `TargetMachine`              |
| SIEM index         | `main`                       |
| Primary event      | Sysmon Event ID 1            |
| Relevant processes | `VaultCmd.exe`, `cmdkey.exe` |
| Observed command   | `VaultCmd.exe /list`         |

## 3. Detection and Evidence

The observed Splunk event contained the following information:

| Field          | Observed value                                                      |
| -------------- | ------------------------------------------------------------------- |
| Process        | `C:\Windows\System32\VaultCmd.exe`                                  |
| Command line   | `"C:\Windows\system32\VaultCmd.exe" /list`                          |
| Parent process | PowerShell                                                          |
| User           | `TARGETMACHINE\a4803`                                               |
| Event ID       | Sysmon Event ID 1                                                   |
| Record number  | `80057`, if confirmed against the saved event                       |
| Timestamp      | `2026-10-12 18:31:44.515 UTC`, if confirmed against the saved event |

The `cmdkey.exe /list` test also produced endpoint output. Record its corresponding Splunk event details only after verifying them in the search results.

## 4. Investigation and Analysis

Review the executable, command line, parent process, and user context.

The `/list` argument indicates enumeration of credential-related information. This can be relevant to an investigation into potential credential-access activity.

However, listing stored credential targets is not the same as extracting their secrets. No password extraction or credential compromise should be claimed without separate supporting evidence.

## 5. MITRE ATT&CK Mapping

**Candidate technique:** T1555.004 — Credentials from Password Stores: Windows Credential Manager.

**Official reference:** https://attack.mitre.org/techniques/T1555/004/

This is a candidate mapping for the observed credential-store-related activity. The event does not by itself prove that an adversary obtained credentials.

## 6. Impact Assessment

* Credential-store enumeration: Observed for `VaultCmd.exe /list`.
* Password extraction: Not demonstrated.
* Credential compromise: Not demonstrated.
* Unauthorized account use: Not demonstrated.
* Data exfiltration: Not demonstrated.

## 7. Response and Containment

No credential reset or endpoint isolation is warranted solely from this benign enumeration test.

If independent evidence indicates that credentials were exposed or misused, follow the organization's credential-protection and incident-response procedures.

## 8. False-Positive Considerations

Credential-related utilities may be invoked by administrators or users for legitimate troubleshooting and inspection.

## 9. Limitations and Evidence Gaps

* Process telemetry identifies the executed command but may not reveal all subsequent actions.
* Enumeration does not prove that secrets were accessed.
* The observed activity does not establish malicious intent.
* The evidence does not demonstrate credential extraction or compromise.

## 10. Recommendations

* Preserve the relevant process-creation events.
* Redact personal email addresses and credential target names from public screenshots.
* Correlate suspicious credential-related activity with authentication events and other endpoint telemetry.
* Avoid describing enumeration as successful credential theft.
* Validate the focused detection against representative benign activity.

## 11. Final Disposition

**Disposition:** Credential-access monitoring exercise; credential extraction or compromise not demonstrated.

**Validation status:** VaultCmd enumeration telemetry observed; focused detection validation requires separate evidence.

**Analyst Notes:** A Sysmon Event ID 1 record was observed for VaultCmd.exe with the command line "C:\Windows\system32\VaultCmd.exe" /list. This supports the observation of credential-vault enumeration activity. The evidence does not demonstrate password extraction, credential compromise, or unauthorized account use. Personal email addresses and credential target names must be redacted from public screenshots.


