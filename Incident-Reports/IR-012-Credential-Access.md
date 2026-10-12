# SOC Incident Report — IR-012

## Incident Summary

| Field        | Details                                               |
| ------------ | ----------------------------------------------------- |
| Incident ID  | SOC-IR-012                                            |
| Title        | Windows Credential Store Enumeration                  |
| Host         | `TargetMachine`                                       |
| Category     | Credential Access                                     |
| Severity     | Medium — preliminary hunting classification           |
| Status       | Benign lab activity observed; no compromise confirmed |
| Data Source  | Sysmon Process Create                                 |
| Splunk Index | `main`                                                |

## Evidence

The supplied Splunk event contained:

* Event ID: `1`
* Record Number: `80057`
* Process: `C:\Windows\System32\VaultCmd.exe`
* Command line: `"C:\Windows\system32\VaultCmd.exe" /list`
* Parent process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* User: `TARGETMACHINE\a4803`
* Host: `TargetMachine`
* Event UTC time: `2026-10-12 18:31:44.515`

The PowerShell screenshot also showed `cmdkey /list` and `vaultcmd /list` being executed and showed two matching local Sysmon Process Create records.

## Investigation

The observed VaultCmd command enumerated available Windows Vaults.

The event was found in Splunk using the credential-access hunting query, demonstrating that the process-creation telemetry was available for investigation.

The supplied evidence does not demonstrate password extraction, credential misuse, or unauthorized access.

## Analyst Assessment

The commands were executed as part of an intentional lab simulation. The observed activity is consistent with the stated test objective.

The event should not be classified as confirmed credential theft solely because a credential-related utility executed.

## Recommended Follow-up

1. Preserve the relevant Sysmon and Splunk event evidence.
2. Review the command line, parent process, user, and host context.
3. Correlate with other telemetry if suspicious activity is suspected.
4. Escalate only if additional evidence supports unauthorized credential access.

## Final Disposition

**Lab validation successful. No confirmed security incident.**

The evidence demonstrates process telemetry collection and hunting-query functionality, not successful credential extraction.
