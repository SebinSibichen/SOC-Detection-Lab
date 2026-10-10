# Screenshots — Suspicious Parent-Child Process Detection

This folder contains evidence for Module #10 of the SOC Detection Lab. Screenshots document Sysmon process-creation telemetry, Splunk searches, and the investigation of parent-child process relationships.

## Screenshot List

| Filename                                | Description                                                              |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `01-Sysmon-Process-Creation-Events.png` | Splunk search showing Sysmon Event ID 1 events.                          |
| `02-Parent-Child-Fields.png`            | Results showing the `ParentImage` and `Image` fields.                    |
| `03-Observed-Process-Relationships.png` | Summary of observed parent-child process pairs.                          |
| `04-PowerShell-CMD-Test.png`            | PowerShell window showing the controlled `cmd.exe` test command.         |
| `05-Splunk-CMD-Process-Event.png`       | Splunk result showing the CMD process-creation event and parent process. |
| `06-Office-to-Script-Detection.png`     | Results from the Office-to-script detection query.                       |
| `07-Expanded-Process-Event.png`         | Expanded Sysmon event showing process details and command line.          |

## Evidence Notes

* Capture actual query results; do not fabricate or alter event evidence.
* If the Office-to-script query returns zero events, retain that result as a validation screenshot and describe it accurately.
* The controlled PowerShell-to-CMD test validates process relationship monitoring but is not itself proof of malicious activity.
* Redact passwords, tokens, and other sensitive information before publishing screenshots.

## Outcome

The lab has confirmed Sysmon process-creation ingestion and the availability of parent and child process fields. Detection validation remains in progress until the relevant test query returns the expected event.
