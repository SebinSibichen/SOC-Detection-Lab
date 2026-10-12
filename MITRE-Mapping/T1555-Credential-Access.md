# MITRE ATT&CK Mapping — Credential Access

## Detection Overview

This detection investigates processes that enumerate Windows credential-related stores or targets.

The lab includes observations involving `VaultCmd.exe /list` and `cmdkey.exe /list`.

## ATT&CK Mapping

| Field                      | Details                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1555.004 — Candidate                                                                                            |
| Official Technique Name    | Credentials from Password Stores: Windows Credential Manager                                                     |
| Tactic                     | Credential Access                                                                                                |
| Supporting Event           | Sysmon Event ID 1 — Process Create                                                                               |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, `User`, `UtcTime`                                                         |
| Observed Activity          | `VaultCmd.exe /list`; `cmdkey.exe /list` was also tested                                                         |
| Mapping Confidence         | Candidate; enumeration is observed, but credential extraction is not demonstrated                                |
| Validation Status          | VaultCmd enumeration event observed; focused detection and credential-access behavior require further validation |

## Mapping Rationale

Windows Credential Manager stores credentials used by applications and Windows services. ATT&CK T1555.004 concerns adversary access to credentials from Windows Credential Manager.

Process-creation events showing credential-related enumeration commands provide useful evidence of activity involving these stores. However, enumeration alone does not establish that stored credentials were retrieved.

## What the Evidence Does Not Demonstrate

* That stored passwords were extracted.
* That any credential was compromised.
* That credentials were transmitted to another system.
* That the observed command was executed by an attacker.
* That the account was used for unauthorized access.
* That credential theft succeeded.

## Validation Notes

The lab observed a `VaultCmd.exe /list` process event. The command enumerates credential-vault information; this is not evidence of password extraction.

Retain the process event and relevant command-line details as evidence. Redact personal email addresses and credential target names from public screenshots.

## Official Reference

https://attack.mitre.org/techniques/T1555/004/
