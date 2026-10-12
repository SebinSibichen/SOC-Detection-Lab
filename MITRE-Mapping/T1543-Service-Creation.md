# MITRE ATT&CK Mapping — Windows Service Creation

## Detection Overview

This detection monitors Windows service-creation activity and investigates whether the activity may be associated with persistence or execution.

## ATT&CK Mapping

| Field                      | Details                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1543.003                                                                                   |
| Official Technique Name    | Create or Modify System Process: Windows Service                                            |
| Tactic                     | Persistence; Privilege Escalation                                                           |
| Supporting Events          | Sysmon Event ID 1; Security Event ID 4697 or relevant System service events, if available   |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, service name, service binary path, `User`, `UtcTime` |
| Mapping Confidence         | Supported when service creation or modification is observed                                 |
| Validation Status          | Controlled service-creation activity observed; assess the corresponding detection results   |

## Mapping Rationale

Windows services can be created or modified to run programs in the background. Adversaries may abuse this mechanism for persistence or privilege escalation.

In this lab, process-creation evidence involving `sc.exe` and a service-creation command can support investigation. Service configuration or a corresponding service-installation event provides additional confirmation.

## What the Evidence Does Not Demonstrate

* That the service is malicious.
* That an attacker established persistence.
* That privilege escalation occurred.
* That the service executed successfully.
* That the service remained installed after testing.

## Validation Notes

Correlate the command line with the resulting service configuration. Document whether the service was successfully created, what executable it referenced, and whether it was removed during cleanup.

## Official Reference

https://attack.mitre.org/techniques/T1543/003/
