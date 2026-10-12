# MITRE ATT&CK Mapping — Remote Desktop

## Detection Overview

This detection investigates Remote Desktop Protocol (RDP) logon activity on the Windows endpoint.

## ATT&CK Mapping

| Field                      | Details                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1021.001 — Conditional                                                                      |
| Official Technique Name    | Remote Services: Remote Desktop Protocol                                                     |
| Tactic                     | Lateral Movement                                                                             |
| Supporting Event           | Windows Security Event ID 4624 — Successful logon                                            |
| Supporting Fields          | `TargetUserName`, `LogonType`, `IpAddress`, `WorkstationName`, `TargetDomainName`, timestamp |
| Key Indicator              | Logon Type 10 supports a Remote Interactive logon                                            |
| Mapping Confidence         | Conditional; depends on the context of the remote session                                    |
| Validation Status          | RDP-related logon telemetry observed; assess authorization and the focused detection         |

## Mapping Rationale

RDP is a remote access mechanism that can be abused for lateral movement. Windows Security Event ID 4624 with Logon Type 10 can provide evidence of a successful Remote Interactive logon.

The event should be correlated with the source address, account, host, and surrounding activity to determine whether the session is relevant to a security investigation.

## What the Evidence Does Not Demonstrate

* That the logon was unauthorized.
* That the account was compromised.
* That lateral movement by an adversary occurred.
* That malicious commands were executed during the session.
* That the remote session resulted in compromise.

## Validation Notes

Confirm the logon type and inspect the account, source address, and destination host. Distinguish an authorized administrative session from activity that warrants escalation.

## Official Reference

https://attack.mitre.org/techniques/T1021/001/
