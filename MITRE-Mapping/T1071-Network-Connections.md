# MITRE ATT&CK Mapping — Network Connections

## Detection Overview

This detection investigates endpoint network-connection telemetry to identify potentially suspicious communication and provide context for security investigations.

## ATT&CK Mapping

| Field                      | Details                                                                     |
| -------------------------- | --------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1049 — Conditional                                                         |
| Official Technique Name    | System Network Connections Discovery                                        |
| Tactic                     | Discovery                                                                   |
| Supporting Event           | Sysmon Event ID 3 — Network connection, if enabled                          |
| Supporting Fields          | `Image`, `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol`, `User` |
| Mapping Confidence         | Conditional; depends on whether connection discovery was observed           |
| Validation Status          | Confirm the event source and detection results                              |

## Mapping Rationale

T1049 describes discovery of system network connections. Sysmon Event ID 3 can provide useful endpoint network-connection context, including the associated process and destination.

A connection event is not automatically evidence of network discovery. The observed behavior must show that the system or process was discovering network connections rather than simply communicating with another host.

## What the Evidence Does Not Demonstrate

* That a network connection was malicious.
* That command-and-control communication occurred.
* That data was exfiltrated.
* That an attacker performed network discovery.
* That the remote destination was compromised.

## Validation Notes

Verify that Sysmon network-connection logging is enabled and that the expected events reach Splunk. Review the process, destination, port, protocol, and surrounding activity before assigning a specific technique.

## Official Reference

https://attack.mitre.org/techniques/T1049/
