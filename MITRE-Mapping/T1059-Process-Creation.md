# MITRE ATT&CK Mapping — Process Creation

## Detection Overview

This detection monitors Windows process creation events to establish visibility into executable launches, command-line arguments, parent-child relationships, and user context.

## ATT&CK Mapping

| Field                      | Details                                                               |
| -------------------------- | --------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1059.001 — Conditional                                               |
| Official Technique Name    | Command and Scripting Interpreter: PowerShell                         |
| Tactic                     | Execution                                                             |
| Supporting Event           | Sysmon Event ID 1 — Process Create                                    |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, `User`, `UtcTime`, `ProcessId` |
| Mapping Confidence         | Conditional; depends on the observed process                          |
| Validation Status          | Review the specific detection evidence                                |

## Mapping Rationale

Sysmon Event ID 1 records process creation. When the event shows PowerShell executing a command, the activity may support mapping to T1059.001.

Generic process creation alone does not establish PowerShell execution. The actual executable and observed behavior must support the mapping.

## What the Evidence Does Not Demonstrate

* That the process was malicious.
* That a suspicious command completed successfully.
* That an attacker gained control of the endpoint.
* That every process-creation event represents an ATT&CK technique.
* That the process resulted in compromise or data loss.

## Validation Notes

Confirm that the event is searchable in Splunk, inspect the raw event, and verify that the detection identifies the intended behavior without treating all process creation as suspicious.

## Official Reference

https://attack.mitre.org/techniques/T1059/001/
