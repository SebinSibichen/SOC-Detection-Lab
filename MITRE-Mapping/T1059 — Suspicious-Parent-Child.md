# MITRE ATT&CK Mapping — Suspicious Parent-Child Processes

## Detection Overview

This detection investigates unusual relationships between parent and child processes. Its purpose is to identify process execution patterns that may warrant further analysis.

## ATT&CK Mapping

| Field                      | Details                                                                                  |
| -------------------------- | ---------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | No single technique assigned without behavior-specific evidence                          |
| Official Technique Name    | Depends on the observed behavior                                                         |
| Tactic                     | Depends on the observed behavior                                                         |
| Supporting Event           | Sysmon Event ID 1 — Process Create                                                       |
| Supporting Fields          | `ParentImage`, `Image`, `CommandLine`, `User`, `UtcTime`, `ProcessId`, `ParentProcessId` |
| Mapping Confidence         | Requires investigation of the specific process relationship                              |
| Validation Status          | Needs further validation if the focused query has not returned representative events     |

## Mapping Rationale

Unexpected parent-child relationships can help identify suspicious execution chains. For example, an Office application spawning a command interpreter may warrant investigation.

However, the process relationship alone is not enough to assign a specific ATT&CK technique. The mapping should reflect the behavior demonstrated by the child process and its command line.

## What the Evidence Does Not Demonstrate

* That the parent process was compromised.
* That the child process was malicious.
* That exploitation occurred.
* That a specific ATT&CK technique was successfully executed.
* That an unusual process relationship is necessarily malicious.

## Validation Notes

Use controlled tests to confirm that the intended process relationship is logged and searchable. Test both matching and benign process relationships.

If the focused SPL query returns zero events, investigate the time range, field names, process availability, and query conditions before claiming detection success.

## Mapping Policy

Assign a specific ATT&CK technique only after the observed process behavior supports it. Record the technique, evidence, and limitations in this file when the mapping is established.
