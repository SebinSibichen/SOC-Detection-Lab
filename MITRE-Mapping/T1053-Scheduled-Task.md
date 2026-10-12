# MITRE ATT&CK Mapping — Scheduled Tasks

## Detection Overview

This detection investigates scheduled-task-related activity that may be used to automate execution or maintain persistence on Windows.

## ATT&CK Mapping

| Field                      | Details                                                                                   |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1053.005                                                                                 |
| Official Technique Name    | Scheduled Task/Job: Scheduled Task                                                        |
| Tactic                     | Execution; Persistence; Privilege Escalation                                              |
| Supporting Events          | Sysmon Event ID 1; relevant Task Scheduler events when collected                          |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, task name, task action, trigger, `User`, `UtcTime` |
| Mapping Confidence         | Appropriate when scheduled-task behavior is observed                                      |
| Validation Status          | Confirm creation or modification and test the focused detection                           |

## Mapping Rationale

Windows scheduled tasks can execute programs or scripts in response to defined triggers.

Process telemetry involving `schtasks.exe` can help identify task-management commands. Task Scheduler events and task configuration provide stronger evidence of actual task creation, modification, or execution.

## What the Evidence Does Not Demonstrate

* That a task was successfully created.
* That a scheduled task executed.
* That the task was malicious.
* That an attacker established persistence.
* That privilege escalation occurred.

## Validation Notes

Where possible, correlate process-creation events with Task Scheduler operational events and the resulting task configuration. Distinguish commands that attempt to create tasks from evidence confirming that a task exists.

## Official Reference

https://attack.mitre.org/techniques/T1053/005/
