# SOC Incident Report — IR-006: Scheduled Task Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-006
**Category:** Scheduled Execution / Potential Persistence
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon and Windows Task Scheduler logs, where configured
**Status:** Detection validation exercise
**Severity:** Informational — Pending task analysis
**Disposition:** Scheduled-task investigation

This exercise investigates scheduled-task-related activity on Windows.

Scheduled tasks are commonly used for maintenance and automation but can also be abused to execute programs or maintain persistence.

## 2. Scope and Environment

| Attribute            | Details                                         |
| -------------------- | ----------------------------------------------- |
| Endpoint             | `TargetMachine`                                 |
| SIEM index           | `main`                                          |
| Primary telemetry    | Sysmon Event ID 1                               |
| Additional telemetry | Task Scheduler operational events, if collected |

## 3. Detection and Evidence

Relevant fields include:

* `Image`
* `CommandLine`
* `ParentImage`
* `User`
* `UtcTime`
* Task name and action, when available

**Observed timestamp:** [Insert verified timestamp]
**Task name:** [Insert verified name]
**Task action:** [Insert verified action]
**Associated process:** [Insert verified process]

## 4. Investigation and Analysis

Review task-creation or modification commands and determine whether the task was successfully registered.

Inspect the task's action, trigger, execution account, and configured executable. Where available, correlate process telemetry with Task Scheduler events and task configuration.

## 5. MITRE ATT&CK Mapping

**Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task.

**Official reference:** https://attack.mitre.org/techniques/T1053/005/

## 6. Impact Assessment

* Task creation: [Confirmed / Not confirmed]
* Task execution: [Confirmed / Not confirmed]
* Malicious purpose: Not established without supporting evidence.
* Persistence: Requires behavior-specific confirmation.

## 7. Response and Containment

If a task is confirmed malicious, preserve its configuration and related evidence before disabling or removing it in accordance with the response procedure.

## 8. False-Positive Considerations

Legitimate applications, update services, and system maintenance frequently create scheduled tasks.

## 9. Limitations and Evidence Gaps

A process command that attempts to create a task does not necessarily prove that the task was registered or executed.

## 10. Recommendations

* Correlate task-management commands with Task Scheduler events.
* Record task actions, triggers, and execution accounts.
* Validate task creation and execution separately.
* Preserve evidence before removing suspicious tasks.

## 11. Final Disposition

**Disposition:** Scheduled-task monitoring exercise; malicious persistence not established.

**Validation status:** [Telemetry observed / Detection validated / Needs further validation]

**Analyst Notes:** Scheduled-task activity should be investigated using the task-management command line and, where available, Task Scheduler events and task configuration. Task creation, successful execution, and malicious intent should be assessed separately. The presence of a task-management command alone does not confirm persistence.

