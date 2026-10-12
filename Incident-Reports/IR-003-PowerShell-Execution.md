# SOC Incident Report — IR-003: PowerShell Execution Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-003
**Category:** Script Execution / Endpoint Monitoring
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Monitoring exercise
**Severity:** Informational — Pending command analysis
**Disposition:** PowerShell execution investigation

This exercise evaluates detection and investigation of PowerShell execution.

PowerShell is a legitimate Windows administration tool that may also be abused by adversaries. The purpose of the detection is to identify execution context and determine whether commands warrant additional investigation.

## 2. Scope and Environment

| Attribute            | Details                                    |
| -------------------- | ------------------------------------------ |
| Endpoint             | `TargetMachine`                            |
| SIEM index           | `main`                                     |
| Primary event        | Sysmon Event ID 1                          |
| Additional telemetry | PowerShell operational logs, if configured |

## 3. Detection and Evidence

Relevant fields:

* `Image`
* `CommandLine`
* `ParentImage`
* `User`
* `UtcTime`
* `ProcessId`

**Observed timestamp:** [Insert verified timestamp]
**Observed command line:** [Insert actual command line]
**Parent process:** [Insert verified value]
**User:** [Insert verified value]

## 4. Investigation and Analysis

Inspect the PowerShell command line, parent process, user context, and execution time.

Where available, correlate the process with PowerShell Script Block Logging, including Event ID 4104. Review related file creation, network activity, and child processes if the behavior appears suspicious.

## 5. MITRE ATT&CK Mapping

**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell.

**Official reference:** https://attack.mitre.org/techniques/T1059/001/

## 6. Impact Assessment

PowerShell execution alone does not establish malicious activity.

* Unauthorized script execution: Not established without supporting evidence.
* Payload execution: Not established.
* Credential access: Not established.
* Endpoint compromise: Not established.

## 7. Response and Containment

No containment is warranted solely because PowerShell ran.

For suspicious commands, preserve the relevant events and investigate the command's purpose and resulting activity.

## 8. False-Positive Considerations

Legitimate causes include system administration, configuration management, software installation, and automated maintenance.

## 9. Limitations and Evidence Gaps

Process-creation telemetry may not reveal every command executed inside an existing PowerShell process. Additional PowerShell logging may be required.

## 10. Recommendations

* Monitor PowerShell command lines.
* Enable appropriate PowerShell logging where feasible.
* Correlate script execution with related endpoint events.
* Test detection logic against benign administrative activity.

## 11. Final Disposition

**Disposition:** PowerShell monitoring exercise; malicious execution not established.

**Validation status:** [Telemetry observed / Detection validated / Needs further validation]

**Analyst Notes:** PowerShell process execution can be investigated using Sysmon Event ID 1 and the associated command line and parent process. Additional PowerShell logging, such as Script Block Logging, may provide further context. PowerShell execution alone does not establish malicious activity.


