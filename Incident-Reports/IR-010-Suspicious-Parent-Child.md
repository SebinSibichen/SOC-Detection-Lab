# SOC Incident Report 010 — Suspicious Parent-Child Process

## Incident Overview

* Incident ID: SOC-IR-010
* Detection: Suspicious Parent-Child Process
* Host: `TargetMachine`
* Data Source: Sysmon Event ID 1
* SIEM: Splunk Enterprise
* Severity: Medium if a suspicious relationship is confirmed; otherwise informational during testing
* Status: Lab validation in progress

## Alert Description

The detection searches for selected Office applications spawning command interpreters or scripting engines. Such behavior may occur during malicious document execution, but it can also result from authorized automation.

## Evidence

The lab's Splunk screenshot confirms that Sysmon process-creation events are ingested and that `ParentImage` and `Image` fields are available.

The initial Office-to-script detection returned zero events. Therefore, no matching Office-to-script activity has been confirmed by that query.

A controlled PowerShell-to-CMD test may be used to validate the process-relationship search independently.

## Investigation

1. Review the parent executable.
2. Review the child executable and command line.
3. Confirm the associated user and endpoint.
4. Establish whether the relationship is expected.
5. Correlate with authentication, PowerShell, and network telemetry.
6. Document the result and escalate if further evidence supports malicious activity.

## MITRE ATT&CK

Potentially relevant technique: T1059 — Command and Scripting Interpreter.

The specific sub-technique depends on the observed behavior. Do not assign a technique solely because a process relationship appears suspicious.

## Analyst Assessment

The presence of process-creation telemetry demonstrates that the endpoint can provide useful process relationship evidence. The original Office-to-script detection has not yet produced a matching event, so this report does not claim a confirmed malicious incident.

## Recommended Actions

* Validate the detection with an appropriate controlled test.
* Tune the rule against known legitimate automation.
* Preserve the relevant process event and command line.
* Escalate only when the evidence justifies further investigation.

## Final Status

Pending detection validation. Update this report when an actual matching event has been captured.
