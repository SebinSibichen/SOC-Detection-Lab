# SOC Incident Report — IR-010: Suspicious Parent-Child Process Relationships

## 1. Executive Summary

**Incident ID:** SOC-IR-010
**Category:** Endpoint Behavior Analysis
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Detection-validation exercise
**Severity:** Informational — Focused detection requires validation
**Disposition:** Process-relationship investigation

This exercise investigates parent-child process relationships that may be unusual or inconsistent with expected application behavior.

The objective is to establish visibility into process execution chains and identify relationships that merit further investigation.

An unusual process relationship is not independently evidence of malicious activity.

## 2. Scope and Environment

| Attribute     | Details                                       |
| ------------- | --------------------------------------------- |
| Endpoint      | `TargetMachine`                               |
| SIEM index    | `main`                                        |
| Primary event | Sysmon Event ID 1                             |
| Key fields    | `ParentImage`, `Image`, `CommandLine`, `User` |

## 3. Detection and Evidence

Relevant fields:

* `ParentImage`
* `Image`
* `CommandLine`
* `User`
* `UtcTime`
* `ProcessId`
* `ParentProcessId`

**Observed timestamp:** [Insert verified timestamp]
**Parent process:** [Insert verified value]
**Child process:** [Insert verified value]
**Command line:** [Insert verified value]

If no matching event was found, document the search result and investigation steps instead of inventing event details.

## 4. Investigation and Analysis

Inspect the parent process, child process, command line, user context, and execution time.

Determine whether the relationship is expected for the software or activity being tested. Correlate with file, network, script, or authentication events when relevant.

The focused query should be considered unvalidated if it has not returned representative matching events.

## 5. MITRE ATT&CK Mapping

**Technique:** No single ATT&CK technique assigned from the process relationship alone.

A technique-specific mapping requires evidence of the behavior performed by the process.

## 6. Impact Assessment

* Malicious execution: Not established.
* Exploitation: Not established.
* Unauthorized access: Not established.
* Endpoint compromise: Not established.

## 7. Response and Containment

No containment is warranted solely because a parent-child relationship is unusual.

If additional evidence supports malicious activity, preserve the relevant process events and investigate the execution chain.

## 8. False-Positive Considerations

Installers, administrative tools, software updaters, scripts, and legitimate applications can create process relationships that appear unusual.

## 9. Limitations and Evidence Gaps

A query returning zero events does not prove that the behavior is absent. Possible causes include an unsuitable test, incorrect field names, restrictive filters, missing telemetry, or an incorrect time range.

## 10. Recommendations

* Validate the search against a controlled test.
* Review actual field names and event data.
* Test representative benign process relationships.
* Document expected matches and non-matches.

## 11. Final Disposition

**Disposition:** Detection-development exercise; malicious activity not established.

**Validation status:** Needs further validation if the focused detection has not returned a representative event.

**Analyst Notes:** The detection is intended to identify potentially unusual parent-child process relationships using Sysmon Event ID 1. The parent image, child image, command line, and execution context should be examined. The focused query requires representative test results before detection effectiveness can be confirmed.


