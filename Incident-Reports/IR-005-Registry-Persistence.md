# SOC Incident Report — IR-005: Registry Persistence Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-005
**Category:** Persistence / Registry Modification
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Detection validation exercise
**Severity:** Informational — Pending registry analysis
**Disposition:** Registry modification investigation

This exercise investigates registry modifications that may be relevant to Windows persistence.

Registry changes are common during normal system operation. The investigation focuses on identifying relevant autostart locations and determining whether the observed changes could cause an application or script to execute automatically.

## 2. Scope and Environment

| Attribute          | Details                               |
| ------------------ | ------------------------------------- |
| Endpoint           | `TargetMachine`                       |
| SIEM index         | `main`                                |
| Relevant telemetry | Sysmon registry events, if configured |
| Candidate events   | Sysmon Event IDs 12, 13, and 14       |

## 3. Detection and Evidence

Relevant fields:

* `Image`
* `TargetObject`
* `Details`
* `User`
* `UtcTime`
* `EventCode`

**Observed timestamp:** [Insert verified timestamp]
**Registry path:** [Insert verified path]
**Value name:** [Insert verified value name]
**Value data:** [Insert verified value data]
**Associated process:** [Insert verified process]

## 4. Investigation and Analysis

Determine whether the changed registry location is associated with an autostart mechanism.

Inspect the value data, executable path, modifying process, user context, and any subsequent execution.

Do not classify an arbitrary registry change as persistence without evidence supporting that conclusion.

## 5. MITRE ATT&CK Mapping

**Candidate technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder.

**Official reference:** https://attack.mitre.org/techniques/T1547/001/

## 6. Impact Assessment

* Persistence established: Requires confirmation.
* Malicious registry modification: Not established without supporting evidence.
* Unauthorized execution: Not established.
* Endpoint compromise: Not established.

## 7. Response and Containment

Preserve the registry path, value data, process information, and relevant timestamps. Do not delete registry entries solely because they triggered a broad detection.

## 8. False-Positive Considerations

Software installation, application updates, and legitimate configuration changes can modify registry entries.

## 9. Limitations and Evidence Gaps

Registry-modification telemetry does not automatically prove that a value was used to execute a program or establish persistence.

## 10. Recommendations

* Verify the relevant Sysmon event configuration.
* Monitor high-value autostart locations.
* Correlate registry modifications with process execution.
* Document the exact registry location and resulting behavior.

## 11. Final Disposition

**Disposition:** Registry-monitoring exercise; persistence or compromise not confirmed.

**Validation status:** [Telemetry observed / Detection validated / Needs further validation]

**Analyst Notes:** Registry modifications should be evaluated using the affected registry path, value data, modifying process, and surrounding activity. A persistence-related technique should be assigned only when the evidence supports the relevant autostart mechanism. Registry modification alone does not establish malicious persistence.


