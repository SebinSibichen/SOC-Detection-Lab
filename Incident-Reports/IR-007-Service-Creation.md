# SOC Incident Report — IR-007: Windows Service Creation

## 1. Executive Summary

**Incident ID:** SOC-IR-007
**Category:** Service Creation / Potential Persistence
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Controlled lab exercise
**Severity:** Informational — Benign test activity
**Disposition:** Service-creation monitoring and validation

This exercise evaluates the visibility of Windows service-creation activity.

A controlled lab service named `SOC_Lab_Service` was used to generate process-creation telemetry associated with a service-creation command.

The creation of a service is not inherently malicious. The purpose of the exercise is to verify telemetry collection and evaluate the supporting detection logic.

## 2. Scope and Environment

| Attribute     | Details           |
| ------------- | ----------------- |
| Endpoint      | `TargetMachine`   |
| SIEM          | Splunk Enterprise |
| Index         | `main`            |
| Primary event | Sysmon Event ID 1 |
| Test service  | `SOC_Lab_Service` |

## 3. Detection and Evidence

**Observed activity:** Controlled service-creation command.

Relevant evidence includes:

* `sc.exe` process execution
* `CommandLine`
* `ParentImage`
* `User`
* `UtcTime`
* Service name and binary path
* Resulting service configuration, if collected

**Observed timestamp:** [Insert verified timestamp]
**Event record number:** [Insert verified record number]
**Service name:** `SOC_Lab_Service`

The report should reference the actual Splunk event and corresponding screenshot.

## 4. Investigation and Analysis

Review the service-creation command and determine whether the service was successfully registered.

Inspect the configured service name, binary path, start type, and execution account where available.

For this exercise, the service name identifies a controlled lab test. Do not classify the test as adversary persistence.

## 5. MITRE ATT&CK Mapping

**Technique:** T1543.003 — Create or Modify System Process: Windows Service.

**Official reference:** https://attack.mitre.org/techniques/T1543/003/

The technique is relevant to the service-creation behavior. The observed benign test does not demonstrate malicious use of that technique.

## 6. Impact Assessment

* Malicious service creation: Not established.
* Privilege escalation: Not established.
* Unauthorized persistence: Not established.
* Endpoint compromise: Not established.

## 7. Response and Cleanup

Remove the controlled test service after collecting the required evidence.

Verify its removal and document the cleanup result. Avoid deleting unrelated services.

## 8. False-Positive Considerations

Software installation, system administration, and legitimate application deployment commonly create or modify Windows services.

## 9. Limitations and Evidence Gaps

A process-creation event does not alone prove that a service was successfully registered, started, or used for persistence.

## 10. Recommendations

* Correlate process creation with service-installation events or service configuration.
* Include service name and binary path in investigations.
* Document both test execution and cleanup.
* Test detection logic against legitimate service creation.

## 11. Final Disposition

**Disposition:** Controlled service-creation test; no malicious incident established.

**Validation status:** Process telemetry observed; record the actual focused detection results separately.

**Analyst Notes:** A controlled service-creation exercise involving SOC_Lab_Service was used to generate process-creation telemetry. The associated sc.exe command provides evidence of the attempted service-creation operation. Service registration and cleanup should be verified separately. The controlled test does not establish malicious persistence or privilege escalation.


