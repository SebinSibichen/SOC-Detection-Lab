# SOC Incident Report — IR-011: Living-Off-The-Land Binary Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-011
**Category:** Endpoint Execution / LOLBin Monitoring
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Sysmon Operational Log
**Status:** Detection-development exercise
**Severity:** Informational — Behavior assessment required
**Disposition:** LOLBin hunting and detection validation

This exercise investigates the use of legitimate Windows utilities that can be abused for execution, file handling, or other adversary behaviors.

The lab includes visibility testing for binaries such as `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `regsvr32.exe`, and `rundll32.exe`.

The observed use of a legitimate utility does not automatically indicate malicious activity.

## 2. Scope and Environment

| Attribute       | Details                                       |
| --------------- | --------------------------------------------- |
| Endpoint        | `TargetMachine`                               |
| SIEM index      | `main`                                        |
| Primary event   | Sysmon Event ID 1                             |
| Relevant fields | `Image`, `CommandLine`, `ParentImage`, `User` |

## 3. Detection and Evidence

The broad hunting query identified a `certutil.exe` process event.

**Observed command:** `"C:\Windows\system32\certutil.exe" -?`

**Observed timestamp:** [Insert verified timestamp]
**Event record number:** [Insert verified record number]
**Parent process:** PowerShell, if confirmed by the recorded event
**User:** [Insert verified account]

The command was used to validate visibility into the utility. It should not be classified as malicious decoding or LOLBin abuse based on the available evidence.

## 4. Investigation and Analysis

Review the executable, command line, parent process, and resulting behavior.

Determine whether the utility was used for an expected administrative purpose or for behavior requiring further investigation.

A focused detection should distinguish suspicious usage from benign commands, including help or usage requests.

## 5. MITRE ATT&CK Mapping

Potential techniques depend on the behavior observed:

* T1218.005 — System Binary Proxy Execution: Mshta
* T1218.010 — System Binary Proxy Execution: Regsvr32
* T1218.011 — System Binary Proxy Execution: Rundll32
* T1140 — Deobfuscate/Decode Files or Information, if decoding is demonstrated
* T1197 — BITS Jobs, if relevant BITS-job abuse is demonstrated

Official references:

https://attack.mitre.org/techniques/T1218/005/

https://attack.mitre.org/techniques/T1218/010/

https://attack.mitre.org/techniques/T1218/011/

https://attack.mitre.org/techniques/T1140/

https://attack.mitre.org/techniques/T1197/

## 6. Impact Assessment

* Malicious LOLBin execution: Not established.
* File decoding: Not established by the `certutil.exe -?` event.
* Proxy execution: Not established.
* Command and control: Not established.
* Data exfiltration: Not established.

## 7. Response and Containment

Do not block or remove legitimate Windows utilities solely because their process events were recorded.

If the command line and resulting behavior support malicious activity, preserve the evidence and follow the appropriate response procedure.

## 8. False-Positive Considerations

Windows utilities are frequently used by administrators, installers, diagnostic tools, and legitimate software.

## 9. Limitations and Evidence Gaps

The broad hunting query established visibility into a utility's process execution. The focused suspicious-behavior detection still requires validation.

## 10. Recommendations

* Retain process and command-line context.
* Develop behavior-specific detection conditions.
* Test benign and suspicious examples.
* Assign ATT&CK techniques only when the observed behavior supports them.

## 11. Final Disposition

**Disposition:** LOLBin visibility and hunting exercise; malicious behavior not established.

**Validation status:** Broad hunting query validated; focused suspicious-behavior detection requires further validation.

**Analyst Notes:** The broad hunting query identified a certutil.exe process launched with the -? argument. This observation confirms process-creation visibility for the utility but does not demonstrate malicious decoding, proxy execution, or other LOLBin abuse. The focused suspicious-behavior detection requires further validation.


