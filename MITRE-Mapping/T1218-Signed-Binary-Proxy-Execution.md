# MITRE ATT&CK Mapping — Living-Off-The-Land Binaries

## Detection Overview

This detection investigates the use of legitimate Windows utilities that can be abused for execution, proxy execution, file handling, or other adversary behaviors.

Examples considered in this lab include `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `regsvr32.exe`, and `rundll32.exe`.

## ATT&CK Mapping

| Field                      | Details                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| Official ATT&CK Identifier | Behavior-specific; no single technique assigned to all LOLBins                                   |
| Official Technique Name    | Depends on the binary's observed use                                                             |
| Supporting Event           | Sysmon Event ID 1 — Process Create                                                               |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, `User`, `UtcTime`                                         |
| Candidate Technique        | T1218.005 — System Binary Proxy Execution: Mshta                                                 |
| Candidate Technique        | T1218.010 — System Binary Proxy Execution: Regsvr32                                              |
| Candidate Technique        | T1218.011 — System Binary Proxy Execution: Rundll32                                              |
| Candidate Technique        | T1140 — Deobfuscate/Decode Files or Information, if decoding behavior is demonstrated            |
| Candidate Technique        | T1197 — BITS Jobs, if BITS-job abuse is demonstrated                                             |
| Mapping Confidence         | Conditional on command-line arguments and resulting behavior                                     |
| Validation Status          | Broad hunting query validated; focused suspicious-behavior detection requires further validation |

## Mapping Rationale

Legitimate Windows binaries may be abused by adversaries to execute content or perform actions without introducing a conventional standalone executable.

Sysmon Event ID 1 provides process and command-line context that can support investigation. The exact technique depends on what the utility actually does.

## What the Evidence Does Not Demonstrate

* That executing a Windows utility is inherently malicious.
* That proxy execution occurred merely because a LOLBin launched.
* That a file was decoded, downloaded, or executed.
* That BITS jobs were abused.
* That defense evasion occurred.
* That command-and-control or data exfiltration occurred.

## Validation Notes

The observed `certutil.exe -?` command demonstrates process-creation visibility for the utility. It does not demonstrate malicious decoding or another suspicious LOLBin technique.

Use command-line evidence and corroborating events to assign a specific technique. Do not map every LOLBin event to every candidate technique.

## Official References

https://attack.mitre.org/techniques/T1218/005/

https://attack.mitre.org/techniques/T1218/010/

https://attack.mitre.org/techniques/T1218/011/

https://attack.mitre.org/techniques/T1140/

https://attack.mitre.org/techniques/T1197/
