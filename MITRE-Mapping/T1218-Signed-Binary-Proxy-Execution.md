# MITRE ATT&CK Mapping — Detection Rule 11

## Overview

Living Off The Land Binaries (LOLBins) are legitimate system utilities that may be abused to perform actions such as transferring files, executing scripts, or loading components.

The appropriate MITRE ATT&CK mapping depends on the actual behavior observed. A binary name alone does not establish a specific technique.

## Candidate Techniques

| Technique                               | ID        | When it may apply                                                        |
| --------------------------------------- | --------- | ------------------------------------------------------------------------ |
| System Binary Proxy Execution: Rundll32 | T1218.011 | Rundll32 is used to proxy execution of a malicious payload or component. |
| System Binary Proxy Execution: Regsvr32 | T1218.010 | Regsvr32 is abused to execute a malicious component or scriptlet.        |
| System Binary Proxy Execution: Mshta    | T1218.005 | Mshta is used to execute malicious HTA or script content.                |
| Ingress Tool Transfer                   | T1105     | Evidence shows a tool or file being transferred into the environment.    |
| Deobfuscate/Decode Files or Information | T1140     | Evidence shows encoded content being decoded or deobfuscated.            |

These are candidate mappings for future validated detections, not confirmed mappings for the current benign test.

## Observed Lab Activity

The confirmed event involved:

* `certutil.exe`
* Command line: `certutil.exe -?`
* Parent: PowerShell
* Sysmon Event ID: 1

The command requested help output. It did not demonstrate proxy execution, file transfer, or decoding.

## Mapping Decision

**Confirmed technique for the observed event:** None assigned.

The event establishes process execution only. Technique mapping should be assigned when the observed behavior and supporting evidence justify it.

## Detection Improvements

* Retain process image and command-line telemetry.
* Examine parent-child process relationships.
* Correlate suspicious command lines with network and file activity.
* Document the evidence supporting each technique assignment.
