# Detection Rule 11 — Living Off The Land Binaries (LOLBins)

## Rule Overview

**Rule ID:** DET-011
**Severity:** Medium — initial hunting classification
**Data Source:** Sysmon Process Creation
**Event ID:** 1
**Index:** `main`
**Status:** Hunting query validated; suspicious-behavior detection pending validation.

## Objective

Identify executions of selected legitimate Windows utilities that may be abused to transfer files, execute scripts, or load components.

## Monitored Binaries

* certutil.exe
* bitsadmin.exe
* mshta.exe
* regsvr32.exe
* rundll32.exe

## Detection Logic

The initial hunting query searches for process-creation events involving the selected binaries.

A second-stage query looks for command-line indicators such as:

* `certutil.exe`: `urlcache`, `decode`, HTTP or HTTPS references.
* `bitsadmin.exe`: `/transfer` or `/download`.
* `mshta.exe`: remote URL references or `javascript:`.
* `regsvr32.exe`: remote URL references or `scrobj.dll`.
* `rundll32.exe`: selected script-like or remote URL arguments.

These patterns are indicators for investigation, not proof of malicious activity.

## Analyst Investigation

When a match occurs:

1. Identify the user and computer.
2. Review the full command line.
3. Inspect the parent process and parent command line.
4. Check the event timestamp and surrounding process events.
5. Determine whether the command is consistent with an approved administrative task.
6. Correlate with network, file, and endpoint telemetry where available.
7. Record findings and document the disposition.

## False Positives

Legitimate system administration, software installation, troubleshooting, and application maintenance may use these utilities.

A binary match alone should not automatically generate a confirmed incident.

## Validation

The lab successfully captured:

`C:\Windows\System32\certutil.exe`

Command line:

`"C:\Windows\system32\certutil.exe" -?`

Parent process:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This is a benign help request and does not trigger the focused suspicious-command-line query.

## Success Criteria

* Sysmon Event ID 1 is collected.
* Process image and command-line fields are available.
* The hunting query identifies the test event.
* Focused detection logic can be tested separately with appropriate controlled test cases.

**Current result:** Process telemetry and the initial LOLBin hunt are validated. Suspicious-activity detection is not yet fully validated.
