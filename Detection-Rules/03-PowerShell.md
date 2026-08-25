# Detection Rule 03 - PowerShell Execution

## Overview

This detection rule monitors Windows PowerShell execution using **Sysmon Event ID 1 (Process Creation)**.

PowerShell is a legitimate Windows administration tool, but it is also commonly abused by attackers for command execution, reconnaissance, downloading files, and other post-exploitation activities.

This rule provides visibility into PowerShell processes and captures important process information for SOC investigation.

---

## Event Source

**Sysmon Event ID:** `1 - Process Creation`

**Log Source:**

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Index:**

```text
main
```

---

## Detection Objective

Detect the execution of:

```text
powershell.exe
```

and capture the following information:

* Execution time
* Computer name
* User
* PowerShell executable
* Parent process
* Command line

This allows an analyst to determine **who executed PowerShell, when it was executed, how it was launched, and what command was executed**.

---

## SPL Detection Query

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

---

## Alternative Query

The following query can be used when the Sysmon source needs to be explicitly specified:

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

---

## Fields Investigated

| Field          | Description                              |
| -------------- | ---------------------------------------- |
| `_time`        | Time when PowerShell was executed        |
| `ComputerName` | Windows system where PowerShell executed |
| `User`         | Account that launched the process        |
| `Image`        | PowerShell executable path               |
| `ParentImage`  | Process that launched PowerShell         |
| `CommandLine`  | Complete PowerShell command line         |

---

## Example Detection

A typical event may contain:

```text
ComputerName: TargetMachine
User: TARGETMACHINE\a4803
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage: C:\Program Files\WindowsApps\...\WindowsTerminal.exe
```

The `CommandLine` field provides additional information about what PowerShell was instructed to execute.

---

## Attack Simulation / Testing

A controlled PowerShell command was manually executed on the Windows test machine to generate a process-creation event.

Example:

```powershell
powershell.exe -Command "Write-Host 'SOC_POWERSHELL_TEST'"
```

After execution, Splunk was queried for the corresponding Sysmon Event ID 1 event.

The resulting event was verified using:

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

---

## Suspicious PowerShell Indicators

PowerShell execution by itself does **not** indicate malicious activity.

For additional detection, the command line can be searched for commonly abused PowerShell indicators:

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| search CommandLine="*Invoke-WebRequest*"
    OR CommandLine="*-enc*"
    OR CommandLine="*EncodedCommand*"
    OR CommandLine="*IEX*"
    OR CommandLine="*Invoke-Expression*"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

These indicators should be treated as **investigation triggers**, not automatic proof of compromise.

---

## SOC Investigation

When PowerShell activity is detected, an analyst should investigate:

1. **Who** executed PowerShell?
2. **When** was it executed?
3. **Which computer** executed it?
4. **What command** was executed?
5. **Which parent process** launched PowerShell?
6. Was the execution expected or authorized?
7. Does the command line contain suspicious parameters?
8. Are there related network connections or process-creation events?
9. Are there other suspicious events around the same timestamp?

---

## MITRE ATT&CK Mapping

### T1059.001 - PowerShell

**Tactic:** Execution

**Technique:** Command and Scripting Interpreter: PowerShell

PowerShell can be abused by attackers to execute commands and scripts on Windows systems.

This detection provides visibility into PowerShell process execution and can support investigation of potential PowerShell-based attacks.

---

## Evidence

Screenshots associated with this detection are stored in:

```text
Detection-Rules/PowerShell/Screenshots/
```

Recommended evidence:

```text
01-Splunk-PowerShell-Detection.png
02-Splunk-PowerShell-Query.png
03-Splunk-Suspicious-PowerShell-Detection.png
04-Expanded-PowerShell-Event.png
```

---

## Result

The detection successfully identified PowerShell process creation using Sysmon Event ID 1 and provided useful process information including the executing user, parent process, executable path, and command line.

This demonstrates that the Windows telemetry pipeline is functioning correctly and that PowerShell activity can be monitored and investigated through Splunk.
