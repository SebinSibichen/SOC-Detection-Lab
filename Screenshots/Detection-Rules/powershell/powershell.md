# PowerShell Detection - Screenshots

This folder contains screenshots demonstrating the detection and investigation of PowerShell execution using **Sysmon Event ID 1 (Process Creation)** and **Splunk**.

The screenshots provide evidence that PowerShell execution generated Sysmon telemetry, that the telemetry was forwarded to Splunk, and that the activity could be detected and investigated using SPL.

---

## 01 - PowerShell Execution

**Filename:**

```text
01-PowerShell-Execution.png
```

### Description

Shows the PowerShell command being manually executed on the Windows test machine.

### Purpose

Provides evidence that PowerShell activity was intentionally generated for the detection test.

---

## 02 - Splunk PowerShell Query

**Filename:**

```text
02-Splunk-PowerShell-Query.png
```

### Description

Shows the SPL query used to identify PowerShell process-creation events.

### Detection Query

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

### Purpose

Demonstrates the search query used by the SOC analyst to detect PowerShell execution.

---

## 03 - PowerShell Detection Results

**Filename:**

```text
03-PowerShell-Detection-Results.png
```

### Description

Shows the PowerShell events returned by Splunk after running the detection query.

### Purpose

Provides evidence that Sysmon successfully recorded the PowerShell process creation and that the event was searchable in Splunk.

### Relevant Fields

* `_time`
* `ComputerName`
* `User`
* `Image`
* `ParentImage`
* `CommandLine`

---

## 04 - Expanded PowerShell Event

**Filename:**

```text
04-Expanded-PowerShell-Event.png
```

### Description

Shows an individual PowerShell process-creation event expanded in Splunk.

### Purpose

Demonstrates the detailed telemetry available to a SOC analyst during investigation.

The analyst can use the event to determine:

* Which computer executed PowerShell
* Which user executed it
* When it was executed
* Which parent process launched PowerShell
* What command was executed

---

# Detection Flow

```text
PowerShell Execution
        ↓
Sysmon Event ID 1
        ↓
Windows Event Log
        ↓
Splunk Universal Forwarder
        ↓
Splunk Enterprise
        ↓
SPL Detection Query
        ↓
PowerShell Detection
        ↓
Event Investigation
```

---

# MITRE ATT&CK Mapping

**Technique:** T1059.001 - Command and Scripting Interpreter: PowerShell

**Tactic:** Execution

---

# Evidence Summary

| Screenshot                            | Evidence                                |
| ------------------------------------- | --------------------------------------- |
| `01-PowerShell-Execution.png`         | PowerShell execution was generated      |
| `02-Splunk-PowerShell-Query.png`      | SPL detection query                     |
| `03-PowerShell-Detection-Results.png` | PowerShell execution detected in Splunk |
| `04-Expanded-PowerShell-Event.png`    | Detailed event investigation            |

These four screenshots provide sufficient evidence that PowerShell execution can be **generated, collected, detected, and investigated** using Sysmon and Splunk.
