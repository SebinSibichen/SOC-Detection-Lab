# PowerShell Execution - Screenshots

This directory contains screenshots demonstrating the detection and investigation of PowerShell execution events using **Splunk** and **Sysmon Event ID 1**.

## Screenshot Evidence

### 01 - PowerShell Detection Query

**File:** `01-PowerShell-Detection-Query.png`

Shows the Splunk SPL query used to search for PowerShell process creation events.

The query filters for:

* Sysmon Event ID 1
* `powershell.exe`
* PowerShell command-line activity
* Host and user information

This screenshot demonstrates the initial detection query used by the SOC analyst.

---

### 02 - PowerShell Detection Results

**File:** `02-PowerShell-Detection-Results.png`

Shows the PowerShell process creation events returned by Splunk.

Important fields include:

* `_time`
* `ComputerName`
* `User`
* `Image`
* `ParentImage`
* `CommandLine`

This confirms that PowerShell execution activity was successfully collected by the Splunk Universal Forwarder and indexed in Splunk.

---

### 03 - Expanded PowerShell Event

**File:** `03-Expanded-PowerShell-Event.png`

Shows the expanded Sysmon Event ID 1 record for a PowerShell process.

The event contains investigation-relevant information such as:

* EventCode
* ComputerName
* User
* Image
* CommandLine
* ParentImage
* ProcessId
* ProcessGuid
* ParentProcessId
* CurrentDirectory
* Hashes

This screenshot demonstrates how an analyst can investigate the details of an individual PowerShell process creation event.

---

### 04 - PowerShell Command Line Evidence

**File:** `04-PowerShell-CommandLine-Evidence.png`

Shows the PowerShell command-line information associated with the detected process.

The command line provides additional context about what PowerShell was executing and helps determine whether the activity is legitimate or potentially suspicious.

Command-line analysis can be used to identify suspicious PowerShell options, encoded commands, scripts, downloads, or other potentially malicious activity.

---

## Evidence Summary

| Screenshot                               | Evidence                              |
| ---------------------------------------- | ------------------------------------- |
| `01-PowerShell-Detection-Query.png`      | SPL detection query                   |
| `02-PowerShell-Detection-Results.png`    | PowerShell events returned by Splunk  |
| `03-Expanded-PowerShell-Event.png`       | Detailed Sysmon Event ID 1            |
| `04-PowerShell-CommandLine-Evidence.png` | PowerShell command-line investigation |

## Detection Context

**Log Source:** Microsoft-Windows-Sysmon/Operational

**Sysmon Event:** Event ID 1 - Process Creation

**Process:** `powershell.exe`

**Detection Objective:** Identify PowerShell execution activity and provide sufficient event information for SOC investigation.

## Analyst Investigation Flow

```text
PowerShell Execution
        ↓
Sysmon Event ID 1
        ↓
Splunk Universal Forwarder
        ↓
Splunk Index
        ↓
SPL Detection Query
        ↓
Detection Results
        ↓
Expanded Event Investigation
        ↓
Command-Line Analysis
```

These screenshots provide visual evidence that the PowerShell execution detection was successfully performed in the lab environment.
