# Process Creation Detection

This folder contains screenshots demonstrating the successful detection of Windows process creation events using Microsoft Sysmon (Event ID 1) in Splunk Enterprise.

The screenshots provide visual evidence that the detection rule successfully identified the execution of `notepad.exe` during the attack simulation.

---

## Detection Information

**Detection Name:** Process Creation

**Data Source:** Microsoft Sysmon

**Event ID:** 1 (Process Create)

**MITRE ATT&CK:** T1059 – Command and Scripting Interpreter (General Process Execution)

---

## SPL Query

```spl
index=main EventCode=1 Image="*notepad.exe"
```

---

## Screenshot Contents

| Screenshot | Description |
|------------|-------------|
| 01-Search-Query.png | SPL search query used to detect process creation. |
| 02-Search-Results.png | Search results showing detected process creation events. |
| 03-Expanded-Event.png | Expanded event displaying key event information. |
| 04-Full-Event-Details.png | Complete Sysmon Event ID 1 log with all available fields. |
| 05-Interesting-Fields.png | Important extracted fields such as Image, CommandLine, ParentImage, User, and ProcessId. |
| 06-Timeline.png | Timeline visualization showing when the process creation events occurred. |

---

## Detection Outcome

The detection successfully identified the execution of `notepad.exe` on the Windows target machine.

Key artifacts captured include:

- Process Image
- Command Line
- Parent Process
- Process ID
- Process GUID
- User Account
- Integrity Level
- File Hashes
- Timestamp

These screenshots validate that Sysmon event collection, Splunk ingestion, and the detection rule are functioning correctly within the SOC Detection Lab.
