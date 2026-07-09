# Detection Rule 01 - Process Creation

## Objective

Detect every new process created on the Windows system using Sysmon Event ID 1.

---

## Log Source

- Sysmon
- Event ID: 1
- Channel:
Microsoft-Windows-Sysmon/Operational

---

## MITRE ATT&CK

Technique:
T1059

Tactic:
Execution

---

## SPL Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| table _time Image ParentImage CommandLine User
```

---

## Expected Result

Shows

- Executable
- Parent Process
- User
- Command Line
- Timestamp

---

## Detection Logic

Whenever a new process starts,
Sysmon generates Event ID 1.

Splunk collects the event and displays process execution details.

---

## Screenshot

See:

../Screenshots/Detection-01/

---

## False Positives

Normal Windows processes

- explorer.exe
- svchost.exe
- services.exe

---

## Analyst Notes

Useful for malware detection.

Attackers almost always create a process.

This is one of the most important Sysmon detections.
