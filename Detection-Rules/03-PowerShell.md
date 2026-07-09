# Detection Rule 03 - PowerShell Execution

## Event

Sysmon Event ID 1

---

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*powershell.exe"
| table _time Image CommandLine ParentImage User
```

---

## MITRE

T1059.001

---

## Purpose

Detect PowerShell execution.
