# Detection Rule 04 - Encoded PowerShell

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*powershell.exe"
CommandLine="*-enc*"
| table _time CommandLine User ParentImage
```

---

## MITRE

T1059.001

---

## Purpose

Detect Base64 encoded PowerShell commands.
