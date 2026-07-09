# Detection Rule 12 – Credential Access

## Objective
Detect potential credential dumping activity.

## MITRE ATT&CK
T1003

## SPL Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
| table _time SourceImage TargetImage GrantedAccess User
```

## Investigation
Look for access to lsass.exe or other credential stores.

## Screenshot
Screenshots/Detection-12/
