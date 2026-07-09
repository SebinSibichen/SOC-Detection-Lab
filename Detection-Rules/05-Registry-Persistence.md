# Detection Rule 05 - Registry Persistence

## Event

Sysmon Event ID 13

---

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
| table _time TargetObject Details Image User
```

---

## MITRE

T1547

---

## Purpose

Detect Registry Run Key persistence.
