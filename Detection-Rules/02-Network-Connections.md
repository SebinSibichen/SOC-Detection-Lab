# Detection Rule 02 - Network Connections

## Objective

Detect outbound network connections.

---

## Event

Sysmon Event ID 3

---

## SPL

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
| table _time Image DestinationIp DestinationHostname DestinationPort User
```

---

## MITRE

T1049

---

## Purpose

Detect malware calling external servers.

Useful for C2 detection.
