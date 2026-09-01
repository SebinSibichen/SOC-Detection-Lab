
---

## `Detection-Rules/05-Registry-Persistence.md`

```markdown
# Detection Rule 05 - Registry Persistence

## Detection Name

Registry Run Key Persistence Detection

---

## Objective

Detect modifications to Windows Registry Run Keys that may be used
to establish persistence.

The detection monitors Sysmon Event ID 13 and identifies registry
values created or modified under the Windows `CurrentVersion\Run`
registry path.

---

## Data Source

- Windows
- Sysmon
- Sysmon Event ID 13
- Splunk Universal Forwarder
- Splunk Enterprise

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Persistence |
| Technique | Registry Run Keys / Startup Folder |
| Technique ID | T1547.001 |
| Legacy ID | T1060 |
| Sysmon Event | Event ID 13 |

---

## SPL Detection Query

```spl
index=main EventCode=13
| search TargetObject="*\\CurrentVersion\\Run\\*"
| where NOT like(Image,"%SplunkUniversalForwarder%")
| table _time ComputerName User Image TargetObject Details
| sort - _time
