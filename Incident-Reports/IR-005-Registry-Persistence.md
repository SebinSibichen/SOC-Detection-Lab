
---

## `Incident-Reports/05-Registry-Persistence-Incident.md`

```markdown
# Incident Report 05 - Registry Persistence

## Incident Overview

| Field | Details |
|---|---|
| Incident ID | SOC-IR-005 |
| Incident Type | Registry Persistence |
| Severity | Medium |
| Status | Closed - Lab Simulation |
| Detection Source | Sysmon Event ID 13 |
| SIEM | Splunk Enterprise |
| Host | TargetMachine |
| User | TARGETMACHINE\a4803 |
| Technique | T1547.001 |
| Tactic | Persistence |

---

## Executive Summary

A controlled Registry Run Key persistence technique was simulated
on the Windows target machine.

A registry value named `SOC_Lab_Test` was created under the user's
Windows `CurrentVersion\Run` registry path and configured to launch
Notepad.

Sysmon generated Event ID 13, recording the registry modification.
The event was successfully forwarded to Splunk and identified using
the Registry Persistence detection rule.

The activity was part of an authorized SOC laboratory simulation.

---

## Observed Activity

The following registry value was created:

```text
Registry Path:
HKU\<User-SID>\Software\Microsoft\Windows\CurrentVersion\Run

Value Name:
SOC_Lab_Test

Value Data:
C:\Windows\System32\notepad.exe
