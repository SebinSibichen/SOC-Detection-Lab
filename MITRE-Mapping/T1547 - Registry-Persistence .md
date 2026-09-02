
---


**File:** `MITRE-Mapping/05-Registry-Persistence.md`

```markdown
# MITRE ATT&CK Mapping 05 - Registry Persistence

## Technique

**T1547.001 - Registry Run Keys / Startup Folder**

---

## Tactic

**Persistence**

---

## Description

Registry Run Keys can be used to automatically execute programs when
a user logs on to a Windows system.

In this laboratory simulation, a registry value was created under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
