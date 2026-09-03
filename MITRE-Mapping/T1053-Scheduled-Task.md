# MITRE ATT&CK Mapping – Scheduled Tasks

## Primary Technique

### T1053.005 – Scheduled Task/Job: Scheduled Task

**Tactic:**

* Persistence
* Execution

The Windows Scheduled Task created during this lab maps to **T1053.005 – Scheduled Task**.

---

## Technique Description

Scheduled Tasks can be used by attackers to execute programs automatically according to a configured trigger.

Attackers may create or modify scheduled tasks to maintain persistence or execute malicious programs.

In this lab, the native Windows `schtasks.exe` utility was used to create a scheduled task configured to execute `notepad.exe` at user logon.

---

## Lab Evidence

### Command Used

```powershell
schtasks /create /tn "SOC_Lab_ScheduledTask" /tr "C:\Windows\System32\notepad.exe" /sc ONLOGON /ru SYSTEM
```

### Scheduled Task

```text
SOC_Lab_ScheduledTask
```

### Trigger

```text
ONLOGON
```

### Run As

```text
SYSTEM
```

### Executable

```text
C:\Windows\System32\notepad.exe
```

---

## Detection Evidence

Sysmon generated:

```text
Event ID 1 – Process Create
```

with:

```text
Image:
C:\Windows\System32\schtasks.exe
```

and:

```text
CommandLine:
... /create /tn SOC_Lab_ScheduledTask ...
```

The parent process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## ATT&CK Mapping

| Field            | Value                      |
| ---------------- | -------------------------- |
| Tactic           | Persistence                |
| Tactic           | Execution                  |
| Technique        | T1053 – Scheduled Task/Job |
| Sub-technique    | T1053.005 – Scheduled Task |
| Platform         | Windows                    |
| Detection Source | Sysmon                     |
| Sysmon Event     | Event ID 1                 |
| Tool             | `schtasks.exe`             |

---

## Detection Relationship

```text
T1053
Scheduled Task/Job
        ↓
T1053.005
Scheduled Task
        ↓
schtasks.exe
        ↓
Sysmon Event ID 1
        ↓
Splunk Detection Rule 06
```

---

## Security Relevance

Scheduled Task creation is not inherently malicious because Windows and legitimate software frequently use scheduled tasks.

However, unexpected tasks should be investigated for:

* Suspicious task names
* Unknown executables
* PowerShell or command shell execution
* Execution from temporary directories
* User-created tasks
* SYSTEM-level execution
* Unusual logon or time-based triggers
* Suspicious parent-child process relationships

---

## Lab Classification

**Technique Demonstrated:** T1053.005

**Activity Type:** Benign SOC Detection Simulation

**Detection Status:** Successfully Detected
