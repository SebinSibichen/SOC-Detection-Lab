
## Incident Information

| Field          | Details                 |
| -------------- | ----------------------- |
| Incident ID    | `SOC-IR-006`            |
| Detection Rule | `06 – Scheduled Tasks`  |
| Severity       | Medium                  |
| Status         | Closed – Lab Simulation |
| Host           | `TargetMachine`         |
| User           | `TARGETMACHINE\a4803`   |
| Event ID       | Sysmon Event ID 1       |
| Technique      | Scheduled Task/Job      |

---

## Incident Summary

A Windows Scheduled Task named `SOC_Lab_ScheduledTask` was created on the target Windows system using the native `schtasks.exe` utility.

The task was configured to execute:

```text
C:\Windows\System32\notepad.exe
```

at user logon and run under the `SYSTEM` account.

The activity was intentionally generated as a benign SOC detection lab simulation.

---

## Detection Evidence

Sysmon recorded the process creation activity.

### Process

```text
C:\Windows\System32\schtasks.exe
```

### Command Line

```text
"C:\Windows\system32\schtasks.exe" /create /tn SOC_Lab_ScheduledTask /tr C:\Windows\System32\notepad.exe /sc ONLOGON /ru SYSTEM
```

### Parent Process

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### User

```text
TARGETMACHINE\a4803
```

---

## Investigation

The SOC investigation confirmed that:

1. `schtasks.exe` was executed.
2. The `/create` parameter was used.
3. A scheduled task named `SOC_Lab_ScheduledTask` was created.
4. The task was configured for execution at user logon.
5. The task was configured to run as `SYSTEM`.
6. The target executable was the legitimate Windows `notepad.exe`.
7. The activity was intentionally generated for this security lab.

---

## Impact Assessment

No malicious impact was identified.

The scheduled task was created solely for testing the SOC detection pipeline.

---

## Response

The scheduled task was removed after completing the investigation.

Cleanup command:

```powershell
schtasks /delete /tn "SOC_Lab_ScheduledTask" /f
```

---

## Final Classification

**Classification:** Benign – Authorized SOC Lab Simulation

**Final Status:** Closed

---

## Lessons Learned

This investigation demonstrates how a SOC analyst can:

* Detect Scheduled Task creation.
* Identify the process responsible.
* Investigate the command line.
* Identify the parent process.
* Identify the user account.
* Determine the executable associated with the task.
* Map the activity to MITRE ATT&CK.
* Distinguish legitimate administrative activity from potentially malicious persistence.
