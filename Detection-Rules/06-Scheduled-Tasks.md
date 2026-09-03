
## Detection Objective

Detect the creation of Windows Scheduled Tasks using the native `schtasks.exe` utility.

Attackers may abuse scheduled tasks to establish persistence or execute programs automatically at a specified time or system event.

---

## Detection Logic

The detection searches Sysmon Process Creation events for:

* `schtasks.exe`
* `/create` command-line parameter
* User responsible for the activity
* Parent process
* Full command line

---

## Sysmon Event

**Event ID:** `1 – Process Create`

The detection focuses on:

```text
Image:
C:\Windows\System32\schtasks.exe
```

and:

```text
CommandLine:
*/create*
```

---

## Splunk Detection Query

```spl
index=main EventCode=1
| search Image="*\\schtasks.exe"
| search CommandLine="*/create*"
| where NOT like(Image,"%SplunkUniversalForwarder%")
| table _time ComputerName User Image ParentImage ParentCommandLine CommandLine
| sort - _time
```

---

## Detection Fields

| Field               | Purpose                           |
| ------------------- | --------------------------------- |
| `_time`             | Time of process execution         |
| `ComputerName`      | Host where activity occurred      |
| `User`              | Account responsible for execution |
| `Image`             | Executable involved               |
| `ParentImage`       | Parent process                    |
| `ParentCommandLine` | Parent process command line       |
| `CommandLine`       | Full `schtasks.exe` command       |

---

## Investigation Considerations

When this detection triggers, the SOC analyst should investigate:

1. Who created the scheduled task?
2. What scheduled task was created?
3. What executable or command will the task execute?
4. What is the task's execution schedule?
5. Which user account created the task?
6. Was `schtasks.exe` launched from PowerShell, Command Prompt, or another process?
7. Is the executable being launched legitimate?
8. Is the task configured to run with elevated privileges or as `SYSTEM`?
9. Is the activity associated with an approved administrative operation?

---

## False Positives

Legitimate scheduled task creation can occur during:

* Software installation
* Windows administration
* System maintenance
* IT automation
* Security software updates
* Enterprise management tools

The SOC analyst should therefore investigate the task command, parent process, user account, and destination executable before classifying the event as malicious.

---

## Detection Result

The lab successfully detected:

```text
C:\Windows\System32\schtasks.exe
```

with:

```text
/create /tn SOC_Lab_ScheduledTask
```

The observed parent process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This confirmed that the Scheduled Task detection rule was successfully working in Splunk.

---

## Severity

**Medium**

Scheduled Task creation can be legitimate, but attackers commonly abuse scheduled tasks for persistence and execution.

---

## Status

**Validated – Lab Simulation**
