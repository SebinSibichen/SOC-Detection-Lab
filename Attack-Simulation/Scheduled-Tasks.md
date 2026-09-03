
## Objective

Simulate a Windows Scheduled Task creation activity that could be used by an attacker to establish persistence or execute a program automatically.

The simulation uses the legitimate Windows `schtasks.exe` utility to create a benign scheduled task that launches `notepad.exe` at user logon.

---

## Lab Environment

* **Target:** Windows 11
* **Username:** `TARGETMACHINE\a4803`
* **Tool:** Windows PowerShell
* **Monitoring:** Sysmon
* **SIEM:** Splunk Enterprise
* **Log Forwarder:** Splunk Universal Forwarder

---

## Step 1 – Create Scheduled Task

PowerShell was opened with Administrator privileges and the following command was executed:

```powershell
schtasks /create /tn "SOC_Lab_ScheduledTask" /tr "C:\Windows\System32\notepad.exe" /sc ONLOGON /ru SYSTEM
```

### Task Details

| Parameter | Value                             |
| --------- | --------------------------------- |
| Task Name | `SOC_Lab_ScheduledTask`           |
| Program   | `C:\Windows\System32\notepad.exe` |
| Schedule  | `ONLOGON`                         |
| Run As    | `SYSTEM`                          |
| Purpose   | Benign SOC lab simulation         |

The command successfully created the scheduled task.

---

## Step 2 – Verify Scheduled Task

The task was verified using:

```powershell
schtasks /query /tn "SOC_Lab_ScheduledTask" /fo LIST /v
```

The output confirmed:

```text
TaskName:
\SOC_Lab_ScheduledTask

Status:
Ready

Task To Run:
C:\Windows\System32\notepad.exe

Schedule Type:
At logon time

Run As User:
SYSTEM
```

---

## Step 3 – Sysmon Detection

Sysmon generated **Event ID 1 – Process Create** when `schtasks.exe` was executed.

Important fields observed:

```text
Image:
C:\Windows\System32\schtasks.exe

CommandLine:
"C:\Windows\system32\schtasks.exe" /create /tn SOC_Lab_ScheduledTask /tr C:\Windows\System32\notepad.exe /sc ONLOGON /ru SYSTEM

ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

User:
TARGETMACHINE\a4803
```

This establishes the following process chain:

```text
PowerShell
    ↓
schtasks.exe
    ↓
Scheduled Task Creation
    ↓
SOC_Lab_ScheduledTask
    ↓
notepad.exe
```

---

## Step 4 – Splunk Detection

The Sysmon Event ID 1 was forwarded to Splunk through the Splunk Universal Forwarder.

The detection query identified the `schtasks.exe` process and filtered for task creation using `/create`.

---

## Expected Result

The activity should be visible in Splunk with:

* `EventCode=1`
* `Image=C:\Windows\System32\schtasks.exe`
* `/create` in the command line
* PowerShell as the parent process
* The user responsible for creating the task

---

## Cleanup

After completing the investigation, remove the test scheduled task using:

```powershell
schtasks /delete /tn "SOC_Lab_ScheduledTask" /f
```

This removes the benign lab-created scheduled task from the Windows system.
