# Detection Rule 07 — Windows Service Creation

## Detection Name

**Windows Service Creation**

## Detection ID

`SOC-DET-007`

## Severity

**Medium**

## Objective

Detect the creation of Windows services using `sc.exe`.

Windows service creation can be legitimate administrative activity, but attackers may also abuse services for persistence or execution.

---

## Detection Logic

The detection looks for:

1. Sysmon Process Creation events
2. `sc.exe` execution
3. The `create` operation
4. Exclusion of Splunk Universal Forwarder activity

---

## MITRE ATT&CK

**T1543.003 — Create or Modify System Process: Windows Service**

---

## Data Source

**Sysmon Event ID 1 — Process Creation**

Source:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

---

## Detection Query

```spl
index=main EventCode=1
| search Image="*\\sc.exe"
| search CommandLine="*create*"
| where NOT like(Image,"%SplunkUniversalForwarder%")
| table _time ComputerName User Image ParentImage ParentCommandLine CommandLine
| sort - _time
```

---

## Investigation Fields

The following fields should be reviewed during investigation:

| Field               | Purpose                           |
| ------------------- | --------------------------------- |
| `_time`             | Time of process execution         |
| `ComputerName`      | Affected host                     |
| `User`              | Account that executed the command |
| `Image`             | Executable used                   |
| `ParentImage`       | Parent process                    |
| `ParentCommandLine` | Parent process command            |
| `CommandLine`       | Service creation command          |

---

## Example Lab Event

```text
Image:
C:\Windows\System32\sc.exe
```

```text
CommandLine:
"C:\Windows\system32\sc.exe" create SOC_Lab_Service binPath= C:\Windows\System32\notepad.exe start= auto
```

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

```text
User:
TARGETMACHINE\a4803
```

---

## Analyst Investigation

If this detection triggers, investigate:

1. Who created the service?
2. Was the service creation authorized?
3. What executable does the service launch?
4. Is the executable legitimate?
5. Was PowerShell or another scripting interpreter involved?
6. Was the service created shortly before suspicious activity?
7. Does the service provide persistence?

---

## False Positives

Possible legitimate activity includes:

* Software installation
* Windows updates
* IT administration
* Security software installation
* Application deployment
* System configuration

The alert should therefore be investigated in context rather than automatically treated as malicious.

---

## Expected Result

The detection should identify events containing:

```text
sc.exe
create
```

and display the associated process, user, host, and command-line information.
