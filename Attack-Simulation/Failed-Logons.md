# Failed Logon Simulation

## Objective

Generate a Windows failed authentication event and verify that the event is collected by Splunk for security monitoring and investigation.

## Lab Environment

| Component             | Details                    |
| --------------------- | -------------------------- |
| Attacker/Test Machine | Kali Linux                 |
| Target Machine        | Windows 11                 |
| Hostname              | TargetMachine              |
| SIEM                  | Splunk Enterprise          |
| Log Collector         | Splunk Universal Forwarder |
| Log Source            | Windows Security Event Log |
| Event ID              | 4625                       |
| MITRE ATT&CK          | T1110 - Brute Force        |

## Simulation Procedure

### Step 1: Generate a Failed Authentication Event

Attempt to authenticate using an invalid credential in the authorized lab environment.

For example, enter an incorrect password once when prompted by an authentication client.

Avoid repeated failed attempts that could trigger account lockout policies.

### Step 2: Verify the Event in Windows

Open PowerShell and run:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

The expected event description is:

`An account failed to log on.`

### Step 3: Verify Event Collection in Splunk

Run the following SPL query:

```spl
index=main EventCode=4625
| table _time ComputerName Account_Name Account_Domain Logon_Type Failure_Reason IpAddress Message
| sort - _time
```

### Step 4: Inspect the Event

Review these fields:

* Event ID
* Account Name
* Account Domain
* Logon Type
* Failure Reason
* Status
* Sub Status
* Source Network Address
* Caller Process Name

## Observed Lab Evidence

The captured event shows:

| Field                  | Observed value                    |
| ---------------------- | --------------------------------- |
| Event ID               | 4625                              |
| Event description      | An account failed to log on       |
| Logon Type             | 2                                 |
| Source Network Address | 127.0.0.1                         |
| Caller Process Name    | `C:\Windows\System32\svchost.exe` |
| Status                 | `0xC000006D`                      |
| Sub Status             | `0xC0000380`                      |

The captured event is a local interactive logon failure. The available evidence does not establish that this event originated from the Kali RDP test.

## Result

Security Event ID 4625 was successfully collected and displayed in Splunk.

The event demonstrates failed-logon monitoring and provides a basis for further authentication investigation.
