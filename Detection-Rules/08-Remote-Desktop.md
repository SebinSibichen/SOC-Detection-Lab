# RDP Logon Detection Rule

## Rule Name

Successful RDP Logon Detection

## Objective

Detect successful Remote Desktop Protocol (RDP) logons to Windows systems using Security Event ID 4624 and Logon Type 10.

## Data Source

```text
Windows Security Event Log
```

## Event ID

```text
4624
```

## Detection Condition

```text
EventCode = 4624
AND
Logon_Type = 10
```

Logon Type 10 represents a `RemoteInteractive` logon, which Microsoft documents as a user logging on remotely through Terminal Services or Remote Desktop.

## Splunk Detection Logic

```spl
index=main EventCode=4624
| search Logon_Type=10
| table _time ComputerName Account_Domain Account_Name Logon_Type Logon_Process Authentication_Package IpAddress Workstation_Name
| sort - _time
```

## Detection Fields

| Field                    | Purpose                                     |
| ------------------------ | ------------------------------------------- |
| `_time`                  | Time of the authentication event            |
| `ComputerName`           | Windows system receiving the RDP connection |
| `Account_Domain`         | Account domain or computer name             |
| `Account_Name`           | Account that successfully logged on         |
| `Logon_Type`             | Identifies the type of logon                |
| `Logon_Process`          | Authentication/logon process                |
| `Authentication_Package` | Authentication mechanism                    |
| `IpAddress`              | Source IP address when available            |
| `Workstation_Name`       | Source workstation when available           |

## Analyst Investigation

When an alert is generated, the SOC analyst should investigate:

1. Which account performed the RDP logon?
2. Which Windows system was accessed?
3. What was the source IP address?
4. Was the RDP connection expected?
5. Was the account authorized to remotely access the system?
6. Was the connection made during expected working hours?
7. Were additional suspicious events generated after the RDP logon?
8. Were privileged accounts involved?

## Detection Severity

**Medium**

The detection identifies successful remote access. Severity should be increased when the source, account, timing, or subsequent activity is suspicious.

## False Positives

Possible legitimate activity includes:

* Authorized administrator access
* IT support activity
* Remote maintenance
* Authorized remote workforce access
* Lab/testing activity

## Recommended SOC Response

For an unexpected RDP logon:

1. Validate the source IP.
2. Identify the account used.
3. Confirm whether the user authorized the connection.
4. Review surrounding Security events.
5. Review process creation events after the logon.
6. Review network connections.
7. Check for privilege escalation or persistence.
8. Disable or restrict the account if unauthorized access is confirmed.
9. Document the investigation.

## MITRE ATT&CK

**T1021.001 - Remote Services: Remote Desktop Protocol**
