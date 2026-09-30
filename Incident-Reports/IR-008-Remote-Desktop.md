# SOC Incident Report - RDP Logon

## Incident ID

```text
SOC-IR-008
```

## Incident Title

Successful Remote Desktop Protocol (RDP) Logon

## Detection Source

Splunk SIEM

## Log Source

Windows Security Event Log

## Event ID

```text
4624
```

## Logon Type

```text
10 - RemoteInteractive
```

## MITRE ATT&CK

```text
T1021.001 - Remote Services: Remote Desktop Protocol
```

## Incident Description

A successful Remote Desktop Protocol authentication was detected on the Windows target system.

The authentication generated Windows Security Event ID 4624 with Logon Type 10, indicating a successful RemoteInteractive logon.

Microsoft documents Event ID 4624 as a successful logon event and identifies Logon Type 10 as RemoteInteractive, used for Remote Desktop/Terminal Services connections.

## Detection Details

| Field              | Value                |
| ------------------ | -------------------- |
| Event ID           | 4624                 |
| Logon Type         | 10                   |
| Host               | TargetMachine        |
| Account            | a4803                |
| Source             | Windows Security Log |
| Detection Platform | Splunk               |
| MITRE Technique    | T1021.001            |

## Investigation

The SOC analyst should investigate the following:

### 1. User Account

Determine whether the account associated with the RDP session is authorized to access the target system remotely.

### 2. Source Address

Review the `IpAddress` field to identify the source system that initiated the RDP connection.

### 3. Authentication Details

Review:

* Logon Process
* Authentication Package
* Logon ID
* Workstation Name
* Source Port

### 4. Related Events

Search for events occurring immediately before and after the RDP authentication.

Relevant events may include:

```text
4625 - Failed logon
4672 - Special privileges assigned to new logon
4688 - Process creation
4634 - Logoff
```

### 5. Post-Logon Activity

Review process creation, PowerShell activity, network connections, persistence mechanisms, and other suspicious activity following the RDP session.

## Impact

A successful RDP logon provides remote interactive access to the Windows system.

The security impact depends on:

* Account privileges
* Source system
* Authorization
* Subsequent activity
* Whether the account was compromised

## Response

If the RDP session is unauthorized:

1. Validate the source IP.
2. Identify the account owner.
3. Terminate the active session if required.
4. Disable or reset the affected account if compromise is suspected.
5. Review authentication and process activity.
6. Investigate potential lateral movement.
7. Check for persistence mechanisms.
8. Document the incident.

## Lab Conclusion

The RDP simulation successfully generated Windows Security Event ID 4624 with Logon Type 10. The event was collected by Splunk Universal Forwarder and detected using a Splunk SPL query.

This demonstrates a SOC workflow for identifying and investigating successful remote access to Windows systems.
