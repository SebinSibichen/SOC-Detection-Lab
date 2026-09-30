# MITRE ATT&CK Mapping - RDP Logon

## Technique

**T1021.001 - Remote Services: Remote Desktop Protocol**

## Tactic

**Lateral Movement**

## Technique Description

Adversaries may use Remote Desktop Protocol (RDP) to remotely access Windows systems.

In this lab, an RDP connection was established from the Kali Linux system to the Windows target machine.

## Lab Activity

```text
Kali Linux
    |
    | RDP Connection
    v
Windows Target
    |
    | Security Event 4624
    | Logon Type 10
    v
Splunk
```

## Detection Evidence

The Windows Security log generated:

```text
Event ID: 4624
Logon Type: 10
```

Microsoft identifies Logon Type 10 as `RemoteInteractive`, corresponding to Remote Desktop/Terminal Services logons.

## Detection Method

Splunk searches for:

```spl
index=main EventCode=4624 Logon_Type=10
```

## Relevant Telemetry

| Telemetry              | Purpose                       |
| ---------------------- | ----------------------------- |
| Event ID 4624          | Successful logon              |
| Logon Type 10          | RemoteInteractive/RDP         |
| Account Name           | Identifies logged-on account  |
| Computer Name          | Identifies target             |
| IP Address             | Identifies source address     |
| Workstation Name       | Identifies source workstation |
| Logon Process          | Authentication process        |
| Authentication Package | Authentication mechanism      |

## SOC Investigation

A SOC analyst should correlate the RDP event with:

* Failed logons
* Privileged logons
* Process creation
* PowerShell execution
* Network connections
* Persistence activity
* Additional authentication events

## Detection Objective

Identify successful RDP connections and provide analysts with sufficient authentication and network information to determine whether the remote access was authorized.

## ATT&CK Mapping Summary

| Field               | Value                                    |
| ------------------- | ---------------------------------------- |
| Tactic              | Lateral Movement                         |
| Technique           | T1021.001                                |
| Technique Name      | Remote Services: Remote Desktop Protocol |
| Windows Event       | 4624                                     |
| Detection Indicator | Logon Type 10                            |
| SIEM                | Splunk                                   |
