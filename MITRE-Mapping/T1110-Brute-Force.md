# MITRE ATT&CK Mapping - Failed Logon Detection

## Technique

**T1110 - Brute Force**

## Tactic

Credential Access

## Technique Overview

Brute-force activity involves attempting to obtain valid credentials through repeated authentication attempts.

Windows Security Event ID 4625 can provide useful telemetry for detecting failed authentication activity. However, an individual failure does not prove a brute-force attack.

## Lab Activity

The lab collected and investigated a Windows failed-logon event.

```text
Windows Target
      |
      | Security Event ID 4625
      v
Splunk Universal Forwarder
      |
      v
Splunk Enterprise
      |
      v
Failed Logon Detection
      |
      v
SOC Investigation
```

## Detection Evidence

| Field                   | Value                       |
| ----------------------- | --------------------------- |
| Windows Event ID        | 4625                        |
| Event Description       | An account failed to log on |
| Observed Logon Type     | 2                           |
| Observed Source Address | 127.0.0.1                   |
| SIEM                    | Splunk Enterprise           |

## Detection Query

```spl
index=main EventCode=4625
| stats count by Account_Name IpAddress ComputerName
| sort - count
```

## SOC Investigation

A SOC analyst should:

* Identify the account associated with the failure.
* Review the source address and logon type.
* Search for repeated authentication failures.
* Identify whether failures target one account or many accounts.
* Correlate failures with successful logons.
* Investigate related process and network activity.

## ATT&CK Mapping Summary

| Field          | Value                            |
| -------------- | -------------------------------- |
| Tactic         | Credential Access                |
| Technique      | T1110                            |
| Technique Name | Brute Force                      |
| Telemetry      | Windows Security Event ID 4625   |
| SIEM           | Splunk Enterprise                |
| Lab Status     | Failed-logon telemetry collected |

## Mapping Limitation

The observed event confirms a failed logon, not a brute-force attack. T1110 is the relevant detection objective for identifying patterns of repeated authentication attempts, but additional evidence is needed to establish that technique.
