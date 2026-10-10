# Failed Logon Detection Rule

## Rule Name

Windows Failed Logon Detection

## Objective

Detect failed Windows authentication attempts using Security Event ID 4625 and provide information for SOC investigation.

## Data Source

Windows Security Event Log

## Detection Condition

```text
EventCode = 4625
```

## Splunk Detection Query

```spl
index=main EventCode=4625
| table _time ComputerName Account_Name Account_Domain Logon_Type Failure_Reason IpAddress Status Sub_Status
| sort - _time
```

## Severity

**Low to Medium** for an individual failed logon.

Severity should be increased when repeated failures, suspicious source addresses, privileged accounts, or other indicators suggest malicious activity.

## Investigation Fields

| Field            | Purpose                           |
| ---------------- | --------------------------------- |
| `_time`          | Time of the failed authentication |
| `ComputerName`   | System where the event occurred   |
| `Account_Name`   | Account associated with the event |
| `Account_Domain` | Associated account domain         |
| `Logon_Type`     | Type of logon being attempted     |
| `Failure_Reason` | Reason recorded for the failure   |
| `IpAddress`      | Source address, when available    |
| `Status`         | Authentication failure status     |
| `Sub_Status`     | Additional authentication status  |

## Analyst Investigation

1. Identify the affected account.
2. Determine which system generated the event.
3. Inspect the logon type.
4. Review the source address and caller process.
5. Search for other failed attempts involving the same account or source.
6. Check for a successful logon following repeated failures.
7. Determine whether the activity is legitimate or suspicious.

## False Positives

Potential causes include:

* Incorrectly entered credentials
* Applications using outdated passwords
* Background services attempting authentication
* Local authentication failures
* Legitimate users attempting to access a system

## Recommended Response

If suspicious authentication activity is identified:

1. Correlate related failed-logon events.
2. Check for successful authentication events.
3. Validate the account and source system.
4. Review related Windows Security events.
5. Follow the organization's account-containment and incident-response procedures if compromise is suspected.

## MITRE ATT&CK

**T1110 - Brute Force**

This technique is relevant when repeated authentication attempts indicate possible brute-force activity. A single Event ID 4625 is not sufficient to confirm a brute-force attack.
