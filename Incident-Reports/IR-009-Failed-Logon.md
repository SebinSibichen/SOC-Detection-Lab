# SOC Incident Report - Failed Logon

## Incident ID

SOC-IR-009

## Incident Title

Windows Failed Authentication Event

## Detection Source

Splunk Enterprise

## Log Source

Windows Security Event Log

## Event ID

4625

## Initial Severity

Low - Pending Investigation

## MITRE ATT&CK

T1110 - Brute Force

## Incident Summary

Splunk identified Windows Security Event ID 4625, indicating that an account failed to log on.

The event was collected from the Windows target and displayed in Splunk. The expanded event contains authentication and process information that can be used for further investigation.

## Observed Evidence

| Field                  | Observed value                    |
| ---------------------- | --------------------------------- |
| Host                   | TargetMachine                     |
| Event ID               | 4625                              |
| Logon Type             | 2                                 |
| Source Network Address | 127.0.0.1                         |
| Caller Process         | `C:\Windows\System32\svchost.exe` |
| Status                 | `0xC000006D`                      |
| Sub Status             | `0xC0000380`                      |
| SIEM                   | Splunk Enterprise                 |

## Investigation

### 1. Authentication Failure

The event message states:

`An account failed to log on.`

### 2. Logon Type

The captured event has Logon Type 2, indicating an interactive logon attempt.

This event does not independently confirm an RDP authentication failure.

### 3. Source Address

The event records `127.0.0.1`, a loopback address.

This indicates that the recorded source is local to the Windows system. Further investigation is required to determine the activity that generated the event.

### 4. Process Information

The event records `C:\Windows\System32\svchost.exe` as the caller process.

Review the surrounding events and process context before drawing conclusions about the cause.

### 5. Related Events

Review nearby events for:

* Additional failed logons (4625)
* Successful logons (4624)
* Special privileges assigned to a new logon (4672)
* Logoff events (4634)
* Process creation events (4688)

## Assessment

A failed authentication event was successfully detected and collected.

The available evidence does not establish a brute-force attack or confirm that the event originated from the Kali RDP test. The event should remain classified as an authentication failure pending investigation.

## Recommended Actions

1. Review nearby authentication events.
2. Identify the account involved in the failed attempt.
3. Investigate the caller process and source address.
4. Check whether additional failed attempts occurred.
5. Correlate the event with successful logons and related activity.
6. Escalate if evidence of unauthorized access or repeated malicious attempts is discovered.

## Conclusion

This lab demonstrates the collection and investigation of Windows failed-logon events using Splunk. Event ID 4625 was successfully ingested and made available for authentication monitoring.
