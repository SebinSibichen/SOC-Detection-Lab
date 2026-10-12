# SOC Incident Report — IR-008: Remote Desktop Logon Monitoring

## 1. Executive Summary

**Incident ID:** SOC-IR-008
**Category:** Remote Access / Authentication
**Environment:** Windows 11 lab endpoint
**Detection Platform:** Splunk Enterprise
**Telemetry Source:** Windows Security Event Log
**Status:** Logon-monitoring exercise
**Severity:** Informational — Authorization assessment required
**Disposition:** RDP-related authentication investigation

This exercise evaluates detection of successful remote interactive logons on Windows.

Windows Security Event ID 4624 with Logon Type 10 can support identification of Remote Interactive logon activity.

A successful RDP-related logon does not automatically indicate unauthorized access.

## 2. Scope and Environment

| Attribute     | Details              |
| ------------- | -------------------- |
| Endpoint      | `TargetMachine`      |
| SIEM index    | `main`               |
| Event ID      | 4624                 |
| Key indicator | Logon Type 10        |
| Data source   | Windows Security log |

## 3. Detection and Evidence

Record the following from the actual event:

* Timestamp
* Target account
* Logon type
* Source IP address
* Workstation name, if available
* Authentication context
* Relevant event record identifier

**Observed timestamp:** [Insert verified timestamp]
**Account:** [Insert verified account]
**Logon Type:** 10, if confirmed
**Source address:** [Insert verified address]

## 4. Investigation and Analysis

Confirm that the event is a successful Remote Interactive logon.

Review the account, source address, destination endpoint, and whether the session was authorized. Correlate with subsequent process activity if the investigation requires determining what occurred during the session.

## 5. MITRE ATT&CK Mapping

**Candidate technique:** T1021.001 — Remote Services: Remote Desktop Protocol.

**Official reference:** https://attack.mitre.org/techniques/T1021/001/

The mapping is appropriate when RDP use is established. A technique mapping alone does not establish adversary activity.

## 6. Impact Assessment

* Unauthorized remote access: Not established.
* Account compromise: Not established.
* Lateral movement: Not established.
* Post-logon malicious activity: Not established.

## 7. Response and Containment

Do not disable accounts or block remote access solely because a successful logon occurred.

If the session is determined to be unauthorized, preserve authentication evidence and follow the organization's access-control and incident-response procedures.

## 8. False-Positive Considerations

Legitimate remote administration, help-desk activity, and authorized user sessions can generate these events.

## 9. Limitations and Evidence Gaps

A successful logon confirms authentication activity but does not independently reveal the purpose of the session or prove compromise.

## 10. Recommendations

* Verify logon type and source information.
* Establish expected remote-access patterns.
* Correlate authentication with endpoint activity.
* Review account and remote-access policies when suspicious activity is identified.

## 11. Final Disposition

**Disposition:** Remote-access monitoring exercise; unauthorized access not established.

**Validation status:** RDP-related logon telemetry observed; document focused detection validation separately.

**Analyst Notes:** Windows Security Event ID 4624 with Logon Type 10 can provide evidence of a successful Remote Interactive logon. The account, source address, and surrounding activity should be reviewed to determine whether the session was authorized. A successful logon alone does not establish unauthorized access or lateral movement.


