SOC Incident Report — IR-002: Network Connection Monitoring

1. Executive Summary

Incident ID: SOC-IR-002
Category: Network Monitoring / Endpoint Communications
Environment: Windows 11 lab endpoint
Detection Platform: Splunk Enterprise
Telemetry Source: Sysmon Operational Log
Status: Monitoring exercise
Severity: Informational — Pending destination and behavior assessment
Disposition: Network telemetry investigation



This exercise evaluates endpoint network-connection visibility using Sysmon and Splunk.



The objective is to identify network activity and provide context for investigating unexpected destinations, unusual processes, and potentially suspicious communication patterns.



A network connection is not inherently malicious.

2. Scope and Environment

Attribute

Details

Endpoint

TargetMachine

SIEM

Splunk Enterprise

Index

main

Event source

Sysmon Operational

Primary event

Sysmon Event ID 3, if enabled

3. Detection and Evidence

Detection objective: Identify and investigate endpoint network connections.



Relevant fields may include:



Image

SourceIp

SourcePort

DestinationIp

DestinationPort

Protocol

User

UtcTime



Observed timestamp: [Insert verified timestamp]
Source address: [Insert verified value]
Destination address: [Insert verified value]
Destination port: [Insert verified value]
Associated process: [Insert verified executable]

4. Investigation and Analysis

Review the associated process, destination, port, protocol, and timing.



Determine whether the connection is expected for the application or activity being tested. Where necessary, correlate the event with DNS records, firewall logs, process execution, or other available telemetry.



Document the destination's purpose and whether the communication can be explained by normal lab activity.

5. MITRE ATT&CK Mapping

Candidate technique: T1049 — System Network Connections Discovery, only when discovery behavior is supported by evidence.



A routine network connection does not independently establish T1049.



Official reference: https://attack.mitre.org/techniques/T1049/

6. Impact Assessment

Unauthorized communication: Not established without supporting evidence.

Command and control: Not established.

Data exfiltration: Not established.

Endpoint compromise: Not established.

7. Response and Containment

Do not block a destination solely because it appears in a connection event.



If the destination or process is confirmed suspicious, preserve the evidence and assess the need for blocking or endpoint isolation under the applicable response procedure.

8. False-Positive Considerations

Legitimate applications commonly communicate with update services, internal systems, DNS resolvers, and cloud services.

9. Limitations and Evidence Gaps

Sysmon Event ID 3 must be enabled for the relevant network events to be collected.

A connection does not reveal the full contents or purpose of the communication.

Destination reputation alone is insufficient to establish compromise.

10. Recommendations

Verify network-event collection.

Record process and destination context.

Correlate network activity with endpoint execution.

Establish a baseline of expected connections where practical.

11. Final Disposition

Disposition: Network-monitoring exercise; malicious communication not established.



Validation status: [Telemetry observed / Detection validated / Needs further validation]



**Analyst Notes:** Network-connection telemetry is intended to provide visibility into endpoint communications. The associated process, destination address, destination port, and protocol should be reviewed to determine whether the activity is expected. A malicious connection has not been established solely from connection telemetry.

