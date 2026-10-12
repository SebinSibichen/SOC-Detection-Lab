# Module 02 — Network Connections: MITRE ATT&CK Mapping

## Objective

Map Windows network-connection telemetry collected by Sysmon to relevant MITRE ATT&CK techniques for investigation and threat detection.

## 1. Tactic: Command and Control

### T1071 — Application Layer Protocol

* **Description:** Adversaries may communicate with compromised systems using application-layer protocols.
* **Relevance:** Network connections may help analysts investigate potentially suspicious communications over protocols such as HTTP or HTTPS.
* **Evidence to investigate:** Destination IP, destination port, process image, connection time, and network context.
* **Mapping status:** Candidate technique. A network connection alone does not confirm command-and-control activity.

## 2. Tactic: Command and Control

### T1095 — Non-Application Layer Protocol

* **Description:** Adversaries may use non-application-layer protocols to communicate with compromised systems.
* **Relevance:** Unusual network connections may warrant investigation when their process, destination, or behavior is suspicious.
* **Evidence to investigate:** Protocol, source and destination addresses, ports, and initiating process.
* **Mapping status:** Candidate technique. Confirm the protocol and supporting evidence before assigning this technique.

## 3. Tactic: Discovery

### T1046 — Network Service Discovery

* **Description:** Adversaries may scan networks to identify services running on remote systems.
* **Relevance:** Repeated connections to multiple ports or hosts may indicate service discovery or scanning activity.
* **Evidence to investigate:** Connection frequency, destination diversity, destination ports, and the process generating the connections.
* **Mapping status:** Use only when the observed behavior supports network-service discovery. A single connection is insufficient.

## 4. Tactic: Command and Control

### T1105 — Ingress Tool Transfer

* **Description:** Adversaries may transfer tools or files into a compromised environment.
* **Relevance:** Network connections initiated by utilities or scripts may provide context for investigating possible downloads.
* **Evidence to investigate:** Initiating process, command line, destination, transfer-related events, and downloaded-file evidence.
* **Mapping status:** Candidate technique only when there is supporting evidence of tool or file transfer. A connection alone does not establish a transfer.

## Telemetry Source

* **Platform:** Windows
* **Tool:** Sysmon
* **Event ID:** 3 — Network connection detected
* **Splunk index:** `main`
* **Typical fields:** `Image`, `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`, `Protocol`, and `Initiated`, depending on the event configuration and field extraction.

## Analyst Guidance

1. Identify the process responsible for the connection.
2. Review the destination IP address, port, and protocol.
3. Check whether the connection is expected for the host and application.
4. Correlate with process-creation events and other available telemetry.
5. Assign a MITRE ATT&CK technique only when the observed behavior supports the mapping.

## Conclusion

Sysmon network-connection telemetry can support investigations into suspicious communications, network discovery, and potential tool transfers. The correct MITRE ATT&CK mapping depends on the behavior and corroborating evidence, not merely on the existence of a network connection.

**Validation status:** This document provides candidate technique mappings. Confirm the specific techniques against the actual events and detection logic in the lab before describing them as detected behavior.
