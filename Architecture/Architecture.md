# SOC Detection Lab Architecture

## Overview

The SOC Detection Lab was developed to simulate a real-world Security Operations Center (SOC) using Windows logging, Sysmon, Splunk Universal Forwarder, and Splunk Enterprise.

The lab enables security event collection, centralized logging, threat detection, and incident investigation.

---

## Lab Components

### Windows 11 Virtual Machine

Acts as the monitored endpoint where user activity and attack simulations occur.

Responsibilities:

- Generate Windows Event Logs
- Execute attack simulations
- Produce Sysmon telemetry

---

### Sysmon

Sysmon extends native Windows logging by providing detailed visibility into endpoint activity.

Examples include:

- Process Creation
- Network Connections
- Registry Changes
- Driver Loading
- Image Loading
- Process Access

---

### Splunk Universal Forwarder

Installed on the Windows VM.

Responsibilities:

- Collect Windows Event Logs
- Monitor Sysmon Operational Logs
- Forward events securely to Splunk Enterprise

Forwarding Port:

9997

---

### Splunk Enterprise

Installed on the host machine.

Responsibilities:

- Receive forwarded logs
- Index security events
- Execute SPL searches
- Support detection engineering
- Perform incident investigations

---

### VMware Workstation

Provides an isolated environment for safely conducting attack simulations.

---

## Data Flow

Windows Activity

↓

Windows Event Logs

↓

Sysmon

↓

Splunk Universal Forwarder

↓

TCP Port 9997

↓

Splunk Enterprise

↓

Indexes

↓

SPL Queries

↓

Detection Rules

↓

Incident Reports

---

## Lab Goals

- Learn Detection Engineering
- Practice Threat Hunting
- Develop SPL Queries
- Investigate Security Incidents
- Map detections to MITRE ATT&CK

---

## Skills Demonstrated

- Windows Logging
- Sysmon Configuration
- Splunk Administration
- Universal Forwarder Configuration
- Detection Engineering
- Threat Hunting
- Incident Response
- MITRE ATT&CK Mapping
