# SPL Queries

This directory contains Splunk Processing Language (SPL) queries developed for the **SOC Detection Lab**. These queries are designed to detect suspicious activities, investigate security events, and support incident response using **Splunk Enterprise**, **Sysmon**, and **Windows Event Logs**.

---

# Objectives

- Detect suspicious and malicious system activity
- Monitor Windows process execution
- Identify PowerShell abuse
- Detect persistence mechanisms
- Monitor network connections
- Detect authentication anomalies
- Support incident response and threat hunting
- Map detections to the MITRE ATT&CK Framework

---

# Detection Queries

| Query | Description | Primary Log Source |
|------|-------------|--------------------|
| Process-Creation.spl | Detect process creation events | Sysmon Event ID 1 |
| Network-Connections.spl | Detect outbound network connections | Sysmon Event ID 3 |
| PowerShell-Execution.spl | Detect PowerShell execution | Sysmon Event ID 1 |
| Encoded-PowerShell.spl | Detect Base64 encoded PowerShell commands | Sysmon Event ID 1 |
| Registry-Persistence.spl | Detect registry modifications for persistence | Sysmon Event ID 13 |
| Scheduled-Tasks.spl | Detect scheduled task creation | Security Event ID 4698 |
| Services-Creation.spl | Detect Windows service creation | System Event ID 7045 |
| Remote-Desktop.spl | Detect Remote Desktop logons | Security Event ID 4624 |
| Failed-Logons.spl | Detect failed authentication attempts | Security Event ID 4625 |
| Suspicious-Parent-Child.spl | Detect suspicious parent-child process relationships | Sysmon Event ID 1 |
| Living-Off-The-Land.spl | Detect execution of LOLBins | Sysmon Event ID 1 |
| Credential-Access.spl | Detect potential credential dumping activity | Sysmon Event ID 10 |

---

# Query Structure

Each query is designed to include:

- Detection Objective
- Data Source
- SPL Search Query
- Relevant Event IDs
- Investigation Fields
- Expected Results

---

# Data Sources

- Sysmon Operational Log
- Windows Security Log
- Windows System Log
- PowerShell Operational Log

---

# Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer
- Windows 11

---

# MITRE ATT&CK Coverage

These SPL queries detect techniques across multiple ATT&CK tactics, including:

- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Command and Control

---

These queries are intended for educational purposes and demonstrate practical SOC analyst skills, including threat detection, investigation, and log analysis using Splunk.
