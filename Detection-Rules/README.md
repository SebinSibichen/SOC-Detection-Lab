# 🛡️ Detection Rules

This directory contains detection use cases developed for the SOC Detection Lab using Windows Event Logs, Sysmon, and Splunk.

Each detection rule is designed to identify suspicious or malicious behavior commonly observed during cyber attacks.

---

# Objectives

- Detect malicious process execution
- Monitor PowerShell abuse
- Identify persistence mechanisms
- Detect credential access attempts
- Monitor lateral movement
- Identify Living-off-the-Land (LOLBins) techniques
- Improve threat hunting skills
- Practice SOC investigation workflow

---

# Detection Rules Included

| Rule | Description | Primary Event |
|------|-------------|---------------|
| 01 | Process Creation | Sysmon Event ID 1 |
| 02 | Network Connections | Sysmon Event ID 3 |
| 03 | PowerShell Execution | Sysmon Event ID 1 / PowerShell Logs |
| 04 | Encoded PowerShell | Sysmon Event ID 1 |
| 05 | Registry Persistence | Sysmon Event ID 13 |
| 06 | Scheduled Tasks | Security Event 4698 |
| 07 | Service Creation | Security Event 7045 |
| 08 | Remote Desktop Activity | Security Event 4624 |
| 09 | Failed Logons | Security Event 4625 |
| 10 | Suspicious Parent-Child Processes | Sysmon Event ID 1 |
| 11 | Living-Off-The-Land Binaries (LOLBins) | Sysmon Event ID 1 |
| 12 | Credential Access Detection | Sysmon Event ID 10 |

---

# Standard Detection Rule Format

Each rule contains:

- Overview
- Why it matters
- Event IDs used
- Required log source
- SPL Query
- Detection Logic
- MITRE ATT&CK Mapping
- Investigation Steps
- False Positives
- References

---

# Log Sources

- Sysmon
- Windows Security Logs
- PowerShell Operational Logs
- Windows System Logs

---

# Tools Used

- Splunk Enterprise
- Sysmon
- Windows Event Viewer
- Windows 11
- Kali Linux

---

# MITRE ATT&CK Coverage

These rules cover techniques including:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Command and Control

---

This repository is intended for educational purposes and SOC analyst training.
