# MITRE ATT&CK Mapping

This directory maps the detection rules implemented in the SOC Detection Lab to the MITRE ATT&CK Framework.

The MITRE ATT&CK Framework is a globally recognized knowledge base of adversary tactics and techniques based on real-world observations. It helps security analysts understand attacker behavior and develop effective detection and response strategies.

---

## Objectives

- Map detection rules to MITRE ATT&CK techniques.
- Understand attacker tactics and techniques.
- Improve detection engineering skills.
- Support threat hunting and incident response.
- Provide a standardized framework for security investigations.

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Technique | Detection Rule |
|--------------|-----------|----------------|
| T1003 | Credential Access | Credential Access |
| T1021 | Remote Services | Remote Desktop |
| T1053 | Scheduled Task | Scheduled Tasks |
| T1059 | Command and Scripting Interpreter | Process Creation / PowerShell |
| T1071 | Application Layer Protocol | Network Connections |
| T1110 | Brute Force | Failed Logons |
| T1112 | Registry Modification | Registry Persistence |
| T1204 | User Execution | Suspicious Parent-Child |
| T1218 | Signed Binary Proxy Execution | Living-Off-The-Land |
| T1543 | Create or Modify System Process | Service Creation |
| T1547 | Boot or Logon Autostart Execution | Registry Persistence |

---

## Document Structure

Each technique document includes:

- Technique Overview
- MITRE ATT&CK Tactic
- Description
- Detection Rule
- Relevant Windows Event IDs
- Relevant Sysmon Event IDs
- Detection Logic
- Investigation Guidance
- References

---

## References

- https://attack.mitre.org/
- https://attack.mitre.org/matrices/enterprise/

---

This mapping demonstrates how the detection rules implemented in this project align with industry-standard adversary techniques and defensive strategies.
