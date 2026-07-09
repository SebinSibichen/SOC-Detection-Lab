# Attack Simulation

This directory documents the attack simulation techniques used to generate security events for the SOC Detection Lab.

The purpose of these simulations is to safely create Windows and Sysmon events that can be collected by Splunk, allowing detection rules and SPL queries to be tested in a controlled lab environment.

---

## Objectives

- Generate realistic security events
- Validate detection rules
- Test SPL queries
- Practice incident investigation
- Improve threat hunting skills

---

## Simulated Techniques

| Simulation | Purpose |
|------------|---------|
| Process Creation | Generate Sysmon Event ID 1 |
| Network Connections | Generate Sysmon Event ID 3 |
| PowerShell Execution | Detect PowerShell usage |
| Encoded PowerShell | Detect obfuscated commands |
| Registry Persistence | Detect registry modifications |
| Scheduled Tasks | Detect persistence via Task Scheduler |
| Service Creation | Detect new Windows services |
| Remote Desktop | Detect RDP logons |
| Failed Logons | Detect brute-force attempts |
| Living-Off-The-Land | Detect LOLBins |
| Credential Access | Detect LSASS access attempts |

---

> **Note:** All simulations were performed in an isolated lab environment for educational purposes only.
