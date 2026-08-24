# Network Connection Attack Simulation

## Overview

This document describes the controlled network activity used to generate
network connection telemetry for the SOC Detection Lab.

The simulation uses a Windows Target VM and a Kali Linux VM. Kali hosts
a temporary HTTP server, and the Windows VM connects to it. This generates
network activity that can be monitored using Sysmon Event ID 3 and analyzed
in Splunk Enterprise.

This is a controlled lab simulation performed within isolated virtual
machines.

---

## Objective

The objectives of this simulation are to:

- Generate controlled network connection activity.
- Simulate communication between a Windows endpoint and a Linux system.
- Generate Sysmon Event ID 3 telemetry.
- Verify that the network activity is forwarded to Splunk.
- Validate the Network Connection Detection rule.
- Practice SOC investigation of network connections.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Windows VM | Target / Log Source |
| Kali Linux VM | Test / HTTP Server |
| Windows IP | 192.168.189.134 |
| Kali IP | 192.168.189.133 |
| Protocol | HTTP |
| Destination Port | 8080 |
| Telemetry | Sysmon Event ID 3 |
| Log Forwarder | Splunk Universal Forwarder |
| SIEM | Splunk Enterprise |

---

# Attack Simulation Scenario

The simulation follows this process:

```text
Kali Linux
192.168.189.133
     |
     | HTTP Server :8080
     |
     v
Windows VM
192.168.189.134
     |
     | HTTP Request
     v
Kali Linux
     |
     v
Sysmon Event ID 3
     |
     v
Splunk Universal Forwarder
     |
     v
Splunk Enterprise
