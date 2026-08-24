# Network Connection Detection

## Overview

This detection identifies and investigates network connections generated
from the Windows endpoint using Sysmon Event ID 3 and Splunk Enterprise.

The detection is designed to demonstrate how a SOC analyst can identify
network connections, investigate destination IP addresses and ports, and
analyze the associated process responsible for the connection.

---

## Objective

The objectives of this detection are to:

- Monitor Windows network connection activity.
- Detect Sysmon Event ID 3 network connection events.
- Identify source and destination IP addresses.
- Identify destination ports and network protocols.
- Determine the process responsible for the connection.
- Investigate connections to specific hosts and ports.
- Demonstrate network telemetry analysis using Splunk.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Windows Target | Windows VM |
| Attacker/Test Machine | Kali Linux VM |
| Kali IP Address | 192.168.189.133 |
| Test Port | 8080 |
| Log Source | Sysmon |
| Event ID | 3 - Network Connection |
| Log Forwarder | Splunk Universal Forwarder |
| SIEM | Splunk Enterprise |
| Index | main |

---

## Detection Scenario

A controlled network connection was generated from the Windows VM
to the Kali Linux VM.

The Kali Linux machine hosted a temporary Python HTTP server on
TCP port 8080.

The Windows VM then generated an HTTP request to:

    http://192.168.189.133:8080

The network activity was monitored using Sysmon.

Sysmon recorded the connection as Event ID 3, which was forwarded
to Splunk Enterprise through the Splunk Universal Forwarder.

---

## Detection Flow

```text
Windows VM
    |
    | Network Connection
    v
Kali Linux
192.168.189.133:8080
    |
    | Sysmon Event ID 3
    v
Windows Event Log
    |
    | Splunk Universal Forwarder
    v
Splunk Enterprise
    |
    | SPL Query
    v
Network Connection Detection
