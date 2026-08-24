# Network Connection Detection - Screenshots

This directory contains screenshots documenting the testing and validation
of the Network Connection Detection rule using Sysmon Event ID 3 and
Splunk Enterprise.

The screenshots demonstrate the complete workflow from generating a
controlled network connection between the Windows and Kali Linux virtual
machines to detecting and investigating the resulting network telemetry
in Splunk.

---

## Detection Scenario

A controlled HTTP connection was generated from the Windows Target VM
to the Kali Linux VM.

The Kali Linux VM hosted a temporary Python HTTP server on TCP port 8080.

### Lab Environment

| System | IP Address | Role |
|--------|------------|------|
| Windows VM | 192.168.189.134 | Target / Log Source |
| Kali Linux VM | 192.168.189.133 | Test / HTTP Server |

The Windows VM generated an HTTP request to:

    http://192.168.189.133:8080

The network connection was recorded by Sysmon as Event ID 3 and
forwarded to Splunk Enterprise through the Splunk Universal Forwarder.

---

# Screenshot Evidence

## 01 - Windows HTTP Request

**File:**

`01-Windows-HTTP-Request.png`

Shows the HTTP request generated from the Windows VM toward the
Kali Linux HTTP server.

Example command:

    Invoke-WebRequest http://192.168.189.133:8080

### Purpose

- Generates controlled network traffic.
- Creates a network connection that can be monitored by Sysmon.
- Demonstrates the Windows-to-Kali communication used for testing.

---

## 02 - Kali HTTP Request Received

**File:**

`02-Kali-HTTP-Request-Received.png`

Shows the Kali Linux HTTP server receiving the request from the
Windows VM.

A successful HTTP request is represented by an HTTP response such as:

    200 OK

### Purpose

- Confirms that the request successfully reached the Kali VM.
- Verifies the Windows-to-Kali network connection.
- Provides evidence for the controlled detection test.

---

## 03 - Splunk Network Connections

**File:**

`03-Splunk-Network-Connections.png`

Shows network connection events collected by Splunk from the Windows
endpoint.

The search is based on Sysmon Event ID 3.

Example SPL:

    index=main EventCode=3

Network connection events can contain fields such as:

- Source IP
- Source Port
- Destination IP
- Destination Port
- Protocol
- Process Image
- Computer Name
- User

### Purpose

- Confirms that Sysmon network connection telemetry is reaching Splunk.
- Demonstrates network activity analysis in Splunk.
- Provides the initial search results for the detection.

---

## 04 - Splunk Suspicious Port Detection

**File:**

`04-Splunk-Suspicious-Port-Detection.png`

Shows an investigation of network connections involving commonly
monitored destination ports.

Example SPL:

    index=main EventCode=3
    | where DestinationPort IN (21,22,23,25,53,80,110,135,139,143,443,445,3389,4444,8080)
    | stats count by Image, DestinationIp, DestinationPort, Protocol, User
    | sort - count

### Purpose

- Identifies connections involving ports that may require additional
  investigation.
- Demonstrates port-based network analysis.
- Helps a SOC analyst prioritize potentially interesting connections.

> A connection to a monitored port does not automatically indicate
> malicious activity. Additional investigation and context are required.

---

## 05 - Splunk Kali Connection Detection

**File:**

`05-Splunk-Kali-Connection-Detection.png`

Shows the specific network connection from the Windows endpoint to
the Kali Linux VM.

Example SPL:

    index=main EventCode=3 DestinationIp="192.168.189.133"
    | table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol User
    | sort - _time

### Purpose

- Identifies the Windows-to-Kali connection.
- Confirms the destination IP address.
- Identifies the destination port.
- Shows the process responsible for the connection.
- Demonstrates targeted investigation of a network event.

---

## 06 - Expanded Network Event

**File:**

`06-Expanded-Network-Event.png`

Shows the expanded Sysmon Event ID 3 event in Splunk.

Important fields available for investigation may include:

- `EventCode`
- `ComputerName`
- `Image`
- `SourceIp`
- `SourcePort`
- `DestinationIp`
- `DestinationPort`
- `Protocol`
- `User`

### Purpose

- Provides detailed evidence of the detected network connection.
- Allows investigation of the process and network endpoints involved.
- Demonstrates how a SOC analyst can examine the raw event details.

---

# Detection Workflow

The screenshots demonstrate the following workflow:

    Windows VM
        |
        | HTTP Request
        v
    Kali Linux :8080
        |
        | Network Connection
        v
    Sysmon Event ID 3
        |
        | Windows Event Log
        v
    Splunk Universal Forwarder
        |
        v
    Splunk Enterprise
        |
        | SPL Investigation
        v
    Network Connection Detection

---

# Evidence Summary

| Screenshot | Evidence |
|------------|----------|
| 01-Windows-HTTP-Request | Windows generates network traffic |
| 02-Kali-HTTP-Request-Received | Kali receives the HTTP request |
| 03-Splunk-Network-Connections | Network telemetry is available in Splunk |
| 04-Splunk-Suspicious-Port-Detection | Port-based network investigation |
| 05-Splunk-Kali-Connection-Detection | Windows-to-Kali connection identified |
| 06-Expanded-Network-Event | Detailed Sysmon network event investigation |

---

# Related Documentation

The detection logic and SPL queries used for this detection are documented
in:

    Detection-Rules/Network-Connection/network_connection.md

The screenshots in this directory provide visual evidence supporting
the Network Connection Detection rule.
