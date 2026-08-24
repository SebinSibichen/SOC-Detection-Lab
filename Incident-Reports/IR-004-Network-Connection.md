# Incident Report - Network Connection Detection

## Incident Information

| Field | Details |
|---|---|
| Incident ID | INC-001 |
| Incident Type | Network Connection |
| Severity | Low |
| Status | Closed - Lab Simulation |
| Detection Source | Sysmon Event ID 3 |
| SIEM | Splunk Enterprise |
| Affected Host | Windows Target VM |
| Destination Host | Kali Linux VM |
| Destination IP | 192.168.189.133 |
| Destination Port | 8080 |
| Protocol | TCP/HTTP |
| Environment | Isolated SOC Detection Lab |

---

# 1. Executive Summary

A network connection from the Windows Target VM to the Kali Linux VM
was detected using Sysmon Event ID 3 and analyzed in Splunk Enterprise.

The connection was generated intentionally as part of a controlled SOC
detection lab exercise. Kali Linux hosted a temporary Python HTTP server
on TCP port 8080, and the Windows VM generated an HTTP request to the
server.

The resulting network activity was recorded by Sysmon and forwarded to
Splunk using the Splunk Universal Forwarder.

The activity was confirmed to be authorized laboratory traffic and was
therefore classified as benign.

---

# 2. Detection

The activity was detected using Sysmon Event ID 3, which records
network connections initiated by processes on the Windows endpoint.

### Detection Query

```spl
index=main EventCode=3

### The following query was used to investigate the specific connection

```spl

index=main EventCode=3 DestinationIp="192.168.189.133"
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol User
| sort - _time
