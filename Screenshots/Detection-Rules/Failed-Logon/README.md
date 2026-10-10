# Failed Logon Detection - Screenshots

This directory contains evidence of Windows Security Event ID 4625 generation, Splunk ingestion, and event investigation.

## Screenshot 01 - PowerShell Event

**Filename:** `01-Failed-Logon-PowerShell-Event.png`

Shows PowerShell output from the Windows Security event query.

**Purpose:** Demonstrates that Windows recorded Event ID 4625.

## Screenshot 02 - Splunk Search Query

**Filename:** `02-Failed-Logon-Splunk-Query.png`

Shows the SPL query used to search for Event ID 4625.

**Purpose:** Documents the detection query used in Splunk.

## Screenshot 03 - Splunk Search Results

**Filename:** `03-Failed-Logon-Splunk-Results.png`

Shows Splunk returning five events for the failed-logon search.

**Purpose:** Demonstrates that failed-logon telemetry is being ingested and searched in the SIEM.

## Screenshot 04 - Expanded Event

**Filename:** `04-Failed-Logon-Expanded-Event.png`

Shows the expanded Windows Security event, including authentication and process details.

The visible fields include:

* Event description
* Logon Type
* Account information
* Failure Reason
* Status and Sub Status
* Caller Process Name
* Source Network Address
* Authentication Package

**Purpose:** Provides detailed evidence for SOC investigation.

## Evidence Summary

| Screenshot | Evidence                      |
| ---------- | ----------------------------- |
| 01         | Windows Event ID 4625         |
| 02         | Splunk SPL search             |
| 03         | Failed-logon search results   |
| 04         | Expanded authentication event |

## Important Observation

The expanded event records Logon Type 2 and source address 127.0.0.1. These details indicate a local interactive logon failure rather than confirmed RDP activity.

The screenshots demonstrate failed-logon monitoring and investigation. They do not, by themselves, prove a brute-force attack.

## Result

Windows failed-logon telemetry was successfully collected and displayed in Splunk, providing evidence of a working authentication-monitoring workflow.
