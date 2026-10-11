# Module 11: Living Off the Land Binaries (LOLBins) — Screenshots

This directory contains screenshots documenting the LOLBins detection lab, including executable availability, Splunk hunting queries, detected process events, and expanded event details.

## Screenshot Evidence

### 1. `01-LOLBins-Executable-Availability.png`

**Description:** Shows the availability of LOLBins executables on the Windows target machine, including `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `regsvr32.exe`, and `rundll32.exe`.

**Purpose:** Confirms that the selected Windows utilities are available for process monitoring and detection testing.

### 2. `02-Splunk-LOLBins-Hunting-Query.png`

**Description:** Shows the Splunk SPL query used to search Sysmon Process Creation events for the selected LOLBins executables.

**Purpose:** Documents the initial hunting query used to identify executions of these utilities.

### 3. `03-Splunk-LOLBins-Hunting-Events.png`

**Description:** Shows the events returned by the LOLBins hunting query in Splunk, including the process image, command line, parent process, timestamp, and user where available.

**Purpose:** Demonstrates that Sysmon process-creation telemetry is being ingested into Splunk and can be searched for LOLBins activity.

### 4. `04-Splunk-LOLBins-Hunting-Expanded-Events.png`

**Description:** Shows the expanded details of a selected LOLBins process-creation event, including the executable path, command line, parent process, host, and other available event fields.

**Purpose:** Supports investigation by providing detailed context about the process execution.

## Validation Summary

* **Sysmon telemetry:** Process-creation events were observed on the Windows target.
* **Splunk ingestion:** LOLBins-related process events were searchable in Splunk.
* **Observed test:** `certutil.exe -?` was executed as a benign help test.
* **Detection status:** Broad LOLBins hunting was validated. Detection of suspicious LOLBins command-line behavior requires further testing.

> **Note:** The observed `certutil.exe -?` event is benign and does not, by itself, indicate malicious activity or a confirmed security incident.
