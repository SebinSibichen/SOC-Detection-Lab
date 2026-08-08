# Configuration

This folder documents the configuration required to collect Windows endpoint telemetry into Splunk.

## Contents

* Sysmon installation and verification
* Sysmon Event Viewer verification
* Splunk Universal Forwarder configuration
* `inputs.conf` configuration
* Splunk receiving port (`9997`) configuration
* Windows Event Log verification

## Purpose

These screenshots document the configuration of the Windows target VM and Splunk logging pipeline.

They demonstrate that:

1. Sysmon is installed and generating events.
2. Windows Security and Sysmon logs are enabled for collection.
3. The Splunk Universal Forwarder service is running.
4. The `inputs.conf` file is configured to collect Windows telemetry.
5. Splunk Enterprise is listening on receiving port `9997`.

These configurations establish the logging pipeline required for monitoring and analyzing security events during the attack simulation phase of the SOC lab.
