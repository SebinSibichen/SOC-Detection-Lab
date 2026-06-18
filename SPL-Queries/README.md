# SPL Queries

This folder contains Splunk Processing Language (SPL) queries developed for the SOC Detection Lab.

## Objectives

* Detect suspicious activity
* Identify failed authentication attempts
* Monitor PowerShell execution
* Investigate process creation events
* Support incident response and threat hunting

## Planned Detection Use Cases

* Failed Login Detection (Event ID 4625)
* Successful Login Monitoring (Event ID 4624)
* PowerShell Abuse Detection (Event ID 4104)
* Process Creation Monitoring (Sysmon Event ID 1)
* Network Connection Monitoring (Sysmon Event ID 3)
* Log Clearing Detection (Event ID 1102)
* Service Installation Detection (Event ID 7045)

Each detection will include:

* SPL Query
* Detection Logic
* MITRE ATT&CK Mapping
* Investigation Guidance
