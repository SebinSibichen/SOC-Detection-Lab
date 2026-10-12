# Module 12 — Credential Access Screenshots

This directory contains evidence from the Windows credential-store enumeration lab and its validation in Splunk.

## Screenshot Evidence

### 1. `01-Credential-Access-status.png`

**Description:** PowerShell output showing the execution of `cmdkey /list` and `vaultcmd /list`, followed by a local Sysmon event query.

**Purpose:** Documents the lab commands and the local process-creation evidence.

**Privacy note:** Redact email addresses, credential target names, and other account-related information before publishing this screenshot publicly.

### 2. `02-Credential-Access-Splunk-Query.png`

**Description:** The SPL hunting query used to identify `cmdkey.exe` and `vaultcmd.exe` executions in Sysmon Process Create events.

**Purpose:** Documents the search logic used for credential-store enumeration hunting.

### 3. `03-Credential-Access-Splunk-Events.png`

**Description:** Splunk search results containing one matching `VaultCmd.exe` event.

**Purpose:** Demonstrates successful ingestion and search of the observed VaultCmd process-creation event.

### 4. `04-Credential-Access-Splunk-Expanded-Events.png`

**Description:** Expanded Sysmon event details, including the executable path, command line, parent process, event record number, and timestamp.

**Purpose:** Provides supporting evidence for the analyst's investigation and event validation.

## Validation Summary

* Local Sysmon Process Create events observed.
* VaultCmd event returned by Splunk.
* Credential enumeration hunting query validated against the supplied event.
* No confirmed credential extraction or compromise demonstrated.

## Final Status

**Telemetry and hunting validation successful.**

The screenshots document benign lab activity. They must not be presented as proof of a confirmed credential-theft incident.
