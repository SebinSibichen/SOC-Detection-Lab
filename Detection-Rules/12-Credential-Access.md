# DET-012 — Credential Access Enumeration

## Rule Overview

| Field            | Value                                     |
| ---------------- | ----------------------------------------- |
| Rule ID          | DET-012                                   |
| Rule Name        | Windows Credential Store Enumeration      |
| Category         | Credential Access                         |
| Initial Severity | Medium — investigate and validate context |
| Data Source      | Sysmon Operational                        |
| Event ID         | 1 — Process Create                        |
| Platform         | Windows                                   |
| Status           | Validated for the observed VaultCmd event |

## Objective

Identify executions of `cmdkey.exe` and `vaultcmd.exe` that may indicate credential-store enumeration and warrant further investigation.

## Detection Logic

Monitor Sysmon Process Create events for:

* `cmdkey.exe`
* `vaultcmd.exe`

Capture the executable path, command line, parent process, user, host, and event timestamp.

## Observed Evidence

The validated event contained:

* Process: `VaultCmd.exe`
* Command: `/list`
* Parent: `powershell.exe`
* Host: `TargetMachine`
* Event ID: 1
* Record Number: `80057`

## Investigation Guidance

When an event is detected:

1. Review the complete command line.
2. Identify the parent process and the process that launched it.
3. Confirm the user and host involved.
4. Check whether the activity aligns with an approved administrative task.
5. Correlate with other available telemetry before determining whether the activity is suspicious.
6. Escalate for further investigation if additional evidence suggests unauthorized credential access.

## False Positives

Legitimate administrative troubleshooting, credential management, and system maintenance may execute these utilities.

## Limitations

This rule identifies selected process executions. It does not independently prove that credentials were extracted, disclosed, or misused.

It does not detect every possible credential-access technique.

## Validation Status

**Validated:** The supplied evidence confirms that `VaultCmd.exe /list` was recorded by Sysmon and returned by the Splunk hunting query.

**Not established:** Malicious intent, credential extraction, or compromise.
