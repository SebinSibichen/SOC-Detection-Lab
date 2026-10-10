# Attack Simulation 10 — Suspicious Parent-Child Process

## Objective

Validate Windows process-creation telemetry and investigate potentially suspicious parent-child process relationships using Sysmon and Splunk.

## Environment

* Target: Windows 11 VM
* SIEM: Splunk Enterprise
* Log collector: Splunk Universal Forwarder
* Telemetry: Sysmon Event ID 1 — Process Creation
* Index: `main`

## Test 1: Generate a benign process relationship

Open PowerShell on the Windows 11 VM and execute:

```powershell
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami"
```

This launches Command Prompt from PowerShell and executes `whoami` to display the current account.

## Test 2: Verify the event in Splunk

Run:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*cmd.exe"
| table _time ComputerName User ParentImage Image CommandLine
| sort - _time
```

Expected behavior: If Sysmon records the process creation and the event reaches Splunk, the results should show the child process and its parent.

## Test 3: Investigate suspicious relationships

Search for Office applications launching scripting engines or command interpreters.

Examples that may warrant investigation include:

* `winword.exe` → `powershell.exe`
* `excel.exe` → `cmd.exe`
* `outlook.exe` → `wscript.exe`

These are investigation leads, not proof of malicious activity.

## Evidence Requirements

* Capture the PowerShell test command.
* Capture the process-creation event in Splunk.
* Capture the parent and child executable paths.
* Record the actual query result, including zero-result outcomes where applicable.

## Cleanup

The test command runs `whoami` and does not create a persistent account, service, scheduled task, or registry entry.

## Conclusion

This simulation validates process-creation monitoring. The Office-to-script detection should be considered validated only after a matching event is observed or a separate controlled test demonstrates the detection logic.
