# PowerShell Execution Simulation

## Overview

This document describes the controlled PowerShell execution activity
performed on the Windows Target VM to generate security telemetry for
the SOC Detection Lab.

The activity was performed manually on the Windows VM. Kali Linux was
not required for this simulation because the objective was to generate
PowerShell process-execution telemetry.

---

## Objective

The objectives of this simulation are to:

* Generate a PowerShell process-creation event.
* Verify Sysmon Event ID 1 telemetry.
* Confirm that the event is forwarded to Splunk.
* Validate the PowerShell Execution detection rule.
* Practice investigating PowerShell activity in Splunk.

---

## Lab Environment

| Component                  | Role                              |
| -------------------------- | --------------------------------- |
| Windows Target VM          | PowerShell execution / log source |
| Splunk Universal Forwarder | Log forwarding                    |
| Splunk Enterprise          | SIEM / detection                  |
| Sysmon                     | Endpoint telemetry                |

---

## Step 1 - Open PowerShell

On the Windows Target VM, open PowerShell.

The PowerShell session was executed directly on the Windows test
machine.

---

## Step 2 - Generate PowerShell Activity

The following command was used to generate a controlled PowerShell
execution event:

```powershell
powershell.exe -Command "Write-Host 'SOC_POWERSHELL_TEST'"
```

The command produces the following output:

```text
SOC_POWERSHELL_TEST
```

A second controlled command was also used:

```powershell
powershell.exe -Command "Get-Process | Select-Object -First 5"
```

These commands are benign and were executed only to generate telemetry
for detection testing.

---

## Step 3 - Sysmon Telemetry

Sysmon monitors the process creation and records the execution as:

```text
Event ID: 1
Event Type: Process Create
```

Important fields include:

* Image
* CommandLine
* ParentImage
* User
* ComputerName
* Timestamp

The expected PowerShell image is:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## Step 4 - Splunk Verification

The generated event was searched for in Splunk using:

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

The event was successfully identified in Splunk.

---

## Expected Result

The expected detection flow is:

```text
PowerShell Command
       ↓
Windows Process Creation
       ↓
Sysmon Event ID 1
       ↓
Splunk Universal Forwarder
       ↓
Splunk Enterprise
       ↓
SPL Detection
       ↓
PowerShell Execution Detected
```

---

## Security Context

PowerShell is a legitimate Windows administration tool and its
execution does not automatically indicate malicious activity.

In this simulation, PowerShell execution was intentionally generated
and classified as authorized laboratory activity.

Additional command-line analysis is required to identify potentially
suspicious PowerShell behavior.

---

## Evidence

Evidence for this simulation is stored in:

```text
Screenshots/PowerShell/
```

The screenshots demonstrate:

* PowerShell execution
* Splunk detection query
* Detection results
* Expanded Sysmon event

---

## Conclusion

The PowerShell execution simulation successfully generated Sysmon
Event ID 1 telemetry.

The event was forwarded to Splunk and successfully detected using the
PowerShell Execution detection rule.
