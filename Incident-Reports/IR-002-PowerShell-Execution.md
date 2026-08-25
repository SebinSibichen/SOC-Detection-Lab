# Incident Report - PowerShell Execution

## Incident Information

| Field            | Details                 |
| ---------------- | ----------------------- |
| Incident ID      | INC-002                 |
| Incident Type    | PowerShell Execution    |
| Severity         | Low                     |
| Status           | Closed - Lab Simulation |
| Detection Source | Sysmon Event ID 1       |
| SIEM             | Splunk Enterprise       |
| Affected Host    | Windows Target VM       |
| User             | TARGETMACHINE\a4803     |
| MITRE Technique  | T1059.001 - PowerShell  |

---

# 1. Executive Summary

A PowerShell execution event was detected on the Windows Target VM using
Sysmon Event ID 1 and Splunk Enterprise.

The PowerShell process was intentionally executed as part of the SOC
Detection Lab to test the PowerShell detection capability.

The resulting Sysmon telemetry was forwarded to Splunk Universal
Forwarder and successfully identified using an SPL detection query.

The activity was confirmed to be authorized laboratory activity.

---

# 2. Detection

The event was detected using Sysmon Event ID 1:

```text
Process Create
```

The primary detection query was:

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

---

# 3. Simulated Activity

The following command was executed on the Windows Target VM:

```powershell
powershell.exe -Command "Write-Host 'SOC_POWERSHELL_TEST'"
```

Additional PowerShell activity was generated using:

```powershell
powershell.exe -Command "Get-Process | Select-Object -First 5"
```

The commands were benign and were used only to generate detection
telemetry.

---

# 4. Investigation

The following fields were reviewed:

### User

```text
TARGETMACHINE\a4803
```

### Image

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Parent Process

The parent process was reviewed to determine how PowerShell was
launched.

### Command Line

The command line was reviewed to determine what PowerShell was instructed
to execute.

### Timestamp

The event timestamp was reviewed to correlate the activity with the
laboratory test.

---

# 5. MITRE ATT&CK

The observed behavior maps to:

**T1059.001 - Command and Scripting Interpreter: PowerShell**

**Tactic:** Execution

PowerShell is commonly used for legitimate administration as well as
potential attacker command and script execution.

---

# 6. Severity Assessment

### Severity: Low

The event was classified as Low severity because:

* The PowerShell activity was intentionally generated.
* The Windows VM is part of the controlled SOC laboratory.
* No unauthorized activity was identified.
* The commands were benign test commands.
* The purpose was detection validation.

---

# 7. Response Actions

The following actions were performed:

1. Reviewed the PowerShell process-creation event.
2. Identified the executing user.
3. Reviewed the PowerShell executable path.
4. Reviewed the parent process.
5. Reviewed the command line.
6. Confirmed the activity was part of the authorized laboratory test.
7. Classified the event as benign.
8. Closed the simulated incident.

---

# 8. Evidence

Evidence is stored in:

```text
Screenshots/PowerShell/
```

Evidence includes:

* PowerShell execution
* Splunk detection query
* PowerShell detection results
* Expanded PowerShell event

---

# 9. Analyst Conclusion

The PowerShell execution was successfully detected using Sysmon Event ID
1 and Splunk Enterprise.

The investigation confirmed that the activity was intentionally
generated as part of the SOC Detection Lab.

No additional response actions were required.

**Final Classification:** Benign / Authorized Lab Activity

**Final Status:** Closed

**Severity:** Low
