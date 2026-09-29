# SOC Incident Report — Service Creation

## Incident ID

`SOC-IR-007`

## Detection ID

`SOC-DET-007`

## Incident Type

Windows Service Creation

## Severity

Medium

## Status

Closed — Lab Simulation

---

## 1. Executive Summary

A Windows service creation event was detected on the monitored Windows 11 host.

The activity was generated as part of a controlled SOC detection lab using `sc.exe`. The service was named `SOC_Lab_Service` and was configured to execute `notepad.exe`.

Sysmon recorded the activity as a Process Creation event and forwarded the telemetry to Splunk for detection and investigation.

The activity was confirmed to be a benign lab simulation.

---

## 2. Affected Host

**Hostname:**

```text
TargetMachine
```

**User:**

```text
TARGETMACHINE\a4803
```

---

## 3. Observed Process

**Process:**

```text
C:\Windows\System32\sc.exe
```

**Parent Process:**

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## 4. Observed Command Line

```text
"C:\Windows\system32\sc.exe" create SOC_Lab_Service binPath= C:\Windows\System32\notepad.exe start= auto
```

---

## 5. Detection Source

**Data Source:**

Sysmon

**Event ID:**

```text
1 — Process Create
```

**Splunk Source:**

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

---

## 6. MITRE ATT&CK Mapping

**Technique:**

`T1543.003 — Create or Modify System Process: Windows Service`

The technique describes the creation or modification of Windows services that can be used for execution or persistence.

---

## 7. Investigation

The SOC detection identified `sc.exe` executing a `create` operation.

The following evidence was reviewed:

* Executable path
* Command line
* User account
* Parent process
* Hostname
* Sysmon Event ID
* Splunk event telemetry

The parent process was identified as PowerShell.

The created service used:

```text
C:\Windows\System32\notepad.exe
```

---

## 8. Analyst Assessment

The event was determined to be a **controlled and authorized laboratory simulation**.

No malicious payload was used.

The service was created specifically to generate telemetry and validate the Splunk detection rule.

---

## 9. Response

The following actions were performed:

1. Confirmed the service creation event.
2. Verified Sysmon telemetry.
3. Confirmed ingestion into Splunk.
4. Investigated the process and parent process.
5. Mapped the activity to MITRE ATT&CK.
6. Documented the detection.
7. Removed the test service after testing.

---

## 10. Cleanup

The test service can be removed using:

```powershell
sc.exe delete SOC_Lab_Service
```

---

## 11. Conclusion

The SOC lab successfully detected Windows service creation activity using Sysmon Process Creation telemetry and a Splunk SPL detection query.

The investigation demonstrated how a SOC analyst can correlate:

```text
User → Process → Parent Process → Command Line → Service Creation
```

to investigate potentially suspicious service activity.
