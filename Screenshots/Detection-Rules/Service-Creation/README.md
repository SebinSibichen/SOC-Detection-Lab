# Service Creation — Screenshots

This directory contains screenshots documenting the complete Service Creation detection workflow in the SOC lab.

The screenshots demonstrate the creation of a Windows service, verification of the service, Splunk detection, and investigation of the resulting Sysmon event.

---

## Screenshot 01 — Service Created

**Filename:**

```text
01-Service-Created.png
```

### Description

Shows the creation of the test Windows service using `sc.exe`.

The service created for the lab is:

```text
SOC_Lab_Service
```

The service is configured to use:

```text
C:\Windows\System32\notepad.exe
```

### Purpose

Demonstrates the initial service creation activity that generates security telemetry.

---

## Screenshot 02 — Service Creation Status

**Filename:**

```text
02-Service-Creation-status.png
```

### Description

Shows the status of `SOC_Lab_Service` after creation.

### Purpose

Confirms that the Windows Service Control Manager recognizes the newly created service.

---

## Screenshot 03 — Service Creation Detection

**Filename:**

```text
03-Service-Creation-Detection.png
```

### Description

Shows the Splunk SPL detection query used to identify Windows service creation activity.

The detection searches for:

```text
sc.exe
```

combined with:

```text
create
```

### Purpose

Demonstrates the detection logic used by the SOC monitoring system.

---

## Screenshot 04 — Splunk Service Creation Detection

**Filename:**

```text
04-Splunk-Service-Creation-Detection.png
```

### Description

Shows the resulting service creation event returned by Splunk.

The event contains process creation information associated with:

```text
C:\Windows\System32\sc.exe
```

### Purpose

Demonstrates successful ingestion and detection of the simulated activity in Splunk.

---

## Screenshot 05 — Expanded Service Event

**Filename:**

```text
05-Expanded-Service-Event.png
```

### Description

Shows the expanded Sysmon event in Splunk with detailed process information.

Important evidence includes:

```text
Image:
C:\Windows\System32\sc.exe
```

```text
CommandLine:
"C:\Windows\system32\sc.exe" create SOC_Lab_Service binPath= C:\Windows\System32\notepad.exe start= auto
```

```text
User:
TARGETMACHINE\a4803
```

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Purpose

Provides detailed evidence for SOC investigation and incident documentation.

---

## Evidence Flow

The screenshots demonstrate the following workflow:

```text
Service Creation
       ↓
Service Status Verification
       ↓
Sysmon Process Creation Event
       ↓
Splunk Detection
       ↓
Expanded Event Investigation
```

---

## MITRE ATT&CK

The simulated behavior is mapped to:

```text
T1543.003
Create or Modify System Process: Windows Service
```

## Lab Classification

```text
Benign Controlled Simulation
```
