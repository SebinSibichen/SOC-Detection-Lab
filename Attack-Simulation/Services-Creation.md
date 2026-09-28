# Service Creation Attack Simulation

## Objective

Simulate Windows service creation using `sc.exe` to generate Sysmon Process Creation telemetry for SOC detection and investigation.

This is a controlled and benign lab simulation. The service uses `notepad.exe` as its executable and is not intended to perform malicious activity.

---

## Lab Environment

* **Target:** Windows 11
* **Monitoring:** Splunk Enterprise
* **Telemetry:** Sysmon
* **Forwarder:** Splunk Universal Forwarder
* **Technique:** Windows Service Creation
* **Service Name:** `SOC_Lab_Service`
* **Executable:** `C:\Windows\System32\notepad.exe`

---

## Step 1 — Create the Service

Open PowerShell as Administrator and execute:

```powershell
sc.exe create SOC_Lab_Service binPath= "C:\Windows\System32\notepad.exe" start= auto
```

Expected result:

```text
[SC] CreateService SUCCESS
```

This creates a Windows service named:

```text
SOC_Lab_Service
```

The service is configured to use:

```text
C:\Windows\System32\notepad.exe
```

---

## Step 2 — Verify the Service

Run:

```powershell
sc.exe query SOC_Lab_Service
```

The service should appear in the Service Control Manager.

The lab screenshot records the service creation status and configuration.

---

## Step 3 — Generate Sysmon Telemetry

The service creation command generates a Sysmon Process Creation event.

Important fields include:

```text
EventCode: 1
Image: C:\Windows\System32\sc.exe
User: TARGETMACHINE\a4803
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The command line contains:

```text
sc.exe create SOC_Lab_Service
```

---

## Step 4 — Verify the Event in Splunk

Search Splunk for:

```spl
index=main EventCode=1 "SOC_Lab_Service"
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

The expected event should contain:

```text
Image: C:\Windows\System32\sc.exe
CommandLine: ... create SOC_Lab_Service ...
ParentImage: ...powershell.exe
```

---

## Step 5 — Cleanup

After completing the detection test, remove the lab service:

```powershell
sc.exe delete SOC_Lab_Service
```

Verify that it has been removed:

```powershell
sc.exe query SOC_Lab_Service
```

Expected result:

```text
[SC] OpenService FAILED 1060
```

This indicates that the service no longer exists.

---

## Security Relevance

Attackers can create or modify Windows services to establish persistence or execute programs with elevated privileges.

A SOC analyst can investigate:

* Which user created the service
* Which process created it
* The service executable/path
* The parent process
* The command line
* The creation time
* Whether the service is legitimate
* Whether the executable is suspicious

This lab demonstrates how Sysmon process telemetry can be used to detect service creation activity.
