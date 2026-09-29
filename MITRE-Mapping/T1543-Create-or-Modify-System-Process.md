# MITRE ATT&CK Mapping — Service Creation

## Technique

**T1543.003 — Create or Modify System Process: Windows Service**

## Tactic

**Persistence**

## Secondary Relevance

**Privilege Escalation**

## Observed Behavior

The lab generated a Windows service creation command:

```text
sc.exe create SOC_Lab_Service
```

The executable used for the service was:

```text
C:\Windows\System32\notepad.exe
```

The process responsible for the service creation was:

```text
C:\Windows\System32\sc.exe
```

The parent process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

## Telemetry

Sysmon:

```text
Event ID 1 — Process Creation
```

Splunk fields:

```text
Image
CommandLine
ParentImage
ParentCommandLine
User
ComputerName
```

## Detection Relationship

The SOC detection searches for:

```text
sc.exe
+
create
```

This identifies process activity associated with Windows service creation.

## Investigation Considerations

A real-world alert should be investigated by checking:

* Service name
* Service executable
* Service account
* Creating user
* Parent process
* Command line
* Creation time
* File reputation
* Whether the service is expected
* Related activity before and after service creation

## Lab Classification

**Benign — Controlled SOC Lab Simulation**
