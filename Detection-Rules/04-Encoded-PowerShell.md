# Detection Rule 04 - PowerShell Encoded Command

## Detection Name

**Suspicious PowerShell Encoded Command Execution**

---

## Event Source

Sysmon

## Event ID

**Event ID 1 – Process Creation**

---

## Description

Detects PowerShell processes using the `-EncodedCommand`, `-Encoded`, or `-enc` parameters.

Encoded PowerShell commands can be used to obscure the actual command being executed, making this useful for identifying potentially suspicious PowerShell activity.

---

## SPL Query

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| regex CommandLine="(?i)(-encodedcommand|-encoded|-enc)(\s|$)"
| where NOT match(Image,"(?i).*SplunkUniversalForwarder.*")
| table _time ComputerName User Image ParentImage CommandLine ProcessId ProcessGuid
| sort - _time
```

---

## Alternative Simple SPL

If the regex query does not return results, use:

```spl
index=main EventCode=1
| search Image="*\\powershell.exe"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-enc *"
| where NOT like(Image,"%SplunkUniversalForwarder%")
| table _time ComputerName User Image ParentImage CommandLine
| sort - _time
```

---

## Expected Detection

The result should show a PowerShell process similar to:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

and:

```text
CommandLine:
powershell.exe -NoProfile -EncodedCommand <Base64>
```

---

## Why the Splunk Universal Forwarder Is Excluded

The Splunk Universal Forwarder may generate its own PowerShell-related process events.

The following filter prevents those normal Splunk processes from creating false positives:

```spl
| where NOT match(Image,"(?i).*SplunkUniversalForwarder.*")
```

---

## Severity

**Medium**

Increase severity when encoded PowerShell is combined with:

* Network connections
* Suspicious parent processes
* Download commands
* Credential access
* Persistence
* Obfuscated commands

---

## MITRE ATT&CK

**T1059.001 – PowerShell**

---

## Detection Objective

Identify PowerShell execution where the command-line arguments indicate that the command has been encoded or obfuscated.
