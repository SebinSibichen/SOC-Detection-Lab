# MITRE ATT&CK Mapping - PowerShell Encoded Command

## Technique

**T1059.001 – PowerShell**

## Tactic

**Execution**

## Description

The detection monitors PowerShell process creation where the command line contains encoded-command parameters such as:

```text
-EncodedCommand
```

```text
-Encoded
```

```text
-enc
```

PowerShell is a legitimate Windows administration and scripting tool, but attackers can abuse it to execute commands while attempting to obscure their contents.

## Detection Evidence

The detection is based on:

* Sysmon Event ID 1
* `powershell.exe`
* PowerShell command-line arguments
* `CommandLine` containing encoded-command parameters

## Project Mapping

| Project Component | Mapping                               |
| ----------------- | ------------------------------------- |
| Sysmon Event ID   | 1 – Process Creation                  |
| Detection         | Suspicious PowerShell Encoded Command |
| MITRE Tactic      | Execution                             |
| MITRE Technique   | T1059.001                             |
| Data Source       | Windows Sysmon                        |
| SIEM              | Splunk                                |
| Severity          | Medium                                |
