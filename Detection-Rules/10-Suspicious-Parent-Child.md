# Detection Rule 10 – Suspicious Parent-Child Processes

## Objective
Detect abnormal parent-child process relationships.

## MITRE ATT&CK
T1036

## SPL Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| table _time ParentImage Image CommandLine
```

## Investigation
Review unexpected parent-child relationships.

Examples:
- Word → cmd.exe
- Excel → powershell.exe
- Outlook → mshta.exe

## Screenshot
Screenshots/Detection-10/
