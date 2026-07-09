# Detection Rule 07 – Service Creation

## Objective
Detect new Windows services.

## Log Source
Windows Security Logs

## MITRE ATT&CK
T1543

## SPL Query

```spl
index=main EventCode=7045
| table _time ServiceName ImagePath User
```

## Investigation
Check service binary and startup type.

## Screenshot
Screenshots/Detection-07/
