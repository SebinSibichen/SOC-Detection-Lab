# Detection Rule 06 – Scheduled Tasks

## Objective
Detect scheduled task creation.

## Log Source
Windows Security Logs

## MITRE ATT&CK
T1053

## SPL Query

```spl
index=main EventCode=4698
| table _time TaskName SubjectUserName
```

## Investigation
Verify task creator and scheduled action.

## Screenshot
Screenshots/Detection-06/
