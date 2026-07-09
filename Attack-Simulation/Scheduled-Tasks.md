# Scheduled Task Simulation

## Objective

Create a scheduled task.

## Command

```cmd
schtasks /create /tn TestTask /tr notepad.exe /sc once /st 23:59
```

## Expected Event

- Security Event ID 4698

## Detection Rule

06-Scheduled-Tasks.md
