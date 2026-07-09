# Encoded PowerShell Simulation

## Objective

Simulate encoded PowerShell execution.

## Command

```powershell
powershell.exe -EncodedCommand SGVsbG8=
```

## Expected Event

- Sysmon Event ID 1

## Detection Rule

04-Encoded-PowerShell.md

## SPL Query

Encoded-PowerShell.spl
