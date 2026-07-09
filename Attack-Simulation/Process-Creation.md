# Process Creation Simulation

## Objective

Generate a Sysmon Event ID 1 by creating a new Windows process.

## Command

```cmd
notepad.exe
```

## Expected Event

- Sysmon Event ID 1

## Detection Rule

01-Process-Creation.md

## SPL Query

Process-Creation.spl

## Expected Result

A new process creation event appears in Splunk.
