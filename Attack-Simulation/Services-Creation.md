# Service Creation Simulation

## Objective

Simulate Windows service creation.

## Command

```cmd
sc create DemoService binPath= "C:\Windows\System32\notepad.exe"
```

## Expected Event

- System Event ID 7045

## Detection Rule

07-Services-Creation.md
