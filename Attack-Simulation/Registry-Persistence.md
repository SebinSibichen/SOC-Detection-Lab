# Registry Persistence Simulation

## Objective

Create a registry modification event.

## Command

```cmd
reg add HKCU\Software\Test /v Demo /t REG_SZ /d Test /f
```

## Expected Event

- Sysmon Event ID 13

## Detection Rule

05-Registry-Persistence.md
