# Detection Rule 11 – Living Off The Land Binaries

## Objective
Detect execution of LOLBins.

## MITRE ATT&CK
T1218

## SPL Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*certutil.exe" OR Image="*mshta.exe" OR Image="*bitsadmin.exe" OR Image="*rundll32.exe")
| table _time Image CommandLine User
```

## Investigation
Determine whether the binary was used legitimately.

## Screenshot
Screenshots/Detection-11/
