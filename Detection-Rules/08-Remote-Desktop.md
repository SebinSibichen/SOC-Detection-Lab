# Detection Rule 08 – Remote Desktop Logons

## Objective
Detect RDP logons.

## Log Source
Windows Security

## MITRE ATT&CK
T1021.001

## SPL Query

```spl
index=main EventCode=4624 LogonType=10
| table _time Account_Name Workstation_Name Source_Network_Address
```

## Investigation
Verify user identity and source IP.

## Screenshot
Screenshots/Detection-08/
