# Detection Rule 09 – Failed Logons

## Objective
Detect brute-force login attempts.

## Log Source
Windows Security

## MITRE ATT&CK
T1110

## SPL Query

```spl
index=main EventCode=4625
| stats count by Account_Name Source_Network_Address
```

## Investigation
Look for repeated failures from the same source.

## Screenshot
Screenshots/Detection-09/
