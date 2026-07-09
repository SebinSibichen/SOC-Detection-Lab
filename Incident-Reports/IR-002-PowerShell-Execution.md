# Incident Report 002

## Incident Summary

PowerShell execution detected.

## Detection

Sysmon Event ID 1

## Evidence

- powershell.exe
- Parent Process
- Command Line

## Investigation

Checked command line arguments.

Verified whether PowerShell was executed by an administrator or malicious script.

## MITRE ATT&CK

T1059.001

## Status

Under Investigation
