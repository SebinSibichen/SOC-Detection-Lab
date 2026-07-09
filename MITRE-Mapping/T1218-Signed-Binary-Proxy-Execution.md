# T1218 - Signed Binary Proxy Execution

## ATT&CK Tactic

Defense Evasion

## Description

Attackers abuse legitimate Microsoft-signed binaries to execute malicious code.

## Detection Rule

Living-Off-The-Land Binaries

## Relevant Log Sources

- Sysmon

## Event IDs

- Sysmon Event ID 1

## Detection Logic

Monitor execution of LOLBins such as certutil.exe, regsvr32.exe and mshta.exe.

## Investigation Steps

- Review executable.
- Analyze command line.
- Check parent process.
- Verify downloaded files.

## SPL Query

Living-Off-The-Land.spl

## MITRE ATT&CK

Technique: T1218

## References

https://attack.mitre.org/techniques/T1218/
