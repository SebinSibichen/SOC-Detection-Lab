# T1053 - Scheduled Task

## ATT&CK Tactic

Persistence

## Description

Attackers create scheduled tasks to maintain persistence or execute malicious code automatically.

## Detection Rule

Scheduled Task Detection

## Relevant Log Sources

- Windows Security Log
- Sysmon

## Event IDs

- Security Event ID 4698

## Detection Logic

Detect newly created scheduled tasks.

## Investigation Steps

- Review task name.
- Check execution schedule.
- Verify executable path.
- Identify task creator.

## SPL Query

Scheduled-Tasks.spl

## MITRE ATT&CK

Technique: T1053

## References

https://attack.mitre.org/techniques/T1053/
