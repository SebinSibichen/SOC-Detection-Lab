# T1547 - Boot or Logon Autostart Execution

## ATT&CK Tactic

Persistence

## Description

Attackers configure applications to execute automatically when a user logs in or the system starts.

## Detection Rule

Registry Persistence

## Relevant Log Sources

- Sysmon

## Event IDs

- Sysmon Event ID 13

## Detection Logic

Monitor Run and RunOnce registry keys for unauthorized modifications.

## Investigation Steps

- Review modified registry key.
- Identify associated executable.
- Verify persistence.
- Check parent process.

## SPL Query

Registry-Persistence.spl

## MITRE ATT&CK

Technique: T1547

## References

https://attack.mitre.org/techniques/T1547/
