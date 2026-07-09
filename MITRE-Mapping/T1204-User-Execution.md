# T1204 - User Execution

## ATT&CK Tactic

Execution

## Description

Attackers rely on user interaction to execute malicious content.

## Detection Rule

Suspicious Parent-Child Processes

## Relevant Log Sources

- Sysmon

## Event IDs

- Sysmon Event ID 1

## Detection Logic

Monitor Office applications spawning PowerShell or Command Prompt.

## Investigation Steps

- Review parent process.
- Verify child process.
- Check document source.
- Analyze command line.

## SPL Query

Suspicious-Parent-Child.spl

## MITRE ATT&CK

Technique: T1204

## References

https://attack.mitre.org/techniques/T1204/
