# T1112 - Registry Modification

## ATT&CK Tactic

Defense Evasion / Persistence

## Description

Attackers modify the Windows Registry to maintain persistence or alter system behavior.

## Detection Rule

Registry Persistence

## Relevant Log Sources

- Sysmon

## Event IDs

- Sysmon Event ID 13

## Detection Logic

Detect modifications to sensitive registry keys.

## Investigation Steps

- Review registry path.
- Verify changed value.
- Identify process.
- Confirm persistence mechanism.

## SPL Query

Registry-Persistence.spl

## MITRE ATT&CK

Technique: T1112

## References

https://attack.mitre.org/techniques/T1112/
