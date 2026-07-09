# T1071 - Application Layer Protocol

## ATT&CK Tactic

Command and Control

## Description

Attackers communicate with external systems using common application layer protocols.

## Detection Rule

Network Connections

## Relevant Log Sources

- Sysmon

## Event IDs

- Sysmon Event ID 3

## Detection Logic

Monitor outbound network connections to suspicious destinations.

## Investigation Steps

- Review destination IP.
- Check destination port.
- Verify process.
- Investigate external reputation.

## SPL Query

Network-Connections.spl

## MITRE ATT&CK

Technique: T1071

## References

https://attack.mitre.org/techniques/T1071/
