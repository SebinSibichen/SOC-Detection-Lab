# T1543 - Create or Modify System Process

## ATT&CK Tactic

Persistence

## Description

Attackers create or modify Windows services to maintain persistence.

## Detection Rule

Service Creation

## Relevant Log Sources

- Windows System Log

## Event IDs

- Event ID 7045

## Detection Logic

Detect newly installed Windows services.

## Investigation Steps

- Verify service name.
- Review executable path.
- Check service account.
- Confirm digital signature.

## SPL Query

Services-Creation.spl

## MITRE ATT&CK

Technique: T1543

## References

https://attack.mitre.org/techniques/T1543/
