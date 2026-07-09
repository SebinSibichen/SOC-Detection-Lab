# T1110 - Brute Force

## ATT&CK Tactic

Credential Access

## Description

Attackers attempt multiple password guesses to compromise user accounts.

## Detection Rule

Failed Logons

## Relevant Log Sources

- Windows Security Log

## Event IDs

- Security Event ID 4625

## Detection Logic

Detect repeated failed login attempts.

## Investigation Steps

- Count failed logins.
- Identify targeted account.
- Review source IP.
- Check login frequency.

## SPL Query

Failed-Logons.spl

## MITRE ATT&CK

Technique: T1110

## References

https://attack.mitre.org/techniques/T1110/
