# T1003 - Credential Access

## ATT&CK Tactic

Credential Access

## Description

Adversaries attempt to steal account credentials from the operating system or applications. One common technique is dumping credentials from the Local Security Authority Subsystem Service (LSASS) process.

## Detection Rule

Credential Access Detection

## Relevant Log Sources

- Sysmon
- Windows Security Logs

## Event IDs

- Sysmon Event ID 10

## Detection Logic

Monitor attempts to access the LSASS process with excessive privileges.

## Investigation Steps

- Verify the source process.
- Review the user account involved.
- Check GrantedAccess permissions.
- Identify parent process.
- Determine whether the access is legitimate.

## SPL Query

Credential-Access.spl

## MITRE ATT&CK

Technique: T1003

## References

https://attack.mitre.org/techniques/T1003/
