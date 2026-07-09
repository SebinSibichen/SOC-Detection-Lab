# T1021 - Remote Services

## ATT&CK Tactic

Lateral Movement

## Description

Adversaries may use Remote Desktop Protocol (RDP) or other remote services to move laterally within a network.

## Detection Rule

Remote Desktop Detection

## Relevant Log Sources

- Windows Security Log

## Event IDs

- Security Event ID 4624 (Logon Type 10)

## Detection Logic

Monitor successful Remote Desktop logons and identify unusual source systems.

## Investigation Steps

- Verify source IP address.
- Confirm user legitimacy.
- Review login time.
- Identify multiple logins.
- Check subsequent activity.

## SPL Query

Remote-Desktop.spl

## MITRE ATT&CK

Technique: T1021

## References

https://attack.mitre.org/techniques/T1021/
