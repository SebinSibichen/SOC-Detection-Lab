# MITRE ATT&CK Mapping — Failed Logons

## Detection Overview

This detection monitors failed Windows authentication attempts to identify patterns that may warrant investigation for brute-force activity.

## ATT&CK Mapping

| Field                      | Details                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1110 — Conditional                                                                             |
| Official Technique Name    | Brute Force                                                                                     |
| Tactic                     | Credential Access                                                                               |
| Supporting Event           | Windows Security Event ID 4625 — Failed logon                                                   |
| Supporting Fields          | `TargetUserName`, `IpAddress`, `LogonType`, `Status`, `SubStatus`, `WorkstationName`, timestamp |
| Mapping Confidence         | Conditional on repeated attempts or other supporting evidence                                   |
| Validation Status          | Failed-logon telemetry observed; assess detection thresholds and false positives                |

## Mapping Rationale

Repeated authentication failures may indicate an attempt to guess or obtain valid credentials. Event ID 4625 supplies evidence of unsuccessful logons and can support investigation when multiple events form a meaningful pattern.

A brute-force classification should be based on the frequency, distribution, source, targeted accounts, and surrounding authentication activity.

## What the Evidence Does Not Demonstrate

* That one failed logon constitutes brute force.
* That an attacker successfully obtained credentials.
* That a targeted account was compromised.
* That all failed attempts originated from an attacker.
* That repeated failures necessarily represent password spraying or credential stuffing.

## Validation Notes

Test the query against controlled failed-logon events and representative benign failures. Review thresholds, source addresses, account names, and event timing before classifying a pattern as suspicious.

## Official Reference

https://attack.mitre.org/techniques/T1110/
