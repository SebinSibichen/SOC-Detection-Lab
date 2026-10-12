# MITRE ATT&CK Mapping — Encoded PowerShell

## Detection Overview

This detection searches PowerShell process command lines for encoded-command arguments that may warrant further investigation.

## ATT&CK Mapping

| Field                      | Details                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1059.001                                                                                       |
| Official Technique Name    | Command and Scripting Interpreter: PowerShell                                                   |
| Secondary Identifier       | T1027 — Conditional                                                                             |
| Secondary Technique Name   | Obfuscated Files or Information                                                                 |
| Tactic                     | Execution; Defense Evasion for T1027                                                            |
| Supporting Event           | Sysmon Event ID 1 — Process Create                                                              |
| Supporting Fields          | `Image`, `CommandLine`, `ParentImage`, `User`, `UtcTime`                                        |
| Mapping Confidence         | T1059.001 when PowerShell execution is observed; T1027 requires supporting obfuscation evidence |
| Validation Status          | Verify encoded-command matching and benign test results                                         |

## Mapping Rationale

PowerShell can execute commands supplied through encoded command-line arguments. Such arguments can make the command less immediately readable during initial inspection.

T1059.001 is appropriate when PowerShell execution is observed. T1027 may be relevant when the evidence supports an obfuscation technique.

## What the Evidence Does Not Demonstrate

* That the encoded content is malicious.
* That the encoded command was decoded successfully.
* That a payload executed successfully.
* That encoding was used specifically to evade detection.
* That the endpoint was compromised.

## Validation Notes

Inspect the complete command line and, where appropriate, decode the test input in a controlled environment. Compare the detection against ordinary PowerShell activity to identify false positives.

Do not assign T1027 solely because an encoded-command argument is present.

## Official References

https://attack.mitre.org/techniques/T1059/001/

https://attack.mitre.org/techniques/T1027/
