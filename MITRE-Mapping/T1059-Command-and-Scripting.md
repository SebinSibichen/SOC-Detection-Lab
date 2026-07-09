# T1059 - Command and Scripting Interpreter

## ATT&CK Tactic

Execution

## Description

Attackers execute commands using scripting interpreters such as PowerShell or Command Prompt.

## Detection Rule

Process Creation
PowerShell Execution
Encoded PowerShell

## Relevant Log Sources

- Sysmon
- PowerShell Operational Log

## Event IDs

- Sysmon Event ID 1
- PowerShell Event ID 4104

## Detection Logic

Monitor execution of scripting engines and suspicious command-line arguments.

## Investigation Steps

- Review command line.
- Check parent process.
- Identify encoded commands.
- Verify user account.

## SPL Query

PowerShell-Execution.spl

## MITRE ATT&CK

Technique: T1059

## References

https://attack.mitre.org/techniques/T1059/
