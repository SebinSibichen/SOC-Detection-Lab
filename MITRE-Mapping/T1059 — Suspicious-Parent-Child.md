# MITRE ATT&CK Mapping 10 — Suspicious Parent-Child Process

## Primary Detection Objective

Identify potentially suspicious process execution relationships using Sysmon process-creation telemetry.

## Potential Technique: T1059 — Command and Scripting Interpreter

* Tactic: Execution
* Relevance: A scripting or command interpreter may be used to execute commands.
* Evidence to examine: Child executable, command line, user, parent process, and related events.

## Conditional Sub-techniques

Use a specific sub-technique only when the observed activity supports it.

Examples:

* T1059.001 — PowerShell, when PowerShell execution is observed.
* T1059.003 — Windows Command Shell, when `cmd.exe` activity is observed.

## Important Distinction

A parent-child relationship alone does not prove that a technique was used maliciously. The analyst must assess the command line, context, and supporting telemetry.

## Detection Data

* Sysmon Event ID 1
* `ParentImage`
* `Image`
* `CommandLine`
* `User`
* `ComputerName`

## Lab Validation

The Splunk lab confirms that process-creation events and the parent/child fields are available. The Office-to-script query returned zero events during the initial test; therefore, a matching detection has not yet been confirmed.

## References

MITRE ATT&CK:

* T1059 — Command and Scripting Interpreter
* T1059.001 — PowerShell
* T1059.003 — Windows Command Shell

