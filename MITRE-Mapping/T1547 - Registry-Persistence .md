# MITRE ATT&CK Mapping — Registry Persistence

## Detection Overview

This detection investigates registry modifications that may be associated with Windows persistence mechanisms.

## ATT&CK Mapping

| Field                      | Details                                                               |
| -------------------------- | --------------------------------------------------------------------- |
| Official ATT&CK Identifier | T1547.001 — Conditional                                               |
| Official Technique Name    | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Tactic                     | Persistence; Privilege Escalation                                     |
| Supporting Events          | Sysmon Event IDs 12, 13, and 14, where applicable and configured      |
| Supporting Fields          | `EventCode`, `Image`, `TargetObject`, `Details`, `User`, `UtcTime`    |
| Mapping Confidence         | Conditional on the registry location and observed behavior            |
| Validation Status          | Confirm that the tested registry modification matches the detection   |

## Mapping Rationale

Registry Run keys and Startup Folder mechanisms can be used to arrange for programs to execute at startup or logon.

Sysmon registry telemetry can help identify changes to registry keys and values. To support T1547.001, the evidence should identify a relevant autostart location and the modification made to it.

## What the Evidence Does Not Demonstrate

* That every registry modification establishes persistence.
* That the modified value was executed.
* That the change was made by an attacker.
* That the registry value contained malicious content.
* That the modification survived a reboot or logon.

## Validation Notes

Inspect the registry path, value name, value data, process context, and any subsequent execution. Verify the relevant Sysmon event configuration and test the query against a controlled modification.

## Official Reference

https://attack.mitre.org/techniques/T1547/001/
