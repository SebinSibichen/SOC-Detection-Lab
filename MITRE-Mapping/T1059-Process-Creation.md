# Module 01 — Process Creation: MITRE ATT&CK Mapping

## Objective

Map Windows process-creation telemetry collected by Sysmon to relevant MITRE ATT&CK techniques to support threat detection and investigation.

## Telemetry Source

* **Platform:** Windows
* **Tool:** Sysmon
* **Event ID:** 1 — Process Create
* **Splunk index:** `main`
* **Important fields:** `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `ProcessId`, and `UtcTime`.

## 1. Tactic: Execution

### T1059 — Command and Scripting Interpreter

* **Description:** Adversaries may use command and scripting interpreters to execute commands, scripts, or other instructions.
* **Relevance:** Process-creation events can reveal executions involving command interpreters and scripting environments.
* **Examples:** `cmd.exe`, `powershell.exe`, and Windows Script Host interpreters.
* **Evidence to investigate:** Process image, command line, parent process, user, and execution context.
* **Mapping status:** Candidate technique. Process execution alone does not establish malicious activity.

## 2. Tactic: Execution**

### T1059.001 — PowerShell

* **Description:** Adversaries may abuse PowerShell to execute commands and scripts.
* **Relevance:** PowerShell process-creation events can help analysts investigate suspicious command execution.
* **Evidence to investigate:** PowerShell command-line arguments, parent process, user, and associated PowerShell logging events.
* **Mapping status:** Applicable when the observed activity involves PowerShell and the detection logic supports this mapping.

## 3. Tactic: Defense Evasion

### T1218 — System Binary Proxy Execution

* **Description:** Adversaries may abuse legitimate system binaries to execute malicious content or commands.
* **Relevance:** Process-creation telemetry can help identify unusual executions of signed Windows utilities.
* **Examples:** `rundll32.exe`, `regsvr32.exe`, and `mshta.exe`.
* **Evidence to investigate:** Command-line arguments, parent process, executable path, and associated activity.
* **Mapping status:** Candidate technique. The execution of a legitimate Windows binary is not inherently malicious.

## 4. Tactic: Persistence

### T1053.005 — Scheduled Task

* **Description:** Adversaries may abuse scheduled tasks to maintain execution or persistence.
* **Relevance:** Process-creation events involving `schtasks.exe` may help investigate scheduled-task creation or modification.
* **Evidence to investigate:** Command-line arguments, task name, parent process, and corroborating task-scheduler events.
* **Mapping status:** Apply only when the evidence supports scheduled-task abuse. A process event alone may not confirm persistence.

## 5. Tactic: Persistence

### T1543.003 — Windows Service

* **Description:** Adversaries may create or modify Windows services to establish persistence or execute code.
* **Relevance:** Process-creation events involving `sc.exe` or service-management utilities may provide evidence of service configuration changes.
* **Evidence to investigate:** Command line, service name, parent process, and corroborating service-installation events.
* **Mapping status:** Candidate technique when supported by the observed service activity.

## Analyst Investigation Workflow

1. Identify the executable and command-line arguments.
2. Examine the parent process and its command line.
3. Identify the user and host.
4. Determine whether the execution is expected or unusual.
5. Correlate with network connections, authentication events, and other telemetry.
6. Assign a MITRE ATT&CK technique only when the evidence supports it.

## Conclusion

Sysmon Event ID 1 provides valuable process-creation telemetry for investigating execution, defense evasion, and persistence behaviors.

The techniques listed above are candidate mappings. They should not all be assigned to every process-creation event. The final mapping must reflect the specific behavior detected by the rule and the available evidence.

**Validation status:** Process-creation telemetry is available in the lab. Validate each technique against its corresponding detection rule and observed events before claiming that the technique was detected.
