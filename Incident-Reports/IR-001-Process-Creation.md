SOC Incident Report — IR-001: Process Creation Monitoring

1. Executive Summary

Incident ID: SOC-IR-001
Category: Endpoint Monitoring / Process Execution
Environment: Windows 11 lab endpoint
Detection Platform: Splunk Enterprise
Telemetry Source: Sysmon Operational Log
Status: Monitoring exercise
Severity: Informational — Pending behavior-specific assessment
Disposition: Telemetry monitoring and detection validation



This exercise evaluates the collection and analysis of Windows process-creation telemetry through Sysmon and Splunk.



The objective is to establish visibility into executable launches, command-line arguments, parent processes, and user context. Process creation is a foundational source of evidence for investigating suspicious endpoint activity.



A process-creation event alone is not evidence of compromise.

2. Scope and Environment

Attribute

Details

Monitored endpoint

Windows 11 VM

Endpoint hostname

TargetMachine

SIEM

Splunk Enterprise

Forwarding agent

Splunk Universal Forwarder

Splunk index

main

Event source

Sysmon Operational

Primary event

Sysmon Event ID 1

3. Detection and Evidence

Detection objective: Identify process execution and provide sufficient context for investigation.



Primary telemetry: Sysmon Event ID 1 — Process Create.



Relevant fields include:



Image

CommandLine

ParentImage

User

UtcTime

ProcessId

ParentProcessId



Evidence reference: Attach the relevant Splunk event and query screenshots.



Observed timestamp: [Insert verified timestamp]
Event record number: [Insert verified record number]
Observed command line: [Insert actual command line]

4. Investigation and Analysis

Review the executable path, command-line arguments, parent process, user account, and execution time.



Determine whether the process is consistent with expected administrative or user activity. Where necessary, correlate it with network connections, authentication events, script execution, or other endpoint telemetry.

5. MITRE ATT&CK Mapping

Technique: No single technique is assigned to generic process creation.



If the observed process executes PowerShell, T1059.001 — Command and Scripting Interpreter: PowerShell — may be relevant.



Official reference: https://attack.mitre.org/techniques/T1059/001/

6. Impact Assessment

No impact should be inferred solely from a process-creation event.



Confidentiality impact: Not established.

Integrity impact: Not established.

Availability impact: Not established.

Endpoint compromise: Not established.

7. Response and Containment

No containment is warranted solely because a process-creation event exists.



If suspicious behavior is identified, preserve the event, review related activity, and follow the organization's incident response procedure.

8. False-Positive Considerations

Common benign causes include application launches, software installation, administrative scripts, scheduled maintenance, and system processes.

9. Limitations and Evidence Gaps

Process creation does not prove successful execution of every command or payload.

The event alone does not establish malicious intent.

Additional telemetry may be required to determine the process's purpose.

10. Recommendations

Maintain reliable Sysmon collection.

Include parent-process and command-line context in detection searches.

Validate detections against representative benign activity.

Correlate process events with related telemetry when investigating suspicious activity.

11. Final Disposition

Disposition: Monitoring exercise; no confirmed security incident established.



Validation status: [Telemetry observed / Detection validated / Needs further validation]



**Analyst Notes:** Process-creation telemetry is used to establish visibility into executable launches and their associated command-line arguments. The relevant Sysmon events and SPL results should be reviewed before confirming detection effectiveness. No malicious activity is established by process creation alone.



