# SOC Incident Report — SOC-IR-011

## Incident Details

| Field       | Details                                                |
| ----------- | ------------------------------------------------------ |
| Incident ID | SOC-IR-011                                             |
| Title       | LOLBin Process Execution Investigation                 |
| Host        | TargetMachine                                          |
| Data Source | Sysmon Operational                                     |
| Event ID    | 1                                                      |
| SIEM        | Splunk Enterprise                                      |
| Severity    | Informational — benign test                            |
| Status      | Telemetry validated; suspicious activity not confirmed |

## Summary

A controlled test was performed to verify whether execution of `certutil.exe` was recorded by Sysmon and forwarded to Splunk.

The test used the command:

`certutil.exe -?`

The resulting process-creation event was visible in Splunk.

## Evidence

| Field          | Observed value                                              |
| -------------- | ----------------------------------------------------------- |
| Process        | `C:\Windows\System32\certutil.exe`                          |
| Command line   | `"C:\Windows\system32\certutil.exe" -?`                     |
| Parent process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| User           | `TARGETMACHINE\a4803`                                       |
| Host           | `TargetMachine`                                             |
| Event ID       | 1                                                           |
| Record number  | 77624                                                       |
| Event UTC time | 2026-10-11 17:41:58.797 UTC                                 |

## Analysis

The observed command requested the utility's help output. The event confirms that Sysmon recorded the process and that Splunk ingested the event.

The evidence does not indicate that a file was downloaded, decoded, or executed remotely.

The use of `certutil.exe` alone is insufficient to classify the event as malicious.

## Impact

No malicious impact was established from this test.

## Response

* Confirmed process-creation logging.
* Confirmed that the event was searchable in Splunk.
* Recorded the process image, command line, user, and parent process.
* Avoided classifying the benign test as a security incident.

## Current Disposition

**Benign test; no confirmed compromise.**

The broader LOLBin hunting query was validated against the observed `certutil.exe` event. Additional testing is required before claiming that the focused suspicious-command-line rule detects malicious activity.

## Follow-up Actions

1. Validate the query against additional controlled test cases.
2. Review potential false positives.
3. Expand detections only where telemetry and test results support them.
4. Capture final SPL results and document the validation status.
