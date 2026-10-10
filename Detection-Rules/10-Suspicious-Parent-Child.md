# Detection Rule 10 — Suspicious Parent-Child Process

## Rule Name

Suspicious Office Application Spawning a Script Interpreter

## Severity

Medium — increase severity when the command line, user context, or surrounding activity provides additional evidence of malicious behavior.

## Data Source

Sysmon Event ID 1 — Process Creation

## Detection Logic

Identify Office applications launching command interpreters or scripting engines.

Potentially suspicious parent processes:

* `winword.exe`
* `excel.exe`
* `powerpnt.exe`
* `outlook.exe`

Child processes of interest:

* `powershell.exe`
* `pwsh.exe`
* `cmd.exe`
* `wscript.exe`
* `cscript.exe`
* `mshta.exe`

## SPL Detection

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval ParentProcess=lower(ParentImage), ChildProcess=lower(Image)
| where (
    match(ParentProcess, "(?i)\\(winword|excel|powerpnt|outlook)\.exe$")
    AND match(ChildProcess, "(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$")
)
| table _time ComputerName User ParentImage Image CommandLine
| sort - _time
```

**Regex troubleshooting:** If the query produces a regex error, use the simpler `like()` version below.

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval ParentProcess=lower(ParentImage), ChildProcess=lower(Image)
| where (
    like(ParentProcess, "%\\winword.exe")
    OR like(ParentProcess, "%\\excel.exe")
    OR like(ParentProcess, "%\\powerpnt.exe")
    OR like(ParentProcess, "%\\outlook.exe")
)
| where (
    like(ChildProcess, "%\\powershell.exe")
    OR like(ChildProcess, "%\\pwsh.exe")
    OR like(ChildProcess, "%\\cmd.exe")
    OR like(ChildProcess, "%\\wscript.exe")
    OR like(ChildProcess, "%\\cscript.exe")
    OR like(ChildProcess, "%\\mshta.exe")
)
| table _time ComputerName User ParentImage Image CommandLine
| sort - _time
```

The `like()` version uses `%` as a wildcard and avoids regular-expression escaping. See Splunk's documentation for the `where` and `like()` functions: [Splunk where command documentation](https://help.splunk.com/splunk-cloud-platform/spl-search-reference/9.3.2408/search-commands/where?utm_source=chatgpt.com)

## Triage Steps

1. Identify the parent and child executable paths.
2. Review the full command line.
3. Identify the user associated with the process.
4. Determine whether the parent-child relationship is expected for the endpoint.
5. Correlate with PowerShell logs, network connections, and other security events.
6. Escalate if the behavior is unexplained or supported by additional evidence.

## False Positives

* Approved Office add-ins or automation.
* Administrative scripts.
* Legitimate software integrations.
* Authorized troubleshooting activity.

## Limitations

This rule detects a narrow set of process relationships. It does not detect every suspicious process chain and does not establish malicious intent by itself.
