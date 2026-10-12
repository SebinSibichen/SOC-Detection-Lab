# Module 12 — Credential Access Enumeration

## Objective

Validate the collection and detection of Windows process-creation events associated with credential-store enumeration using Sysmon and Splunk.

## Lab Environment

* Operating System: Windows 11
* Target hostname: `TargetMachine`
* Telemetry source: Sysmon Operational
* Sysmon event: Event ID 1 — Process Create
* Splunk index: `main`

## Simulation 1: Windows Credential Enumeration

Command executed:

```powershell
cmdkey /list
```

Purpose:

Enumerate saved Windows credential entries to demonstrate how credential-store enumeration can be observed through process-creation telemetry.

The command output contained stored credential target metadata. No password extraction was performed as part of this test.

## Simulation 2: Windows Vault Enumeration

Command executed:

```powershell
vaultcmd /list
```

Purpose:

List the Windows Vaults available on the system and generate observable process-creation activity.

## Local Sysmon Validation

A PowerShell `Get-WinEvent` query was used to check Sysmon Process Create events for `cmdkey.exe` and `vaultcmd.exe`.

The supplied PowerShell screenshot showed two matching Process Create events.

## Splunk Validation

The Splunk hunting query returned one event for:

* Image: `C:\Windows\System32\VaultCmd.exe`
* Command line: `"C:\Windows\system32\VaultCmd.exe" /list`
* Parent process: `powershell.exe`
* Host: `TargetMachine`
* Sysmon Record Number: `80057`
* Event UTC time: `2026-10-12 18:31:44.515`

The event was available in Splunk, confirming that the relevant Sysmon telemetry was ingested and searchable.

## Results

* Credential enumeration commands executed.
* Local Sysmon process-creation evidence was observed.
* The VaultCmd event was found in Splunk.
* No credential extraction or confirmed compromise was demonstrated.

## Conclusion

The lab successfully validated process-creation telemetry and hunting for selected credential-store enumeration utilities. This is a detection-engineering exercise, not evidence of a confirmed credential-theft incident.
