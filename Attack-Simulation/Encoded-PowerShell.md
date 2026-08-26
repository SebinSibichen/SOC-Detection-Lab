# PowerShell Encoded Command Simulation

## Objective

Simulate a suspicious PowerShell execution using the `-EncodedCommand` parameter and generate a Sysmon Process Creation event for detection in Splunk.

This is a controlled lab simulation using a harmless PowerShell command.

---

## MITRE ATT&CK

**Technique:** T1059.001 – PowerShell

---

## Environment

* Windows VM: TargetMachine
* Sysmon: Installed and running
* Splunk Universal Forwarder: Installed
* Splunk Enterprise: Running on the Splunk server
* Log Source: Microsoft-Windows-Sysmon/Operational
* Sysmon Event ID: 1 – Process Creation

---

## Step 1 – Generate a Base64 Encoded PowerShell Command

Open **PowerShell as Administrator** on the Windows VM.

Run:

```powershell
$cmd = 'Write-Host "SOC Lab Encoded PowerShell Test"'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

Copy the Base64 value that is displayed.

---

## Step 2 – Execute the Encoded Command

Replace `<BASE64_VALUE>` with the value generated above:

```powershell
powershell.exe -NoProfile -EncodedCommand <BASE64_VALUE>
```

Example structure:

```powershell
powershell.exe -NoProfile -EncodedCommand SQBFAFgA...
```

The command is harmless and only prints:

```text
SOC Lab Encoded PowerShell Test
```

---

## Step 3 – Verify the Sysmon Event

Run:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=1
} -MaxEvents 5 | Select-Object TimeCreated, Id, ProviderName
```

Expected result:

```text
Id
--
1
1
1
```

---

## Step 4 – Verify the Command Line

The Sysmon Event ID 1 event should contain:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

and the `CommandLine` should contain:

```text
-EncodedCommand
```

or:

```text
-enc
```

---

## Expected Result

Splunk should receive a Sysmon Event ID 1 containing:

* ComputerName
* User
* Image
* ParentImage
* CommandLine
* ProcessId
* ProcessGuid
* EventCode
* UtcTime

The important detection field is:

```text
CommandLine
```

because it contains the suspicious PowerShell encoded-command parameter.

---

## Evidence

Capture screenshots showing:

1. PowerShell command used to generate the Base64 value.
2. Encoded PowerShell command execution.
3. Sysmon Event ID 1 verification.
4. Splunk detection result.

---

## Result

A controlled encoded PowerShell execution was successfully generated and forwarded to Splunk through Sysmon and the Splunk Universal Forwarder.
