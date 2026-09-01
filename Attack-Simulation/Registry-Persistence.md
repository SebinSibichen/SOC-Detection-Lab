# 05 - Registry Run Key Persistence

## Objective

Simulate a Registry Run Key persistence technique on the Windows
target machine and verify that Sysmon generates Event ID 13 for the
registry modification.

The activity is performed in a controlled SOC lab environment for
security monitoring and detection testing.

---

## MITRE ATT&CK

- Technique: Registry Run Keys / Startup Folder
- Technique ID: T1547.001
- Tactic: Persistence

> Note: T1060 (Registry Run Keys / Startup Folder) is the legacy
> MITRE ATT&CK technique ID. The current technique ID is T1547.001.

---

## Attack Simulation

A test registry value named `SOC_Lab_Test` was created under the
current user's Windows Run key.

The value points to Notepad, which provides a harmless executable
for validating the persistence detection.

### PowerShell Command

```powershell
New-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "SOC_Lab_Test" `
-Value "C:\Windows\System32\notepad.exe" `
-PropertyType String `
-Force
