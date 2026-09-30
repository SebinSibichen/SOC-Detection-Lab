# RDP Logon Attack Simulation

## Objective

Simulate a successful Remote Desktop Protocol (RDP) logon to the Windows target machine and generate Windows Security authentication telemetry for Splunk detection.

The purpose of this simulation is to demonstrate how a SOC analyst can identify successful remote interactive logons using Windows Security Event ID 4624 and Logon Type 10.

## Lab Environment

| Component        | Details                                              |
| ---------------- | ---------------------------------------------------- |
| Attacker Machine | Kali Linux                                           |
| Target Machine   | Windows 11                                           |
| Target Hostname  | TargetMachine                                        |
| SIEM             | Splunk Enterprise                                    |
| Log Collector    | Splunk Universal Forwarder                           |
| Log Source       | Windows Security Event Log                           |
| Event ID         | 4624                                                 |
| Logon Type       | 10 - RemoteInteractive                               |
| MITRE ATT&CK     | T1021.001 - Remote Services: Remote Desktop Protocol |

## Attack Simulation

### Step 1 - Verify Remote Desktop Configuration

On the Windows target machine, verify whether Remote Desktop connections are enabled.

```powershell
Get-ItemPropertyValue `
  -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections"
```

A value of:

```text
0
```

indicates that Remote Desktop connections are enabled.

### Step 2 - Enable Remote Desktop if Required

If Remote Desktop is disabled:

```powershell
Set-ItemProperty `
  -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections" `
  -Value 0
```

Enable the Windows Firewall rules for Remote Desktop:

```powershell
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

### Step 3 - Verify Remote Desktop Service

Check the Remote Desktop Services service:

```powershell
Get-Service TermService
```

The expected state is:

```text
Status   Name          DisplayName
------   ----          -----------
Running  TermService   Remote Desktop Services
```

### Step 4 - Connect from Kali Linux

From Kali Linux, connect to the Windows target using an RDP client.

Example:

```bash
xfreerdp3 /v:<WINDOWS-IP> /u:a4803
```

Replace `<WINDOWS-IP>` with the current IP address of the Windows target.

Enter the Windows account password when prompted.

### Step 5 - Generate the Security Event

After successful RDP authentication, Windows generates Security Event ID:

```text
4624 - An account was successfully logged on
```

For an RDP session, the important field is:

```text
Logon Type: 10
```

Microsoft identifies Logon Type 10 as `RemoteInteractive`, which represents a remote logon through Terminal Services or Remote Desktop.

## Expected Evidence

The generated event should contain information such as:

* Event ID: 4624
* Logon Type: 10
* Account Name
* Account Domain
* Computer Name
* Source Network Address / IP Address
* Workstation Name
* Logon Process
* Authentication Package
* Logon ID

The source IP and other network fields can help a SOC analyst determine where the remote logon originated.

## Cleanup

RDP can be disabled after testing if required:

```powershell
Set-ItemProperty `
  -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections" `
  -Value 1
```

## Security Objective

The simulation demonstrates how successful RDP logons can be monitored to identify potentially unauthorized remote access to Windows systems.

## Result

A successful RDP connection generated Windows Security Event ID 4624 with RemoteInteractive Logon Type 10, which was collected by Splunk Universal Forwarder and made available for SIEM detection.
