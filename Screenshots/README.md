# Screenshots

This directory contains screenshots documenting the complete **SOC Detection Lab**, from environment setup and system configuration to attack detection and investigation within Splunk Enterprise.

The screenshots provide visual evidence that the lab was successfully deployed and that each detection rule functions as expected.

---

# Folder Structure

```text
Screenshots/
│
├── Lab-Setup/
│   ├── Windows Target VM
│   ├── Kali Attacker VM
│   └── Network Architecture
│
├── Configuration/
│   ├── Sysmon Configuration
│   ├── Splunk Universal Forwarder
│   ├── inputs.conf Configuration
│   └── Receiving Port Configuration
│
└── Detection-Rules/
    ├── Process Creation
    ├── Network Connections
    ├── PowerShell
    ├── Encoded PowerShell
    ├── Registry Persistence
    ├── Scheduled Tasks
    ├── Services Creation
    ├── Remote Desktop
    ├── Failed Logons
    ├── Suspicious Parent-Child
    ├── Living-Off-The-Land
    └── Credential Access
```

---

## Lab Setup

This folder contains screenshots of the virtual lab environment used throughout the project.

Typical screenshots include:

- Windows Target Virtual Machine
- Kali Linux Attacker Virtual Machine
- Network Architecture (optional)

**Purpose**

Demonstrates the infrastructure used for attack simulation and security monitoring.

---

## Configuration

This folder contains screenshots showing the configuration of the logging and monitoring infrastructure.

Typical screenshots include:

- Sysmon Installation
- Sysmon Event Viewer
- `inputs.conf` Configuration
- Splunk Universal Forwarder Service
- Splunk Receiving Port Configuration

**Purpose**

Demonstrates that Windows event logging and log forwarding were configured correctly before attack simulation.

---

## Detection Rules

This folder contains screenshots for every detection rule implemented in the SOC Detection Lab.

Each detection rule has its own subfolder containing evidence of successful detection.

Typical screenshots include:

- SPL Search Query
- Search Results
- Expanded Event
- Event Details
- Interesting Fields
- Timeline

**Purpose**

Demonstrates that each SPL query successfully detected the simulated attack and provides supporting evidence for investigation.

---

# Evidence

All screenshots included in this repository were captured from the author's SOC Detection Lab during attack simulation and detection testing.

The screenshots validate:

- Successful lab deployment
- Correct Splunk configuration
- Successful Sysmon event collection
- Proper log forwarding using Splunk Universal Forwarder
- Working SPL detection queries
- Successful attack detection
- Incident investigation workflow

---

These screenshots provide visual documentation supporting every major component of the SOC Detection Lab.


>  **Note:** Some screenshots have been cropped or resized for readability while preserving the original detection results.
>
> 
