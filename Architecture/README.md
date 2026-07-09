# SOC Lab Architecture

This directory contains the architecture of the SOC Detection Lab.

The lab demonstrates how Windows event logs are collected, forwarded, indexed, searched, and investigated using Splunk Enterprise.

The architecture was designed to simulate a small Security Operations Center (SOC) environment suitable for detection engineering, threat hunting, and incident response practice.

---

## Components

- Windows 11 Virtual Machine
- Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise
- VMware Workstation

---

## Data Flow

Windows Events
↓

Sysmon

↓

Splunk Universal Forwarder

↓

Splunk Enterprise

↓

Detection Rules

↓

Incident Investigation

---

## Documentation

- Architecture.md
- Lab-Architecture.png

---

This architecture serves as the foundation for all detection rules, SPL queries, and incident reports included in this repository.
