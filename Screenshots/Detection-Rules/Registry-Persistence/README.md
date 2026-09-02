# Registry Persistence – Screenshots

This folder contains screenshots demonstrating the complete Registry Persistence detection workflow, from attack simulation to Sysmon event generation and Splunk detection.

## Screenshot List

### 01-Registry-Persistence-Created.png

Shows the PowerShell command used to create the benign Registry Run Key persistence entry.

**Purpose:**

* Demonstrates the simulated persistence technique.
* Shows the `SOC_Lab_Test` Run Key being created.
* Provides evidence of the attack simulation.

---

### 02-Sysmon-Registry-Event.png

Shows the Sysmon Event ID 13 generated after modifying the Registry Run Key.

**Purpose:**

* Demonstrates Sysmon detection of registry value modification.
* Shows Event ID `13`.
* Provides evidence of the modified `CurrentVersion\Run` registry location.

---

### 03-splunk-registry-detection-Query.png

Shows the Splunk SPL query used to detect Registry Persistence activity.

**Detection Query:**

```spl
index=main EventCode=13
| search TargetObject="*\\CurrentVersion\\Run\\*"
| where NOT like(Image,"%SplunkUniversalForwarder%")
| table _time ComputerName User Image TargetObject Details
| sort - _time
```

**Purpose:**

* Demonstrates the SOC detection rule.
* Filters Sysmon Event ID 13 events related to Registry Run Keys.
* Excludes known Splunk Universal Forwarder activity.

---

### 04-Registry-Persistence-Events.png

Shows the registry persistence events returned by Splunk.

**Purpose:**

* Confirms that the detection rule successfully identified registry persistence activity.
* Displays relevant fields such as:

  * Timestamp
  * Computer
  * User
  * Image
  * Target Object
  * Registry Details

---

### 05-Expanded-Event.png

Shows an expanded Splunk event containing detailed information about the detected Registry Persistence activity.

**Purpose:**

* Provides detailed investigation evidence.
* Allows analysts to identify the process responsible for the registry modification.
* Shows the affected registry location and value.

---

## Investigation Flow

The screenshots demonstrate the following SOC investigation workflow:

```text
Registry Modification
        ↓
Sysmon Event ID 13
        ↓
Splunk Universal Forwarder
        ↓
Splunk Index
        ↓
Detection Rule
        ↓
Registry Persistence Alert/Evidence
        ↓
SOC Investigation
```

## MITRE ATT&CK

**Primary Technique:**
`T1547.001 – Registry Run Keys / Startup Folder`

**Tactic:**
Persistence

The simulated activity creates a Registry Run Key under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The screenshots provide evidence for the detection and investigation of this persistence technique.
