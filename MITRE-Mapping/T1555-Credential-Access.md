# Module 12 — MITRE ATT&CK Mapping

## Primary Candidate Technique

### T1555.004 — Credentials from Password Stores: Windows Credential Manager

* **Tactic:** Credential Access
* **Platform:** Windows
* **Observed process:** `VaultCmd.exe`
* **Observed command:** `/list`

**Mapping rationale:** The lab observed a command that enumerates available Windows Vaults. This behavior is relevant to investigating attempts to access credentials stored in Windows Credential Manager.

**Evidence limitation:** The observed `/list` command enumerated Vaults. The supplied event does not prove that stored credentials were extracted.

## Related Candidate Technique

### T1555 — Credentials from Password Stores

This parent technique describes attempts to obtain credentials from common password-storage locations.

It provides broader context for the lab but should not be interpreted as proof that credentials were obtained.

## Evidence-to-Technique Assessment

| Evidence                     | Assessment       |
| ---------------------------- | ---------------- |
| `VaultCmd.exe /list`         | Observed         |
| Sysmon Event ID 1            | Confirmed        |
| Splunk event returned        | Confirmed        |
| Credential-store enumeration | Observed         |
| Credential extraction        | Not demonstrated |
| Credential misuse            | Not demonstrated |
| Confirmed compromise         | Not established  |

## Conclusion

Map this lab to T1555.004 as a relevant investigation technique. Record the activity as benign test behavior, and do not claim that a malicious credential-access technique was successfully completed.

Reference: MITRE ATT&CK — Credentials from Password Stores: Windows Credential Manager.
