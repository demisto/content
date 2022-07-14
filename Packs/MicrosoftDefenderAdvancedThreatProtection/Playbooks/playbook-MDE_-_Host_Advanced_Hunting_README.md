This playbook uses the Microsoft Defender For Endpoint Advanced Hunting feature. The hunt is executed based on the provided inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* MDE - Host Advanced Hunting For Network Activity
* MDE - Host Advanced Hunting For Powershell Executions
* MDE - Host Advanced Hunting For Persistence

### Integrations
MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-advanced-hunting-privilege-escalation
* setIncident
* microsoft-atp-advanced-hunting-tampering
* microsoft-atp-advanced-hunting-lateral-movement-evidence
* microsoft-atp-get-file-info

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileSha1 | A comma-separated list of file SHA1 hashes to hunt. |  | Optional |
| FileSha256 | A comma-separated list of file Sha256 hashes to hunt. |  | Optional |
| IP | A comma-separated list of IPs to hunt. |  | Optional |
| DeviceName | A comma-separated list of host names to hunt. |  | Optional |
| FileName | A comma-separated list of file names to hunt. |  | Optional |
| DeviceID | A comma-separated list of device ID to hunt. |  | Optional |
| FileMd5 | A comma-separated list of file MD5 hashes to hunt. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting](../doc_files/MDE_-_Host_Advanced_Hunting.png)
