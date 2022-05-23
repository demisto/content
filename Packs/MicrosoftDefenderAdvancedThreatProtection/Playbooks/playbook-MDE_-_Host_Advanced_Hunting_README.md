

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* MDE - Host Advanced Hunting For Persistence
* MDE - Host Advanced Hunting For Network Activity
* MDE - Host Advanced Hunting For Powershell Executions

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

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
| FileSha1 |  |  | Optional |
| FileSha256 |  |  | Optional |
| IP |  |  | Optional |
| DeviceName |  |  | Optional |
| FileName |  |  | Optional |
| DeviceID |  |  | Optional |
| FileMd5 |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting](Insert the link to your image here)