

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* UnzipFile

### Commands
* microsoft-atp-live-response-get-file
* ip
* microsoft-atp-advanced-hunting-lateral-movement-evidence
* setIncident
* domain
* microsoft-atp-advanced-hunting-persistence-evidence
* microsoft-atp-advanced-hunting-network-connections

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP |  |  | Optional |
| DeviceName |  |  | Optional |
| FileName |  |  | Optional |
| DeviceID |  |  | Optional |
| FileMd5 |  |  | Optional |
| FileSha256 |  |  | Optional |
| FileSha1 |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting For Network Activity](Insert the link to your image here)