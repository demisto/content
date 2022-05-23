

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Command-Line Analysis

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* microsoft-atp-advanced-hunting-process-details
* microsoft-atp-advanced-hunting-network-connections
* microsoft-atp-get-file-related-machines

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
![MDE - Host Advanced Hunting For Powershell Executions](Insert the link to your image here)