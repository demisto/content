This playbook will use the Microsoft Defender For Endpoint feature - Advanced Hunting - and will hunt for host PowerShell executions.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Command-Line Analysis

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-advanced-hunting-process-details
* microsoft-atp-advanced-hunting-network-connections
* microsoft-atp-get-file-related-machines
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | Enter IP to hunt on. Can be a comma-separated list. | incident.detectedips | Optional |
| DeviceName | Enter a hostname to hunt on. Can be a comma-separated list. | incident.hostnames | Optional |
| FileName | Enter file name to hunt on. Can be a comma-separated list. | incident.filenames | Optional |
| DeviceID | Enter device ID to hunt on. Can be a comma-separated list. | incident.agentsid | Optional |
| FileMd5 | Enter file MD5 to hunt on. Can be a comma-separated list. | incident.filemd5 | Optional |
| FileSha256 | Enter file SHA256 to hunt on. Can be a comma-separated list. | incident.filesha256 | Optional |
| FileSha1 | Enter file SHA1 to hunt on. Can be a comma-separated list. | incident.filesha1 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting For Powershell Executions](../doc_files/MDE_-_Host_Advanced_Hunting_For_Powershell_Executions.png)