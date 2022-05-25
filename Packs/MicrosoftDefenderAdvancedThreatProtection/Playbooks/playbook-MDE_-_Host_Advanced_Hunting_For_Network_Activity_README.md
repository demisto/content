This playbook will use the Microsoft Defender For Endpoint feature - Advanced Hunting - and will hunt for host network activity.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* UnzipFile

### Commands
* microsoft-atp-advanced-hunting-network-connections
* setIncident
* microsoft-atp-live-response-get-file
* microsoft-atp-advanced-hunting-lateral-movement-evidence
* microsoft-atp-advanced-hunting-persistence-evidence
* ip
* domain

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | Enter IP to hunt on. Can be a comma-separated list. | incident.detectedips | Optional |
| DeviceName | Enter a hostname to hunt on. Can be a comma-separated list. | incident.hostnames | Optional |
| FileName | Enter file name to hunt on. Can be a comma-separated list. | incident.filenames | Optional |
| DeviceID | Enter device id to hunt on. Can be a comma-separated list. | incident.agentsid | Optional |
| FileMd5 | Enter file md5 id to hunt on. Can be a comma-separated list. | incident.filemd5 | Optional |
| FileSha256 | Enter file SHA256 id to hunt on. Can be a comma-separated list. | incident.filesha256 | Optional |
| FileSha1 | Enter file SHA1 id to hunt on. Can be a comma-separated list. | incident.filesha1 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting For Network Activity](../doc_files/MDE_-_Host_Advanced_Hunting_For_Network_Activity.png)