This playbook uses the Microsoft Defender For Endpoint Advanced Hunting feature to hunt for host persistence evidence.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* microsoft-atp-advanced-hunting-persistence-evidence
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileSha256 | A comma-separated list of file SHA256 hashes to hunt. | incident.filesha256 | Optional |
| FileSha1 | A comma-separated list of file SHA1 hashes to hunt. | incident.filesha1 | Optional |
| FileMd5 | A comma-separated list of file MD5 hashes to hunt. | incident.filemd5 | Optional |
| IP | A comma-separated list of IPs to hunt. | incident.detectedips | Optional |
| DeviceName | A comma-separated list of host names to hunt. | incident.hostnames | Optional |
| FileName | A comma-separated list of file names to hunt. | incident.filenames | Optional |
| DeviceID | A comma-separated list of a device IDs to hunt. | incident.agentsid | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Host Advanced Hunting For Persistence](../doc_files/MDE_-_Host_Advanced_Hunting_For_Persistence.png)
