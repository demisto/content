This playbook is used to block files from running on endpoints. 
This playbook supports the following integrations:
- Palo Alto Networks Traps
- Palo Alto Networks Cortex XDR
- Cybereason
- Carbon Black Enterprise Response
- Cylance Protect v2


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Block File
* Block File - Cylance Protect v2
* Block File - Carbon Black Response
* Traps Quarantine Event
* Traps Blacklist File
* Block File - Cybereason

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | The MD5 hash of the file you want to block. | File.MD5 | Optional |
| SHA256 | The SHA256 hash of the file you want to block. | File.SHA256 | Optional |
| EventId | Traps event ID that contains the malicious file to block. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | Last block time | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | Last block hostname | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | Last block sensor ID | unknown |

## Playbook Image
---
![Block File - Generic v2](https://raw.githubusercontent.com/demisto/content/2cc17644cf3518afe6050b0eefb5786aeccd393a/Packs/CommonPlaybooks/doc_files/Block_File_-_Generic_v2.png)