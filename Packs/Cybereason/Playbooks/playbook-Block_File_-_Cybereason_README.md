This playbook accepts an MD5 hash and blocks the file using the Cybereason integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cybereason

### Scripts
This playbook does not use any scripts.

### Commands
* cybereason-prevent-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | The MD5 hash of the file to block. | File.MD5 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | Last block time. | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | Last block hostname. | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | Last block sensor ID. | unknown |

## Playbook Image
---
![Block File - Cybereason](https://raw.githubusercontent.com/demisto/content/54a1993f8d18984c583ecfcc96fff031325314f0/Packs/Cybereason/doc_files/Block_File_-_Cybereason.png)