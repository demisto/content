Accepts an MD5 hash and blocks the file using the Cybereason integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* Cybereason

## Scripts
This playbook does not use any scripts.

## Commands
* cybereason-prevent-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5 | The MD5 hash of the file to block. | MD5 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | The last block time | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | The last block hostname | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | The last block sensor ID | unknown |

## Playbook Image
---
![Block_File_Cybereason](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_File_Cybereason.png)
