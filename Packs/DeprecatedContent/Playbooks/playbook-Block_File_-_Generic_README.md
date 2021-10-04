DEPRECATED. Use "Block File - Generic v2" playbook instead. Blocks files from running on endpoints. This playbook currently supports Carbon Black Enterprise Response.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Block File - Carbon Black Response

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | The MD5 hash of the file you want to block. | ${File.MD5} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | The last block time. | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | The last block hostname. | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | The last block sensor ID. | unknown |

## Playbook Image
---
![Block_File_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_File_Generic.png)
