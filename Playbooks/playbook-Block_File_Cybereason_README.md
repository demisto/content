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

![Block_File_Cybereason](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Block_File_Cybereason.png)
