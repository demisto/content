Receives an MD5 hash and adds it to the blacklist in Carbon Black Enterprise Response. Files with that MD5 hash are blocked from execution on the managed endpoints.

If the integration is disabled at the time of running, or if the hash is already on the blacklist, no action is taken on the MD5.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
* cb-get-hash-blacklist
* cb-block-hash

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5 | The MD5 hash of the file you want to block. | MD5 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | The last block time. | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | The last block hostname. | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | The last block sensor ID. | unknown |

![Block_File_Carbon_Black_Response](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Block_File_Carbon_Black_Response.png)
