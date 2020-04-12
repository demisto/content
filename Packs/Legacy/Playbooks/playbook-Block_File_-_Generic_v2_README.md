Blocks files from running on endpoints. 

This playbook supports the following integrations:
- Palo Alto Networks Traps
- Cybereason
- Carbon Black Enterprise Response
- Cylance Protect v2


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Block File - Cylance Protect v2
* Block File - Cybereason
* Traps Quarantine Event
* Traps Blacklist File
* Block File - Carbon Black Response

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5 | The MD5 hash of the file you want to block. | MD5 | File | Optional |
| SHA256 | The SHA256 hash of the file you want to block. | SHA256 | File | Optional |
| EventId | The Taps event ID that contains the malicious file to block. | - | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | The last block time. | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | The last block hostname. | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | The last block sensor ID. | unknown |

## Playbook Image
---
![Block_File_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_File_Generic_v2.png)
