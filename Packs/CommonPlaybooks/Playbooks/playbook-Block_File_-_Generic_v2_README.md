This playbook is used to block files from running on endpoints. 
This playbook supports the following integrations:
- Palo Alto Networks Traps
- Cybereason
- Carbon Black Enterprise Response
- Cylance Protect v2


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block File - Cybereason
* Block File - Cylance Protect v2
* Traps Quarantine Event
* Traps Blacklist File
* Cortex XDR Blacklist File
* Block File - Carbon Black Response
* Cortex XDR - quarantine file

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
| FilePath | A path to the file for quarantine. |  | Optional |
| EndpointID | Endpoint ID list to quarantine files on |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.BlockedHashes.LastBlock.Time | Last block time | unknown |
| CbResponse.BlockedHashes.LastBlock.Hostname | Last block hostname | unknown |
| CbResponse.BlockedHashes.LastBlock.CbSensorID | Last block sensor ID | unknown |

## Playbook Image
---
![Block File - Generic v2](Insert the link to your image here)