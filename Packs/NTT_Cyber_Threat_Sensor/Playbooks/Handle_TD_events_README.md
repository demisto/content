Playbook to enritch TD events

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Extract Indicators From File - Generic v2

### Integrations
* NTT Cyber Threat Sensor

### Scripts
* PcapMinerV2
* AddEvidence

### Commands
* NTT-CybertThreatSensor-FetchBlobs

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CTS.EventID | Event ID | string |
| CTS.OccuredTime | Event Time | unknown |

## Playbook Image
---
![Handle TD events](Insert the link to your image here)
