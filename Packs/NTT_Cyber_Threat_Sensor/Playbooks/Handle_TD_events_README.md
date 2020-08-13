Playbook to enrich TD events

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling
* PCAP Analysis

### Integrations
* NTT Cyber Threat Sensor

### Scripts
This playbook does not use any scripts.

### Commands
* NTT-CybertThreatSensor-FetchBlobs
* NTT-CybertThreatSensor-PollBlobs

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CTS.EventID | CTS EventID aka alert / sha | string |
| CTS.OccuredTime | Timestamp when incident was registered | date |

## Playbook Image
---
![Handle TD events](Insert the link to your image here)