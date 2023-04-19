Carbon Black Response isolates an endpoint for a given hostname.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
VMware Carbon Black EDR v2

### Scripts
This playbook does not use any scripts.

### Commands
* cb-edr-quarantine-device
* cb-edr-sensors-list

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to isolate. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- |----------|
| CarbonBlackEDR.Sensor.id | Carbon Black Response Sensors IDs that are isolated. | Number   |
| CarbonBlackEDR.Sensor.status | Sensor status. | String   |
| CarbonBlackEDR.Sensor.is_isolating | Is sensor isolated. | Boolean  |

## Playbook Image
---
![Block Endpoint - Carbon Black Response](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Endpoint_Carbon_Black_Response.png)
