Carbon Black Response isolates an endpoint for a given hostname.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
carbonblack

### Scripts
This playbook does not use any scripts.

### Commands
* cb-quarantine-device
* cb-sensor-info

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to isolate. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.Sensors.CbSensorID | Carbon Black Response Sensors IDs that are isolated. | unknown |
| Endpoint | The isolated enpoint. | unknown |
| CbResponse.Sensors.Status | Sensor status. | unknown |
| CbResponse.Sensors.Isolated | Is sensor isolated. | unknown |
| Endpoint.Hostname | Endpoint hostname. | unknown |

## Playbook Image
---
![Block Endpoint - Carbon Black Response](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Endpoint_Carbon_Black_Response.png)
