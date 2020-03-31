Isolates an endpoint and a given hostname.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* carbonblack

## Scripts
This playbook does not use any scripts.

## Commands
* cb-sensor-info
* cb-quarantine-device

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- |--- | --- |
| Hostname | The hostname to isolate. | ${Endpoint.Hostname} |Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.Sensors.CbSensorID | The Carbon Black Response Sensors IDs that has been isolated. | unknown |
| Endpoint | The isolated enpoint. | unknown |

![Block_Endpoint_Carbon_Black_Response](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Block_Endpoint_Carbon_Black_Response.png)
