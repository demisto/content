This playbook isolates a given endpoint via various endpoint product integrations.
Make sure to provide the valid playbook input for the integration you are using.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Isolate Endpoint - Cybereason
* FireEye HX - Isolate Endpoint 
* Block Endpoint - Carbon Black Response V2
* Cortex XDR - Isolate Endpoint
* Crowdstrike Falcon - Isolate Endpoint 

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
| Endpoint_hostname | The hostname of the endpoint to isolate. |  | Optional |
| ManualHunting.DetectedHosts | Hosts that where detected as infected during the manual hunting. |  | Optional |
| Endpoint_ip | The IP of the endpoint to isolate. |  | Optional |
| Endpoint_id | The ID of the endpoint to isolate. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.Sensors.CbSensorID | Carbon Black Response Sensors IDs that are isolated. | string |
| Endpoint | The isolated endpoint. | string |
| Traps.Isolate.EndpointID | The ID of the endpoint. | string |
| Traps.IsolateResult.Status | The status of the isolation operation. | string |
| Cybereason.Machine | Cybereason machine name. | unknown |
| Cybereason.IsIsolated | Whether the machine is isolated. | unknown |
| Endpoint.Hostname | Hostname of the endpoint. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | The endpoint ID. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_name | The endpoint name. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_status | The status of the endpoint. | unknown |
| PaloAltoNetworksXDR.Endpoint.ip | The endpoint's IP addresses. | unknown |
| PaloAltoNetworksXDR.Endpoint.is_isolated | Whether the endpoint is isolated. | unknown |
| CbResponse.Sensors.Status | Sensor status. | unknown |
| CbResponse.Sensors.Isolated | Whether the sensor is isolated. | unknown |

## Playbook Image
---
![Isolate Endpoint - Generic V2](https://raw.githubusercontent.com/demisto/content/aa69a7486c3bb757972161410a98573936039f4b/Packs/CommonPlaybooks/doc_files/Isolate_Endpoint_-_Generic.png)
