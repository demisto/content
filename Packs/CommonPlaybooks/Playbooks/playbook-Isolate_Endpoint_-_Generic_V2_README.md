This playbook isolates a given endpoint via various of endpoints products integration.
Make sure to provide the valid playbook input for the integration that you using.

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
| Endpoint_hostname | The hostname of the endpoint that you wish to isolate. |  | Optional |
| ManualHunting.DetectedHosts | Hosts that where detected as infected during the manual hunting. |  | Optional |
| Endpoint_ip | The ip of the endpoint that you wish to isolate. |  | Optional |
| Endpoint_id | The id of the endpoint that you wish to isolate. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbResponse.Sensors.CbSensorID | Carbon Black Response Sensors ids that has been isolated. | string |
| Endpoint | The isolated enpoint. | string |
| Traps.Isolate.EndpointID | The ID of the endpoint. | string |
| Traps.IsolateResult.Status | The status of the isolation operation. | string |
| Cybereason.Machine | Cybereason Machine name. | unknown |
| Cybereason.IsIsolated | Is the machine isolated. | unknown |
| Endpoint.Hostname | Hostname of the endpoint. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | The endpoint ID. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_name | The endpoint name. | unknown |
| PaloAltoNetworksXDR.Endpoint.endpoint_status | The status of the endpoint. | unknown |
| PaloAltoNetworksXDR.Endpoint.ip | The endpoint's IP addresses. | unknown |
| PaloAltoNetworksXDR.Endpoint.is_isolated | Whether the endpoint is isolated. | unknown |
| CbResponse.Sensors.Status | Sensor status. | unknown |
| CbResponse.Sensors.Isolated | Is sensor isolated. | unknown |

## Playbook Image
---
![Isolate Endpoint - Generic V2](Insert the link to your image here)