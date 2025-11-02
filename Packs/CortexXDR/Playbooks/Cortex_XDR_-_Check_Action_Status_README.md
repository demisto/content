Checks the action status of an action ID. \nEnter the action ID of the action whose status you want to know.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CortexXDRIR

### Scripts
* PrintErrorEntry

### Commands
* xdr-action-status-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| action_id | Action ID of the specific request. |  | Optional |
| timeout | Amount of time to poll before declaring a timeout and resuming the playbook \(in minutes\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.GetActionStatus | Gets Action Status command results. | unknown |
| PaloAltoNetworksXDR.GetActionStatus.endpoint_id | Endpoint ID. | string |
| PaloAltoNetworksXDR.GetActionStatus.status | Status of specific endpoint ID. | string |
| PaloAltoNetworksXDR.GetActionStatus.action_id | The action ID that was the input. | number |
