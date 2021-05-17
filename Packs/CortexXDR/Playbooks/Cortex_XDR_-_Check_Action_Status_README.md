Checks the action status of an action ID. 
Enter the action ID of the action whose status you want to know. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Cortex XDR - IR

### Scripts
* PrintErrorEntry

### Commands
* xdr-action-status-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| action_id | Action ID of the specific request. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.GetActionStatus | Get Action Status command results. | unknown |
| PaloAltoNetworksXDR.GetActionStatus.endpoint_id | Endpoint ID. | string |
| PaloAltoNetworksXDR.GetActionStatus.status | Status of the specific endpoint ID. | string |
| PaloAltoNetworksXDR.GetActionStatus.action_id | The action ID. | number |

## Playbook Image
---
![Cortex XDR - Check Action Status](https://raw.githubusercontent.com/demisto/content/0b71472b92a1bfa604215334b27c49a40c0260dd/Packs/CortexXDR/doc_files/Cortex%20XDR%20-%20Check%20Action%20Status.png)
