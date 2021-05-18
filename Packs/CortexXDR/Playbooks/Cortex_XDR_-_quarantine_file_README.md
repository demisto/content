This playbook accepts file path, file hash and endpoint id in order to quarantine a selected file and wait until the action is done.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-quarantine-file
* xdr-get-quarantine-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| endpoint_id | The endpoint ID \(string\) to search the selected file. You can retrieve the ID using the xdr\-get\-endpoints command. |  | PaloAltoNetworksXDR | Mandatory |
| file_hash | Hash must be a valid SHA256. |  | Endpoint | Mandatory |
| file_path | the path of the file you want to quarantine. |  |Endpoint  | Mandatory |

## Playbook Outputs
---
Quarantine status. true if the action was successful and false otherwise.