Retrieves and downloads files.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Traps

### Scripts
This playbook does not use any scripts.

### Commands
* traps-endpoint-files-retrieve
* traps-endpoint-files-retrieve-result

## Playbook Inputs
---

| **Name** | **Description** |  **Required** |
| --- | --- | --- |  
| endpoint_id | The ID of the endpoint. | Required |
| file_name | The name of the file to retrieve (including path). | Required |
| event_id | The ID of the Event. | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Traps_Retrieve_And_Download_FIles](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Traps_Retrieve_And_Download_FIles.png)
