This playbook handles all the eradication actions available with Cortex XSIAM, including the following tasks:
* Reset user password
* Delete file
* Kill process (currently, the playbook supports terminating a process by name)  

Note: The playbook inputs enable manipulating the execution flow; read the input descriptions for details.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* IsIntegrationAvailable

### Commands
* ad-expire-password
* core-run-script-delete-file
* core-run-script-kill-process

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoEradicate | Set to True to execute the eradication playbook automatically. | Auto | Optional |
| EndpointID | The endpoint ID. | alert.agentid | Optional |
| FilePath | The file path for the file deletion task. | foundIncidents.CustomFields.initiatorpath | Optional |
| Username | The username to reset the password for. | foundIncidents.CustomFields.username | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>For example, choosing 'Delete' ignores the 'Quarantine file' task under the containment playbook and executes only file deletion. | Delete | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Eradication Plan](https://raw.githubusercontent.com/demisto/content/48a7f1a1a628a2755201c55c24bc68d94e0dd49c/Packs/CommonPlaybooks/doc_files/Eradication_Plan.png)