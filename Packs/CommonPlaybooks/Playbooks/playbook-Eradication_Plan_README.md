This playbook handles all the eradication actions available with XSIAM.
The playbook allows to eradicate the incident with one of the following tasks:
* Reset user password
* Delete file
* Kill process (currently, the playbook supports terminating a process by name)

The playbook inputs allows you to manipulate the execution flow, please pay attention to the inputs description.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
* core-run-script-delete-file
* ad-expire-password
* core-run-script-kill-process

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoEradicate | Boolean. Set to 'true' if you want to execute the eradication playbook automatically. | Auto | Optional |
| EndpointID | The endpoint ID. | alert.agentid | Optional |
| FilePath | The file path for the file deletion task. | foundIncidents.CustomFields.initiatorpath | Optional |
| Username | The username to reset password for. | foundIncidents.CustomFields.username | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>e.g. Choosing 'Delete' will ignore the 'Quarantine file' task under the containment playbook and will execute only file deletion and vice versa. | Delete | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Eradication Plan](https://raw.githubusercontent.com/demisto/content/f3d7d9140f4d82efde1704ed92b8de3176c35b2e/Packs/CommonPlaybooks/doc_files/Eradication_Plan.png)