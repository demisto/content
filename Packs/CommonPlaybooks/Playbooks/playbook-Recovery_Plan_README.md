This playbook handles all the recovery actions available with XSIAM.
The playbook allows to recover  from the incident with one of the following tasks:
* Unisolate endpoint
* Restore quarantined file

The playbook inputs allows you to manipulate the execution flow, please pay attention to the inputs description.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* core-unisolate-endpoint
* core-restore-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| unIsolateEndpoint | Boolean. Set to 'true' if you want to cancel the endpoint isolation. | true | Optional |
| releaseFile | Boolean. Set to 'true' if you want to release the quarantined file. | false | Optional |
| endpointID | The endpoint ID. |  | Optional |
| FileHash | The file hash. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Recovery Plan](https://raw.githubusercontent.com/demisto/content/f3d7d9140f4d82efde1704ed92b8de3176c35b2e/Packs/CommonPlaybooks/doc_files/Recovery_Plan.png)