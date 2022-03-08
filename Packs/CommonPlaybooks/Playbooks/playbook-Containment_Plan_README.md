This playbook handles all the containment actions available with XSIAM.
The playbook allows to contain the incident with one of the following tasks:
* Isolate endpoint
* Disable account
* Quarantine file
* Block indicators (currently, the playbook supports only hashes)
* Clear user session (currently, the playbook supports only Okta)

The playbook inputs allows you to manipulate the execution flow, please pay attention to the inputs description.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Account - Generic

### Integrations
* Okta v2

### Scripts
* IsIntegrationAvailable
* Set

### Commands
* okta-clear-user-sessions
* core-isolate-endpoint
* core-blocklist-files
* okta-get-user
* core-quarantine-files
* core-get-endpoints
* core-get-quarantine-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoContainment | Whether to execute containment plan \(except isolation\) automatically.<br/>The specific containment playbook inputs should also be set to 'True'. | False | Optional |
| HostAutoContainment | Whether to execute endpoint isolation automatically. | True | Optional |
| UserContainment | Boolean. Set to 'true' if you want to disable the user account. | True | Optional |
| BlockIndicators | Boolean. Set to 'true' if you want to block the indicators. | True | Optional |
| FileContainment | Boolean. Set to 'true' if you want to quarantine the identified file. | True | Optional |
| ClearUserSessions | Boolean. Set to 'true' if you want to clear the user active Okta sessions. | True | Optional |
| EndpointID | The endpoint ID to run commands over. | alert.agentid | Optional |
| Username | The username to disable. |  | Optional |
| FileHash | The file hash to block. |  | Optional |
| FilePath | The path of the file to block. |  | Optional |
| IAMUserDomain | The Okta IAM users domain. The domain will be appended to the username. e.g. username@IAMUserDomain. | @demisto.com | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>e.g. Choosing 'Quarantine' will ignore the 'Delete file' task under the eradication playbook and will execute only file quarantine and vice versa. | Quarantine | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Containment Plan](https://raw.githubusercontent.com/demisto/content/f3d7d9140f4d82efde1704ed92b8de3176c35b2e/Packs/CommonPlaybooks/doc_files/Containment_Plan.png)