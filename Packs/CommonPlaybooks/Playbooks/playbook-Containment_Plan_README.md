This playbook handles all the incident containment actions available with Cortex XSIAM, including the following tasks:
* Isolate endpoint
* Disable account
* Quarantine file
* Block indicators (currently, the playbook supports only hashes)
* Clear user session (currently, the playbook supports only Okta)

**Note:** The playbook inputs enable manipulating the execution flow; read the input descriptions for details.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Block Account - Generic

### Integrations
Okta v2

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
| AutoContainment | Whether to automatically execute the containment plan \(except isolation\).<br/>The specific containment playbook inputs should also be set to 'True'. | False | Optional |
| HostAutoContainment | Whether to automatically execute endpoint isolation. | True | Optional |
| UserContainment | Set to True to disable the user account. | True | Optional |
| BlockIndicators | Set to True to block the indicators. | True | Optional |
| FileContainment | Set to True to quarantine the identified file. | True | Optional |
| ClearUserSessions | Set to True to clear the user active Okta sessions. | True | Optional |
| EndpointID | The endpoint ID to run commands over. | alert.agentid | Optional |
| Username | The username to disable. |  | Optional |
| FileHash | The file hash to block. |  | Optional |
| FilePath | The path of the file to block. |  | Optional |
| IAMUserDomain | The Okta IAM user domain. The domain is appended to the username. For example, username@IAMUserDomain. | @demisto.com | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>For example, Choosing 'Quarantine' ignores the 'Delete file' task under the eradication playbook and executes only file quarantine. | Quarantine | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Containment Plan](https://raw.githubusercontent.com/demisto/content/f3d7d9140f4d82efde1704ed92b8de3176c35b2e/Packs/CommonPlaybooks/doc_files/Containment_Plan.png)
