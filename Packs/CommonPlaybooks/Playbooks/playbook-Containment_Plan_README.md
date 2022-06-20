This playbook handles all the alert containment actions available with Cortex XSIAM, including the following tasks:
* Isolate endpoint
* Disable account
* Quarantine file
* Block indicators
* Clear user session (currently, the playbook supports only Okta)

**Note:** The playbook inputs enable manipulating the execution flow; read the input descriptions for details.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Indicators - Generic v2
* Block Account - Generic

### Integrations
This playbook does not use any integrations.

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
| HostContainment | Whether to execute endpoint isolation automatically. | True | Optional |
| UserContainment | Set to 'True' to disable the user account. | True | Optional |
| BlockIndicators | Set to 'True' to block the indicators. | True | Optional |
| FileContainment | Set to 'True' to quarantine the identified file. | True | Optional |
| ClearUserSessions | Set to 'True' to clear the user active Okta sessions. | True | Optional |
| EndpointID | The endpoint ID to run commands over. |  | Optional |
| Username | The username to disable. |  | Optional |
| FileHash | The file hash to block. |  | Optional |
| FilePath | The path of the file to block. |  | Optional |
| IP | The IP indicators. |  | Optional |
| Domain | The domain indicators. |  | Optional |
| URL | The URL indicator. |  | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>For example, choosing 'Quarantine' ignores the 'Delete file' task under the eradication playbook and will execute only file quarantine. | Quarantine | Optional |
| IAMUserDomain | The Okta IAM users domain. The domain will be appended to the username. e.g. username@IAMUserDomain. | @demisto.com | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Containment Plan](https://raw.githubusercontent.com/demisto/content/48a7f1a1a628a2755201c55c24bc68d94e0dd49c/Packs/CommonPlaybooks/doc_files/Containment_Plan.png)