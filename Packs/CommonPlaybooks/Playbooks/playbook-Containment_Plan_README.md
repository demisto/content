This playbook handles all the containment actions available with XSIAM.
The playbook allows to contain the incident with one of the following tasks:
* Isolate endpoint
* Disable account
* Quarantine file
* Block indicators
* Clear user session (currently, the playbook supports only Okta)

The playbook inputs allows you to manipulate the execution flow, please pay attention to the inputs description.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Account - Generic
* Block Indicators - Generic v2

### Integrations
* Okta v2

### Scripts
* IsIntegrationAvailable
* Set

### Commands
* okta-get-user
* core-get-endpoints
* okta-clear-user-sessions
* core-blocklist-files
* core-isolate-endpoint
* core-get-quarantine-status
* core-quarantine-files

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
| EndpointID | The endpoint ID to run commands over. |  | Optional |
| Username | The username to disable. |  | Optional |
| FileHash | The file hash to block. |  | Optional |
| FilePath | The path of the file to block. |  | Optional |
| IP | IP indicators. |  | Optional |
| Domain | Domain indicators. |  | Optional |
| IAMUserDomain | The Okta IAM users domain. The domain will be appended to the username. e.g. username@IAMUserDomain. | @demisto.com | Optional |
| FileRemediation | Choose 'Quarantine' or 'Delete'  to avoid file remediation conflicts. <br/>e.g. Choosing 'Quarantine' will ignore the 'Delete file' task under the eradication playbook and will execute only file quarantine and vice versa. | Quarantine | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Containment Plan](https://raw.githubusercontent.com/demisto/content/bd08dccb90f9847f6105c15345a4ca54017440e1/Packs/CommonPlaybooks/doc_files/Containment_Plan.png)