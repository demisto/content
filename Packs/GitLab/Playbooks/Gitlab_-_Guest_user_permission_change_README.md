This playbook investigates a "User Permissions Changed” alert by gathering user and IP information and performs remediation based on the information gathered and received from the user. To link this playbook to the relevant alerts automatically, we recommend using the following filters when configuring the playbook triggers: Alert Source = Correlation AND Alert Name = Gitlab - Guest user permission change

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Enrichment for Verdict
* Block IP - Generic v3
* Block Account - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setAlert
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InternalRange | List of internal IP ranges. |  | Optional |
| UserVerification | Whether to provide user verification for blocking those IPs. <br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Gitlab - Guest user permission change](../doc_files/Gitlab_-_Guest_user_permission_change.png)
