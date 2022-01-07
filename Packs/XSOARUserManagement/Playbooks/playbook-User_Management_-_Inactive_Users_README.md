

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Demisto REST API

### Scripts
* GetInactiveUsers

### Commands
* send-mail
* demisto-api-post

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DaysSinceLastActive | Number of days since user last logged into XSOAR. \(example, inactive_days=7 will return users that have been inactive for at least 7 days.\) | 365 | Required |
| SourceBrand | Integration SourceBrand Name that is being leveraged for SSO in XSOAR environment. If none leave empty<br/>\(i.e Okta V2\) |  | Optional |
| EmailAddress | Comma separated list of individuals emails to be notified which Users need to be removed from AD.<br/>Note: This is only if SSO is enabled. |  | Optional |
| autoDelete | Delete users from XSOAR automatically<br/>\(i.e true/false\)<br/>Note: This is only if SSO is NOT enabled. | true | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![User Management - Inactive Users](https://user-images.githubusercontent.com/72804710/148561641-cbae60ce-21ab-4aab-978e-a81a1c4977c0.png)
