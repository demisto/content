Deprecated. Use "Email Address Enrichment - Generic v2.1" playbook instead. Get email address reputation using one or more integrations

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Exists
* ADGetUser
* EmailReputation
* EmailDomainSquattingReputation
* IsEmailAddressInternal

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | A list of internal domains |  | Optional |
| Email | The email addresses to enrich | Account.Email.Address | Optional |
| GetReputation | Should the playbook get reputation for the Email Address | True | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The Account's object | unknown |
| Account.Email.Address | The Email account full address | string |
| Account.Groups | The groups the Account is part of | string |
| Account.Email.Domain | The Email account domain | string |
| Account.Email.NetworkType | The Email account NetworkType \(could be Internal/External\) | string |
| Account.Type | Type of the Account entity | string |
| Account.Email.Username | The Email account username | string |
| Account.ID | The unique Account DN \(Distinguished Name\) | string |
| Account.DisplayName | The Account display name | string |
| Account.Manager | The Account's manager | string |
| Account.Email.Distance.Domain | The compared domain | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain  | number |
| DBotScore.Indicator | The Indicator | string |
| DBotScore | The DBotScore's object | unknown |
| DBotScore.Type | The Indicator Type | string |
| DBotScore.Vendor | The DBot score vendor | string |
| DBotScore.Score | The DBot score | number |

## Playbook Image
---
![Email Address Enrichment - Generic](Insert the link to your image here)