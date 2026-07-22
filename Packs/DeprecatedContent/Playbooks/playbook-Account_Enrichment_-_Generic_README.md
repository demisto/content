Deprecated. Use "Account Enrichment - Generic v2.1" playbook instead. Enrich Accounts using one or more integrations

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Exists
* ADGetUser

### Commands
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The Username to enrich | ${Account.Username} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | Account object | unknown |
| Account.Type | Type of the Account entity | string |
| Account.ID | The unique Account DN \(Distinguished Name\) | string |
| Account.Username | The Account username | string |
| Account.Email | The email address associated with the Account | unknown |
| Account.Groups | The groups the Account is part of | unknown |
| Account.DisplayName | The Account display name | string |
| Account.Manager | The Account's manager | string |

## Playbook Image
---
![Account_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Account_Enrichment_Generic.png)