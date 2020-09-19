DEPRECATED. Use "Email Address Enrichment - Generic v2.1" playbook instead. Gets an email addresses's reputation using one or more integrations.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* EmailDomainSquattingReputation
* IsEmailAddressInternal
* ADGetUser
* Exists
* EmailReputation

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Domain | The list of internal domains. | - | - | Optional |
| Email | The email addresses to enrich. | Email.Address | Account | Optional |
| GetReputation | Whether the playbook should get the reputation for the email address. | True | - | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The account's object. | unknown |
| Account.Email.Address | The email account's full address. | string |
| Account.Groups | The groups the account is part of. | string |
| Account.Email.Domain | The email's account domain. | string |
| Account.Email.NetworkType | The email account's networktype. Can be, "Internal" or "External". | string |
| Account.Type | The type of the account entity. | string |
| Account.Email.Username | The email account username. | string |
| Account.ID | The unique Account DN (Distinguished Name). | string |
| Account.DisplayName | The account display name. | string |
| Account.Manager | The account's manager. | string |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain. | number |
| DBotScore.Indicator | The indicator. | string |
| DBotScore | The DBotScore's object. | unknown |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The DBot score vendor. | string |
| DBotScore.Score | The DBot score. | number |

## Playbook Image
---
![Email_Address_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Email_Address_Enrichment_Generic.png)
