Deprecated. Use "Email Address Enrichment - Generic v2.1" playbook instead. Enrich email addresses.  Email address enrichment involves:
- Getting information from Active Directory for internal addresses
- Getting the domain-squatting reputation for external addresses

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* ADGetUser
* Exists
* IsEmailAddressInternal
* EmailDomainSquattingReputation

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InternalDomains | A CSV list of internal domains. The list will be used to determine whether an email address is internal or external. | inputs.InternalDomains.None | Optional |
| Email | The email addresses to enrich. | Account.Email.Address | Optional |
| Domain | The domains associated with the incident. | inputs.Domain | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The Account object. | unknown |
| Account.Email.Address | The email account full address. | string |
| Account.Groups | The groups the account belongs to. | string |
| Account.Email.Domain | The email account domain. | string |
| Account.Email.NetworkType | The email account NetworkType \(Internal/External\). | string |
| Account.Type | Account entity type. | string |
| Account.Email.Username | The email account username. | string |
| Account.ID | The unique account DN \(Distinguished Name\). | string |
| Account.DisplayName | The account display name. | string |
| Account.Manager | The account's manager. | string |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | number |
| DBotScore.Indicator | The indicator. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The DBot score vendor. | string |
| DBotScore.Score | The DBot score. | number |

## Playbook Image
---
![Email Address Enrichment - Generic v2](Insert the link to your image here)