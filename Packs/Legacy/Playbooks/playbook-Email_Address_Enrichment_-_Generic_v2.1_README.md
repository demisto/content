Enriches email addresses.
- Get information from Active Directory for internal addresses
- Get the domain-squatting reputation for external addresses

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* IsEmailAddressInternal
* EmailDomainSquattingReputation
* Exists

### Commands
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| InternalDomains | The CSV list of internal domains. The list will be used to determine whether an email address is internal or external. | None | inputs.InternalDomains | Optional |
| Email | The email addresses to enrich. | Email.Address | Account | Optional |
| Domain | The domains associated with the incident. These domains will be checked for domain-squatting. | None | inputs.Domain | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The account object. | unknown |
| Account.Email.NetworkType | The email account networktype. Can be, "Internal" or "External". | string |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | number |
| DBotScore | The DBotScore object. | unknown |

## Playbook Image
---
![Email_Address_Enrichment_Generic_v2.1](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Email_Address_Enrichment_Generic_v2.1.png)
