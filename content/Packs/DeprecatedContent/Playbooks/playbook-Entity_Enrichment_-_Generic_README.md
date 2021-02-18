DEPRECATED. Use "Entity Enrichment - Generic v3" playbook instead. Enriches entities using one or more integrations.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Account Enrichment - Generic
* IP Enrichment - Generic
* File Enrichment - Generic
* Email Address Enrichment - Generic
* URL Enrichment - Generic
* Domain Enrichment - Generic
* Endpoint Enrichment - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| IP | The IP addresses to enrich. | ${IP.Address} | Optional |
| InternalRange | The internal range to check against the IP address. | - | Optional |
| MD5 | The MD5 hash to enrich. | ${File.MD5} | Optional |
| SHA256 | The SHA256 hash to enrich. | ${File.SHA256} | Optional |
| SHA1 | The SHA1 hash to enrich. | ${File.SHA1} | Optional |
| url | The URL to enrich. | ${URL.Data} | Optional |
| Email | The email addresses to enrich. | ${Account.Email.Address} | Optional |
| Hostname | The hostname to enrich. | ${Endpoint.Hostname} | Optional |
| Username | The username to enrich. | ${Account.Username} | Optional |
| Domain | The domain name to enrich. | ${Domain.Name} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The account's object. | unknown |
| Account.ID | The unique account DN (Distinguished Name). | string |
| Domain | The domain objects. | unknown |
| URL | The URL's object. | unknown |
| URL.Malicious | Whether the URL was detected as malicious. | unknown |
| URL.Vendor | The name of vendor who labeled the URL as malicious. | string |
| URL.Description | The additional information of the URL. | string |
| URL.Address | The enriched URL. | string |
| Account.Email.Address | The email account's full address. | string |
| IP | The IP address objects. | unknown |
| Account.Email.Domain | The email account's domain. | string |
| Account.Email.NetworkType | The email account networktype. Can be, "Internal" or "External". | string |
| Account.Email.Username | The email account username. | string |
| Account.Email.Distance.Domain | The compared domain. | unknown |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | string |
| Account.Type | The type of the account entity. | string |
| Account.Username | The account username. | string |
| Account.Email | The email address associated with the account. | unknown |
| Account.Groups | The groups the account is part of. | unknown |
| Account.DisplayName | The account display name. | string |
| Account.Manager | The account's manager. | string |
| File | The file's object. | unknown |
| File.MD5 | The MD5 hash of the file. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.Malicious.Vendor | The vendor that made the decision that the file was malicious. | string |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |
| DBotScore | The indicator's object. | unknown |
| DBotScore.Indicator | The indicator. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The DBot score vendor. | string |
| DBotScore.Score | The DBot score. | number |

## Playbook Image
---
![Entity_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Entity_Enrichment_Generic.png)
