Deprecated. Use "Entity Enrichment - Generic v3" playbook instead. Enrich entities using one or more integrations

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* URL Enrichment - Generic
* IP Enrichment - Generic
* File Enrichment - Generic
* Account Enrichment - Generic
* Domain Enrichment - Generic
* Email Address Enrichment - Generic
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
| IP | The IP addresses to enrich | ${IP.Address} | Optional |
| InternalRange | The internal range to check against the IPs |  | Optional |
| MD5 | File MD5 to enrich | ${File.MD5} | Optional |
| SHA256 | File SHA256 to enrich | ${File.SHA256} | Optional |
| SHA1 | File SHA1 to enrich | ${File.SHA1} | Optional |
| url | url to enrich | ${URL.Data} | Optional |
| Email | The email addresses to enrich | ${Account.Email.Address} | Optional |
| Hostname | The hostname to enrich | ${Endpoint.Hostname} | Optional |
| Username | The Username to enrich | ${Account.Username} | Optional |
| Domain | The domain name to enrich | ${Domain.Name} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The Account's object | unknown |
| Account.ID | The unique Account DN \(Distinguished Name\) | string |
| Domain | The domain objects | unknown |
| URL | The URL's object | unknown |
| URL.Malicious | whether url was detected as malicious | unknown |
| URL.Vendor | name of vendor who labeled as malicious | string |
| URL.Description | additional info on the url | string |
| URL.Address | The enriched URL | string |
| Account.Email.Address | The Email account full address | string |
| IP | The IP objects | unknown |
| Account.Email.Domain | The Email account domain | string |
| Account.Email.NetworkType | The Email account NetworkType \(could be Internal/External\) | string |
| Account.Email.Username | The Email account username | string |
| Account.Email.Distance.Domain | The compared domain | unknown |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain  | string |
| Account.Type | Type of the Account entity | string |
| Account.Username | The Account username | string |
| Account.Email | The email address associated with the Account | unknown |
| Account.Groups | The groups the Account is part of | unknown |
| Account.DisplayName | The Account display name | string |
| Account.Manager | The Account's manager | string |
| File | The File's object | unknown |
| File.MD5 | MD5 hash of the file | string |
| File.SHA1 | SHA1 hash of the file | string |
| File.SHA256 | SHA256 hash of the file | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision | string |
| Endpoint | The Endpoint's object | unknown |
| Endpoint.Hostname | The hostname to enrich | string |
| Endpoint.OS | Endpoint OS | string |
| Endpoint.IP | List of endpoint IP addresses | unknown |
| Endpoint.MAC | List of endpoint MAC addresses | unknown |
| Endpoint.Domain | Endpoint domain name | string |
| DBotScore | The Indicator's object | unknown |
| DBotScore.Indicator | The Indicator | string |
| DBotScore.Type | The Indicator Type | string |
| DBotScore.Vendor | The DBot score vendor | string |
| DBotScore.Score | The DBot score | number |

## Playbook Image
---
![Entity Enrichment - Generic](Insert the link to your image here)