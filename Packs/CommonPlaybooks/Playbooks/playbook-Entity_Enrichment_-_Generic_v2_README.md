Enriches entities using one or more integrations.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Email Address Enrichment - Generic v2.1
* Domain Enrichment - Generic v2
* Account Enrichment - Generic v2.1
* IP Enrichment - Generic v2
* Endpoint Enrichment - Generic v2.1
* URL Enrichment - Generic v2
* File Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IP | The IP addresses to enrich. | Address | IP | Optional |
| InternalRange | The list of internal IP address ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotes). If a list is not provided, the integration will use the default list provided in the `IsIPInRanges` script (the known IPv4 private address ranges). | -  | - | Optional |
| MD5 | The MD5 hash to enrich. | MD5 | File | Optional |
| SHA256 | The SHA256 hash to enrich. | SHA256 | File | Optional |
| SHA1 | The SHA1 hash to enrich. | SHA1 | File | Optional |
| URL | The URL to enrich. | Data | URL | Optional |
| Email | The email addresses to enrich. | Email.Address | Account | Optional |
| Hostname | The hostname to enrich. | Hostname | Endpoint | Optional |
| Username | The username to enrich .| Username | Account | Optional |
| Domain | The domain name to enrich. | Name | Domain | Optional |
| ResolveIP | Whether the IP address "Enrichment - Generic" playbook should convert IP addresses to hostnames using a DNS query. Can be either, "True" or "False". | False | - | Optional |
| InternalDomains | A CSV list of internal domains. The list will be used to determine whether an email address is "Internal" or "External". | - | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP address object. | unknown |
| Endpoint | The endpoint object. | unknown |
| Endpoint.Hostname | The hostname that was enriched. | string |
| Endpoint.OS | The endpoint's operating system. | string |
| Endpoint.IP | A list of endpoint IP addresses. | unknown |
| Endpoint.MAC | A list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The endpoint domain name. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File | The file object. | unknown |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.MD5 | The MD5 hash of the file. | string |
| File.Malicious | Whether the file is malicious. | unknown |
| File.Malicious.Vendor | The vendor that made the decision that the file is malicious. | string |
| URL | The URL object. | uknown |
| URL.Data | The enriched URL. | string |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Vendor | The vendor that labeled the URL as malicious. | string |
| URL.Description | Additional information for the URL. | string |
| Domain | The domain object. | unknown |
| Account | The account object. | unknown |
| Account.Email | The email of the account. | unknown |
| Account.Email.NetworkType | The email account networktype. Can be, "Internal" or "External". | string |
| Account.Email.Distance | The object that contains the distance between the email domain and the compared domain.  | unknown |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | number |
| ActiveDirectory.Users | An object containing information about the user from Active Directory. | unknown |
| ActiveDirectory.Users.sAMAccountName | The user's samAccountName. | unknown |
| ActiveDirectory.Users.userAccountControl | The user's account control flag. | unknown |
| ActiveDirectory.Users.mail | The user's email address. | unknown |
| ActiveDirectory.Users.memberOf | The groups the user is a member of. | unknown |
| CylanceProtectDevice | The device information about the hostname that was enriched using Cylance Protect v2. | unknown |

## Playbook Image
---
![Entity_Enrichment_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Entity_Enrichment_Generic_v2.png)
