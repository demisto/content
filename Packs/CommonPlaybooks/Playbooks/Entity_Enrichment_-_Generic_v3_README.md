Enrich entities using one or more integrations.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* IP Enrichment - Generic v2
* Account Enrichment - Generic v2.1
* Email Address Enrichment - Generic v2.1
* Domain Enrichment - Generic v2
* Endpoint Enrichment - Generic v2.1
* File Enrichment - Generic v2
* URL Enrichment - Generic v2
* CVE Enrichment - Generic v2

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
| IP | The IP addresses to enrich | IP.Address | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The comma-separated list should be provided in CIDR notation. For example, a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). | lists.PrivateIPs | Optional |
| MD5 | File MD5 to enrich | File.MD5 | Optional |
| SHA256 | File SHA256 to enrich | File.SHA256 | Optional |
| SHA1 | File SHA1 to enrich | File.SHA1 | Optional |
| URL | URL to enrich | URL.Data | Optional |
| Email | The email addresses to enrich | Account.Email.Address | Optional |
| Hostname | The hostname to enrich | Endpoint.Hostname | Optional |
| Username | The username to enrich | Account.Username | Optional |
| Domain | The domain name to enrich | Domain.Name | Optional |
| ResolveIP | Determines whether the IP Enrichment - Generic playbook should convert IP addresses to hostnames using a DNS query. True - Resolves the IP addresses to hostnames. False - Does not resolve the IP addresses to hostnames. | False | Optional |
| InternalDomains | A CSV list of internal domains. The list will be used to determine whether an email address is internal or external. |  | Optional |
| CVE | CVE ID to enrich. | CVE.ID | Optional |
| URLSSLVerification | Whether to verify SSL certificates for URLs.<br/>Can be True or False. | False | Optional |
| UseReputationCommand | Whether to execute the reputation command on the indicator. | False | Optional |
| AccountDomain | Optional - This input is needed for the IAM-get-user command \(used in the Account Enrichment - IAM playbook\). Please provide the domain name that the user is related to.<br/>Example: @xsoar.com |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP object. | unknown |
| Endpoint | The endpoint object. | unknown |
| Endpoint.Hostname | The hostname that was enriched. | string |
| Endpoint.OS | The endpoint's operating system. | string |
| Endpoint.IP | A list of endpoint IP addresses. | unknown |
| Endpoint.MAC | A list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The endpoint domain name. | string |
| DBotScore | The DBotScore object. | unknown |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File | The file object. | unknown |
| File.SHA1 | SHA1 hash of the file. | string |
| File.SHA256 | SHA256 hash of the file. | string |
| File.MD5 | MD5 hash of the file. | string |
| File.Malicious | Whether the file is malicious. | unknown |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | string |
| URL | The URL object. | uknown |
| URL.Data | The enriched URL. | string |
| URL.Malicious | Whether the detected URL was malicious. | unknown |
| URL.Vendor | Vendor that labeled the URL as malicious. | string |
| URL.Description | Additional information for the URL. | string |
| Domain | The domain object. | unknown |
| Account | The account object. | unknown |
| Account.Email | The email of the account. | unknown |
| Account.Email.NetworkType | The email account NetworkType \(Internal/External\). | string |
| Account.Email.Distance | The object that contains the distance between the email domain and the compared domain.  | unknown |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | number |
| ActiveDirectory.Users | An object containing information about the user from Active Directory. | unknown |
| ActiveDirectory.Users.sAMAccountName | The user's samAccountName. | unknown |
| ActiveDirectory.Users.userAccountControl | The user's account control flag. | unknown |
| ActiveDirectory.Users.mail | The user's email address. | unknown |
| ActiveDirectory.Users.memberOf | Groups the user is a member of. | unknown |
| CylanceProtectDevice | The device information about the hostname that was enriched using Cylance Protect v2. | unknown |
| PaloAltoNetworksXDR.RiskyUser | The account object. | string |
| PaloAltoNetworksXDR.RiskyUser.type | Form of identification element. | string |
| PaloAltoNetworksXDR.RiskyUser.id | Identification value of the type field. | string |
| PaloAltoNetworksXDR.RiskyUser.score | The score assigned to the user. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons | The account risk objects. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.date created | Date when the incident was created. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.description | Description of the incident. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.severity | The severity of the incident. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.status | The incident status. | string |
| PaloAltoNetworksXDR.RiskyUser.reasons.points | The score. | string |
| PaloAltoNetworksXDR.RiskyHost | The endpoint object. | string |
| PaloAltoNetworksXDR.RiskyHost.type | Form of identification element. | string |
| PaloAltoNetworksXDR.RiskyHost.id | Identification value of the type field. | string |
| PaloAltoNetworksXDR.RiskyHost.score | The score assigned to the host. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons | The endpoint risk objects. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.date created | Date when the incident was created. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.description | Description of the incident. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.severity | The severity of the incident. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.status | The incident status. | string |
| PaloAltoNetworksXDR.RiskyHost.reasons.points | The score. | string |
| Core | An object containing risky users and risky hosts as identified by the Core ITDR module. | unknown |
| Core.RiskyUser | The risky user object. | unknown |
| Core.RiskyUser.type | Form of identification element. | unknown |
| Core.RiskyUser.id | Identification value of the type field. | unknown |
| Core.RiskyUser.score | The score assigned to the user. | unknown |
| Core.RiskyUser.reasons | The reasons for the user risk level. | unknown |
| Core.RiskyUser.reasons.date created | Date when the incident was created. | unknown |
| Core.RiskyUser.reasons.description | Description of the incident. | unknown |
| Core.RiskyUser.reasons.severity | The severity of the incident. | unknown |
| Core.RiskyUser.reasons.status | The incident status. | unknown |
| Core.RiskyUser.reasons.points | The score. | unknown |
| Core.Endpoint | The endpoint object. | unknown |
| Core.RiskyHost | The risky host object. | unknown |
| Core.Endpoint.endpoint_id | The endpoint ID. | unknown |
| Core.Endpoint.endpoint_name | The endpoint name. | unknown |
| Core.Endpoint.endpoint_type | The endpoint type. | unknown |
| Core.Endpoint.endpoint_status | The status of the endpoint. | unknown |
| Core.Endpoint.os_type | The endpoint OS type. | unknown |
| Core.Endpoint.ip | A list of IP addresses. | unknown |
| Core.Endpoint.users | A list of users. | unknown |
| Core.Endpoint.domain | The endpoint domain. | unknown |
| Core.Endpoint.alias | The endpoint's aliases. | unknown |
| Core.Endpoint.first_seen | First seen date/time in Epoch \(milliseconds\). | unknown |
| Core.Endpoint.last_seen | Last seen date/time in Epoch \(milliseconds\). | unknown |
| Core.Endpoint.content_version | Content version. | unknown |
| Core.Endpoint.installation_package | Installation package. | unknown |
| Core.Endpoint.active_directory | Active directory. | unknown |
| Core.Endpoint.install_date | Install date in Epoch \(milliseconds\). | unknown |
| Core.Endpoint.endpoint_version | Endpoint version. | unknown |
| Core.Endpoint.is_isolated | Whether the endpoint is isolated. | unknown |
| Core.Endpoint.group_name | The name of the group to which the endpoint belongs. | unknown |
| Core.RiskyHost.type | Form of identification element. | unknown |
| Core.RiskyHost.id | Identification value of the type field. | unknown |
| Core.RiskyHost.score | The score assigned to the host. | unknown |
| Core.RiskyHost.reasons | The reasons for the risk level. | unknown |
| Core.RiskyHost.reasons.date created | Date when the incident was created. | unknown |
| Core.RiskyHost.reasons.description | Description of the incident. | unknown |
| Core.RiskyHost.reasons.severity | The severity of the incident. | unknown |
| Core.RiskyHost.reasons.status | The incident status. | unknown |
| Core.RiskyHost.reasons.points | The score. | unknown |

## Playbook Image

---

![Entity Enrichment - Generic v3](../doc_files/Entity_Enrichment_-_Generic_v3.png)
