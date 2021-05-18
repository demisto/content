This playbook investigates an access incident by gathering user and IP information.

The playbook then interacts with the user that triggered the incident to confirm whether or not they initiated the access action.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Active Directory - Get User Manager Details
* Account Enrichment - Generic v2.1
* IP Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* EmailAskUser

### Commands
* closeInvestigation
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SrcIP | The source IP address from which the incident originated. | incident.src | Optional |
| DstIP | The target IP address that was accessed. | incident.dest | Optional |
| Username | The username of the account that was used to access the DstIP. | incident.srcuser | Optional |
| Role | The default role to assign the incident to. | Administrator | Required |
| OnCall | Set to true to assign only the users that are currently on shift. Requires Cortex XSOAR v5.5 or later. | false | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email address object associated with the Account | string |
| DBotScore | Indicator, Score, Type, Vendor | unknown |
| Account.ID | The unique Account DN \(Distinguished Name\) | string |
| Account.Username | The Account username | string |
| Account.Email | The email address associated with the Account | unknown |
| Account.Type | Type of the Account entity | string |
| Account.Groups | The groups the Account is part of | unknown |
| Account | Account object | unknown |
| Account.DisplayName | The Account display name | string |
| Account.Manager | The Account's manager | string |
| DBotScore.Indicator | The indicator value | string |
| DBotScore.Type | The indicator's type | string |
| DBotScore.Vendor | The indicator's vendor | string |
| DBotScore.Score | The indicator's score | number |
| IP | The IP objects | unknown |
| Endpoint | The Endpoint's object | unknown |
| Endpoint.Hostname | The hostname to enrich | string |
| Endpoint.OS | Endpoint OS | string |
| Endpoint.IP | List of endpoint IP addresses | unknown |
| Endpoint.MAC | List of endpoint MAC addresses | unknown |
| Endpoint.Domain | Endpoint domain name | string |

## Playbook Image
---
![Access](https://raw.githubusercontent.com/demisto/content/a5e419535b376b08764f65670c24ea364072e869/Packs/AccessInvestigation/doc_files/Access_Investigation_-_Generic_4_5.png)
