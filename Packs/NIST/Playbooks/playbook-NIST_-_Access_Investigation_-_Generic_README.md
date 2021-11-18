Investigates an access incident by gathering user and IP address information, and handling the incident based on the stages in "[Handling an incident - Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)" by NIST.


Used Sub-playbooks:
- IP Enrichment - Generic v2
- Account Enrichment - Generic v2.1
- Block IP - Generic v2
- NIST - Lessons Learned

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Enrichment - Generic v2
* NIST - Lessons Learned
* Block IP - Generic v2
* Account Enrichment - Generic v2.1

### Integrations
* Active Directory Query v2
* Builtin

### Scripts
* ADGetUser
* GenerateInvestigationSummaryReport

### Commands
* closeInvestigation
* send-mail
* ad-expire-password
* setIncident
* ad-disable-account

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| SrcIP | The source IP address from which the incident originated. |Optional |
| DstIP | The target IP address that was accessed. | Optional |
| Username | The email address of the account that was used to access the DstIP. | Optional |
| NotifyEmail | The email addresses to notify about the incident. | Optional |
| RemediationSLA | The remediation SLA for the "Containment, Eradication, and Recovery" stage (in minutes). | Optional |
| IPBlacklistMiner | The name of the IP address block list miner in MineMeld. | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Email.Address | The email address object associated with the account. | string |
| DBotScore | The Indicator, Score, Type, and Vendor. | unknown |
| Account.ID | The unique account DN (Distinguished Name). | string |
| Account.Username | The account username. | string |
| Account.Email | The email address associated with the account. | unknown |
| Account.Type | The type of the account entity. | string |
| Account.Groups | The groups the account is part of. | unknown |
| Account | The account object. | unknown |
| Account.DisplayName | The account display name. | string |
| Account.Manager | The account's manager. | string |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator's type. | string |
| DBotScore.Vendor | The indicator's vendor. | string |
| DBotScore.Score | The indicator's score. | number |
| IP | The IP address's objects. | unknown |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of Endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of Endpoint MAC addresses | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

## Playbook Image
---
![NIST_Access_Investigation_Generic](https://github.com/demisto/content/raw/9b18afbd67ebda0d36202e07229062385da53223/Packs/NIST/doc_files/Access_Investigation_-_Generic_-_NIST.png)
