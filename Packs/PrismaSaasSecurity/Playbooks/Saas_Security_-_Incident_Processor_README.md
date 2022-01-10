This playbook notifies incidents owner and provides remediation options to Saas Security admin for resolving incidents. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Send Action Taken Email to Tenant Admin
* Send Action Taken Email to Assignee

### Integrations
* EWS Mail Sender

### Scripts
This playbook does not use any scripts.

### Commands
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| updated_at | This is the incident updated at timestamp. | ${incident.saassecurityincidentupdatedat} | Optional |
| tenant_admin | This is the tenant admin email. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SaasSecurity.Incident.incident_id | Incident ID. | unknown |
| SaasSecurity.Incident.tenant | Tenant associated with the incident. | unknown |
| SaasSecurity.Incident.app_id | Application ID. | unknown |
| SaasSecurity.Incident.app_name | Application name. | unknown |
| SaasSecurity.Incident.app_type | Application type. | unknown |
| SaasSecurity.Incident.cloud_id | Cloud ID. | unknown |
| SaasSecurity.Incident.asset_name | Asset name. | unknown |
| SaasSecurity.Incident.asset_sha256 | SHA256 hash value of the asset. | unknown |
| SaasSecurity.Incident.asset_id | Asset ID. | unknown |
| SaasSecurity.Incident.asset_page_uri | Asset page URI. | unknown |
| SaasSecurity.Incident.asset_cloud_uri | Asset cloud URI. | unknown |
| SaasSecurity.Incident.exposure_type | Exposure type \(Internal/External\). | unknown |
| SaasSecurity.Incident.exposure_level | Exposure level. | unknown |
| SaasSecurity.Incident.policy_id | Policy ID. | unknown |
| SaasSecurity.Incident.policy_name | Policy name. | unknown |
| SaasSecurity.Incident.policy_version | Policy version. | unknown |
| SaasSecurity.Incident.policy_page_uri | Policy page URI. | unknown |
| SaasSecurity.Incident.severity | Severity of the incident. | unknown |
| SaasSecurity.Incident.status | Incident status. | unknown |
| SaasSecurity.Incident.state | Incident state. | unknown |
| SaasSecurity.Incident.category | Incident category. | unknown |
| SaasSecurity.Incident.resolved_by | Name of the user who resolved the incident. | unknown |
| SaasSecurity.Incident.resolution_date | Date the incident was resolved. | unknown |
| SaasSecurity.Incident.created_at | Date the incident was created, e.g., \`2021-08-23T09:26:25.872Z\`. | unknown |
| SaasSecurity.Incident.updated_at | Date the incident was last updated. e.g., \`2021-08-24T09:26:25.872Z\`. | unknown |
| SaasSecurity.Incident.asset_owner_id | ID of the asset owner. | unknown |
| SaasSecurity.Incident.asset_owner_name | Name of the asset owner. | unknown |
| SaasSecurity.Incident.asset_owner_email | Email address of the asset owner. | unknown |

## Playbook Image
---
![Saas Security - Incident Processor](https://raw.githubusercontent.com/demisto/content/6f87824ee719814f27e0f77068242924617de9a1/Packs/PrismaSaasSecurity/doc_files/Incident_Processor_Playbook.png)