Enriches the incident with asset details and the asset with the incident URL on the RiskIQ Digital Footprint platform. This playbook also sends an email containing the owner's information to the primary or secondary contact of the asset and provides the user with an opportunity to update or remove the asset.
Supported integration:
- RiskIQ Digital Footprint

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Update Or Remove Assets - RiskIQ Digital Footprint

### Integrations
* RiskIQ Digital Footprint

### Scripts
* DeleteContext
* GetServerURL

### Commands
* setIncident
* df-update-assets
* df-get-asset
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| asset_type | Type of the asset. Possible values: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert, Contact. This input supports a single value only. | incident.riskiqassettype | Required |
| asset_name | Name of the asset. | incident.riskiqassetname | Required |
| skip_manual_tasks | Skip the manual tasks and do not prompt for user input. Possible values: "Yes" and "No". The default value is "No". | incident.riskiqskipmanualtasks | Optional |
| support_email_address | The contact email address of the support team from which manual inputs should be fetched. | incident.riskiqsupportcontact | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Enrich Incident With Asset Details - RiskIQ Digital Footprint](../doc_files/Enrich_Incident_With_Asset_Details_-_RiskIQ_Digital_Footprint.png)