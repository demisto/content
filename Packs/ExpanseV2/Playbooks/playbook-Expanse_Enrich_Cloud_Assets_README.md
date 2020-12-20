Subplaybook for Handle Expanse Incident playbooks.
This Playbook is used to enrich Public Cloud Assets by:
- Searching the corresponding Region and Service from IPRange feeds retrieved from Cloud Providers
- Searching IPs and FQDNs in Prisma Cloud

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Prisma Cloud - Find Public Cloud Resource by Public IP
* Prisma Cloud - Find Public Cloud Resource by FQDN
* Expanse Find Cloud IP Address Region and Service

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* associateIndicatorToIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | IP to enrich | incident.expanseip | Optional |
| FQDN | FQDN to enrich | incident.expansedomain | Optional |
| Provider | Cloud Provider | incident.expanseprovider | Optional |
| AWSIndicatorTags | Tags to identify AWS IP Ranges | AWS | Optional |
| GCPIndicatorTags | Tags to identify GCP IP Ranges | GCP | Optional |
| AzureIndicatorTags | Tags to identify Azure IP Ranges | Azure | Optional |
| Update Incident | Flag to check whether to update incident<br/><br/>Update means:<br/>- Set Expanse Region and Expanse Service to the values found from indicators<br/>- Link found indicators to the incident | True | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloud.Attribution | Prisma Cloud Asset Attribution | unknown |

## Playbook Image
---
![Expanse Enrich Cloud Assets](https://raw.githubusercontent.com/demisto/content/cfcd4dbc38cc4ec560202da62750c73c9452b553/Packs/ExpanseV2/Playbooks/playbook-Expanse_Enrich_Cloud_Assets.png)