Enrich an endpoint by hostname using XM Cyber integration. Outputs include affected assets, affected entities, complexity of compromise, and more

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* XMCyber

### Scripts
* IsIntegrationAvailable

### Commands
* hostname
* xmcyber-affected-critical-assets-list
* xmcyber-affected-entities-list

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to enrich. | Endpoint.Hostname | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The endpoint object of the endpoint that was enriched. | unknown |
| Endpoint.Hostname | The hostnames of the endpoints that were enriched. | string |
| Endpoint.OS | The operating systems running on the endpoints that were enriched. | string |
| Endpoint.IP | A list of the IP addresses of the endpoints. | string |
| XMCyber.Entity.isAsset | Is Entity a Critical Asset | boolean |
| XMCyber.Entity.affectedEntities | Number of unique entities at risk from this entity | number |
| XMCyber.Entity.averageComplexity | Average complexity to compromise this entity | number |
| XMCyber.Entity.criticalAssetsAtRisk | Number of unique critical assets at risk from this entity | number |
| XMCyber.Entity.averageComplexityLevel | Level of the average complexity to compromise this entity | string |
| XMCyber.Entity.id | XMCyber Entity ID | string |
| XMCyber.Entity.criticalAssetsAtRiskList | Critical assets at risk from this entity | unknown |
| XMCyber.Entity.entitiesAtRiskList | Entities at risk from this entity | unknown |

## Playbook Image
---
![Endpoint Enrichment - XM Cyber](https://github.com/matan-xmcyber/content/blob/master/docs/images/playbooks/Endpoint_Enrichment_XM_Cyber.png)
