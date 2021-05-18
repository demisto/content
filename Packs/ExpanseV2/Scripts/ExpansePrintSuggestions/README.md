Generates and prints a report in markdown format containing useful suggestions for the Analyst to attribute an Expanse Issue to an owner.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| expanse_users | Formatted list of users connecting to the service. |
| expanse_devices | Formatted list of firewall devices with evidence of connections. |
| expanse_ips | Formatted list of public IPs connecting to the service. |
| prisma_cloud_assets | Formatted list of assets found in Prisma Cloud related to this service. |
| shadow_it | List of Shadow IT checks and results. |
| ip | IP Address of the service. |
| port | Port of the service. |
| fqdn | FQDN or Domain of the service. |
| region | Public Cloud region. |
| service | Public cloud service \(i.e. EC2\). |
| provider | Provider of the service. |
| expanse_issue_tags | List of Expanse tags associated to the issue. |
| expanse_asset_tags | List of Expanse tags associated to the asset. |
| expanse_business_units | List of Expanse Business Units. |

## Outputs
---
There are no outputs for this script.
