Subplaybook for Expanse Enrich Cloud Assets subplaybook.
Finds Region and Service for IP Address belonging to Public Cloud, using
Indicators (CIDRs) from Public Cloud feeds. Correlates based on longest match.
Returns the matching indicator with the longest prefix.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

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
| ip | IP Address to find. | ${IP.Address} | Required |
| Provider | Cloud Provider \(Google,Amazon web services,Microsoft azure\) or empty to search in all. |  | Optional |
| AWSIndicatorTags | Tags to search for AWS Indicators. | AWS | Optional |
| GCPIndicatorTags | Tags to search for GCP Indicators. | GCP | Optional |
| AzureIndicatorTags | Tags to search for Azure Indicators. | Azure | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchingCIDRIndicator | Matching CIDR Indicator | unknown |

## Playbook Image
---
![Expanse Find Cloud IP Address Region and Service](https://raw.githubusercontent.com/demisto/content/cfcd4dbc38cc4ec560202da62750c73c9452b553/Packs/ExpanseV2/Playbooks/playbook-Expanse_Find_Cloud_IP_Address_Region_and_Service.png)