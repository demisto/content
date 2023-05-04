Automatically discover and enrich indicators with the same actor and source as the triggering IOC. Search for and isolate any compromised endpoints and proactively block IOCs from entering your network.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Search Endpoints By Hash - Generic V2
* Block Indicators - Generic v2
* Entity Enrichment - Generic v2
* Isolate Endpoint - Generic V2

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* SetAndHandleEmpty
* SixgillSearchIndicators
* ToTable

### Commands
* associateIndicatorToIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | File hash \(MD5, SHA-1, SHA-256\) from Darkfeed | File | Optional |
| URL | URL from Darkfeed | URL | Optional |
| Maximum number of IOCs | Set value to the maximum number of IOCs you would like returned in searches for items from the same source and same actor | 50 | Optional |
| Query time lookup | Set value to the number of days back in searches for IOCs with the same source and same actor | 3 day ago | Optional |
| IP | IP address from Darkfeed | IP | Optional |
| Is automated endpoint isolation activated? | Set "yes" if you would like to automatically isolate endpoints on which malicious indicators were detected | no | Optional |
| Is automated blocking activated? | Set "yes" if you would like to automatically block discovered malicious indicators. | no | Optional |
| Domain | Domain from Darkfeed | Domain.Name | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Darkfeed Threat hunting-research](../doc_files/Darkfeed_Threat_hunting-research.png)