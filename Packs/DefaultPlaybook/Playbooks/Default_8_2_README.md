This playbook executes when no other playbook is associated with an incident. It performs the following actions:
- Extracts and enriches indicators in an incident using one or more integrations.
- Deduplicates by linking and closing similar incidents.
- Retrieves related files from endpoints using hash / file path.
- Hunts for occurrences of suspicious files in the organization's endpoints.
- Unzips zipped files, and extracts indicators from them.
- Detonates files and URLs in sandbox integrations.
- Calculates a severity for the incident.
- Allows the analyst to remediate the incident by blocking malicious indicators that were found.



## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Extract Indicators From File - Generic v2
* Search Endpoints By Hash - Generic V2
* Detonate URL - Generic v1.5
* Dedup - Generic v4
* Entity Enrichment - Generic v3
* Get File Sample - Generic
* Calculate Severity - Generic v2
* Block Indicators - Generic v3
* Detonate File - Generic

### Integrations

This playbook does not use any integrations.

### Scripts

* GenerateInvestigationSummaryReport
* Set

### Commands

* extractIndicators
* closeInvestigation
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExtractIndicators | Determines whether indicators in this incident should be extracted manually. If you turned off Auto-extract for the current incident type, you may want to set this value to True. Otherwise, indicators from this incident will not be extracted, which will negatively affect the efficacy of the playbook. | True | Optional |
| AdvancedInvestigation | Whether to perform advanced actions in the incident. This overrides the ExtractIndicators input as if it was set to False.<br/><br/>Possible values are: True, False.<br/><br/>If set to False, the playbook will still perform major steps such as out-of-band indicator extraction, basic file extraction and calculating severity for the incident.<br/><br/>If set to True, advanced steps will be executed:<br/>- Getting file samples from endpoints.<br/>- Searching more endpoints by the extracted file hash.<br/>- Detonating files and URLs in sandbox integrations.<br/><br/> | False | Optional |
| DedupSimilarIncidents | Whether to deduplicate incidents that are similar to the current incident. Can be True or False. | False | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Default](../doc_files/Default.png)
