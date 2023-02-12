This playbook executes when no other playbook is associated with an incident. It performs the following actions:
- Extracts and enriches indicators in an incident using one or more integrations.
- Deduplicates by linking and closing similar incidents.
- Retrieves related files from endpoints using hash / file path.
- Hunts for occurrences of suspicious files in the organization's endpoints.
- Unzips zipped files, and extracts indicators from them.
- Analyzes suspicious command line executions if included in the incident.
- Detonates files and URLs in sandbox integrations.
- Calculates a severity for the incident.
- Allows the analyst to remediate the incident by blocking malicious indicators that were found.



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Dedup - Generic v4
* Get File Sample - Generic
* Detonate File - Generic
* Calculate Severity - Generic v2
* Search Endpoints By Hash - Generic V2
* Extract Indicators From File - Generic v2
* Entity Enrichment - Generic v3
* Detonate URL - Generic
* Block Indicators - Generic v3

### Integrations
This playbook does not use any integrations.

### Scripts
* GenerateInvestigationSummaryReport
* Set
* SetMultipleValues

### Commands
* setIncident
* closeInvestigation
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExtractIndicators | Determines whether indicators in this incident should be extracted manually. If you turned off Auto-extract for the current incident type, you may want to set this value to True. Otherwise indicators from this incident will not be extracted, which will negatively affect the efficacy of the playbook. | True | Optional |
| MaliciousTagName | The tag to assign for indicators to block. Tagging indicators can be done through the buttons in the incident layout. | malicious | Optional |
| BenignTagName | The tag to assign for allowed indicators. Tagging indicators can be done through the buttons in the incident layout. | benign | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Default](../doc_files/Default.png)