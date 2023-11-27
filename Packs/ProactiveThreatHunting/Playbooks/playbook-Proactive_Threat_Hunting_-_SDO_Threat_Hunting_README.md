This playbook will be executed when the analyst chooses to perform SDO hunting.
The playbook receives an SDO type indicator and executes the following steps:

- Searches IOCs related to the SDO indicator - IPs, Hashes, Domains, URLs.
- Hunts for the found IOCs using the "Threat Hunting - Generic" sub-playbook.
- Searches attack patterns that are related to the SDO indicator.
- Searches LOLBAS tools that are related to the found attack patterns.
- Hunts for LOLBin executions command-line arguments that are similar to LOLBAS  malicious commands patterns.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Threat Hunting - Generic
* Search LOLBAS Tools By Name
* TIM - Indicator Relationships Analysis
* Search and Compare Process Executions - Generic

### Integrations

This playbook does not use any integrations.

### Scripts

* SearchIndicatorRelationships
* Print
* Set
* SearchIndicator
* JsonToTable

### Commands

* setIncident
* appendIndicatorField
* associateIndicatorsToIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SDOName | The SDO name. |  | Optional |
| SDOType | The SDO type. | Campaign | Optional |
| HuntingTimeFrame | Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). The default is the last 24 hours. | 30 days | Optional |
| StringSimilarityThreshold | StringSimilarity automation threshold. StringSimilarity is being used in this playbook to compare between pattern of malicious use in a tool and command-line arguments found in the environment. Please provide number between 0 and 1, where 1 represents the most similar results of string comparisons. The automation will output only the results with a similarity score equal to or greater than the specified threshold. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Proactive Threat Hunting - SDO Threat Hunting](../doc_files/Proactive_Threat_Hunting_-_SDO_Threat_Hunting.png)
