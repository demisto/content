This playbook takes the command-line from the alert and perform the following action:
- Checks and decode base64
- Extracts and enrich indicators from the command line
- Checks specific arguments for malicious usage 
At the end, the playbook will set a possible verdict for the command-line based on the finding.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexCoreIR

### Scripts
* Set
* Base64Decode
* MatchRegexV2

### Commands
* core-get-dynamic-analysis
* extractIndicators
* enrichIndicators

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchRegex | The value matched by the regex | unknown |
| Indicators | Extracted indicators from the command-line | unknown |
| commandline | The command-line | unknown |
| CommandlineVerdict | The verdict of the command-line | unknown |

## Playbook Image
---
![Command-Line Analysis](Insert the link to your image here)