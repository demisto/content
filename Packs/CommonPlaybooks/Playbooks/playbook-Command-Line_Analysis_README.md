This playbook takes the command line from the alert and performs the following actions:
- Checks for base64 string and decodes if exists
- Extracts and enriches indicators from the command line
- Checks specific arguments for malicious usage 

At the end of the playbook, it sets a possible verdict for the command line, based on the finding:
1. Indicators found in the command line
2. Found AMSI techniques
3. Found suspicious parameters
4. Usage of malicious tools
5. Indication of network activity

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* MatchRegexV2
* Base64Decode
* Set

### Commands
* enrichIndicators
* extractIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Commandline | The command line. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchRegex | The regex found in the command line | unknown |
| Indicators | Indicators extracted from the command line | unknown |
| commandline | The command line | unknown |
| CommandlineVerdict | The command line verdict | unknown |

## Playbook Image
---
![Command-Line Analysis](https://raw.githubusercontent.com/demisto/content/260a4d094a4db588e37a3763d511b5248cd7049b/Packs/CommonPlaybooks/doc_files/Command-Line_Analysis.png)