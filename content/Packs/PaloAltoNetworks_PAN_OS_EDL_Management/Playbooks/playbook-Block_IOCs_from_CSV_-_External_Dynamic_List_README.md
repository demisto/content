Parses a CSV file with IOCs and blocks them using Palo Alto Networks External Dynamic Lists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* PAN-OS - Block IP and URL - External Dynamic List
* PAN-OS - Block Domain - External Dynamic List
* Add Indicator to Miner - Palo Alto MineMeld

## Integrations
This playbook does not use any integrations.

## Scripts
* ParseCSV

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPColumn | The column number that contains IP addresses. (First column is column 0). | - | Optional |
| DomainColumn | The column number that contains domains. (First column is column 0). | - | Optional |
| FileColumn | The column number that contains hashes. (First column is column 0). | - | Optional |
| Miner | The Miner name to upload the indicators to in MineMeld. | - | Optional |
| IPListName | The IP address list from the instance context with which to override the remote file. | Demisto Remediation - IP EDL |Optional |
| DomainListName | The domain list from the instance context with which to override the remote file. | Demisto Remediation - Domain EDL |Optional |
| EDLServerIP | The EDL server IP address. | - |Optional |
| LogForwarding | The log forwarding object name. | - |Optional |
| AutoCommit | The input establishes whether to commit the configuration automatically. Yes - Commit automatically. No - Commit manually. | No |Optional |
| pre-post-rulebase | Either pre-rulebase or post-rulebase, according to the rule structure. | pre-rulebase |Optional |
| rule-position | The position of the rule in the ruleset. Valid values are, "Top", "Bottom", "Before", or "After". | Top | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Block_IOCs_from_CSV_External_Dynamic_List](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_IOCs_from_CSV_External_Dynamic_List.png)
