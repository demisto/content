Blocks malicious indicators using all integrations that are enabled, using the following sub-playbooks:  

- Block URL - Generic
- Block Account - Generic
- Block IP - Generic v2
- Block File - Generic v2



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Block URL - Generic
* Block File - Generic v2
* Block IP - Generic v2
* Block Account - Generic

## Integrations
This playbook does not use any integrations.

## Scripts
This playbook does not use any scripts.

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IPBlacklistMiner | The name of the IP address blacklist Miner in Minemeld. | - | - | Optional |
| URLBlacklistMiner | The name of the URL blacklist Miner in Minemeld. | - | - | Optional |
| IP | The array of malicious IP addresses to block. | Indicator | DBotScore | Optional |
| URL | The array of malicious URLs to block. | Indicator | DBotScore | Optional |
| Username | The array of malicious usernames to block. | Indicator | DBotScore | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Domain | The rule domain. | unknown |
| CheckpointFWRule.Enabled | The rule status. | unknown |
| CheckpointFWRule.Name | The rule name. | unknown |
| CheckpointFWRule.UID | The rule UID. | unknown |
| CheckpointFWRule.Type | The rule type. | unknown |
| CheckpointFWRule.DestinationNegate | The rule destination negate status. Can be, "True" or "False". | unknown |
| CheckpointFWRule.Action | The rule action. Valid values are, "Accept", "Drop", "Apply Layer", "Ask", or "Info". | unknown |
| CheckpointFWRule.Destination | The rule destination. | unknown |
| CheckpointFWRule.ActionSetting | The rule action settings. | unknown |
| CheckpointFWRule.CustomFields | The rule custom fields. | unknown |
| CheckpointFWRule.Data | The rule data. | unknown |
| CheckpointFWRule.DataDirection | The rule data direction. | unknown |
| CheckpointFWRule.DataNegate | The rule data negate status. Can be, "True" or "False". | unknown |
| CheckpointFWRule.Hits | The rule hits count. | unknown |
| PanoramaRule.Direction | The direction of the Panorama rule. Can be "to","from", or "both". | string |
| PanoramaRule.IP | The IP address the Panorama rule blocks. | string |
| PanoramaRule.Name | The name of the Panorama rule. | string |
| CheckpointFWRule.Data.Name | The rule data object name. | unknown |
| CheckpointFWRule.Data.Domain | The information about the domain the data object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | The rule domain name. | unknown |
| CheckpointFWRule.Domain.UID | The rule domain UID. | unknown |
| CheckpointFWRule.Domain.Type | The rule domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The date of the first hit for the rule. | unknown |
| CheckpointFWRule.Hits.LastDate | The date of the last hit for the rule. | unknown |
| CheckpointFWRule.Hits.Level | The level of rule hits. | unknown |
| CheckpointFWRule.Hits.Percentage | The percentage of rule hits | unknown |
| CheckpointFWRule.Hits.Value | The value of rule hits. | unknown |

## Playbook Image
---
![Block_Indicators_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Indicators_Generic_v2.png)
