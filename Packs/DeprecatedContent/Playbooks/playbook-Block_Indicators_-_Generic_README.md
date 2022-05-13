Deprecated. Blocks malicious indicators using all integrations that are enabled.

Supported integrations for this playbook:
* Active Directory
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks Panorama
* Zscaler
* Carbon Black Enterprise Response


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Block File - Generic
* Block Account - Generic
* Block IP - Generic v2
* Block IP - Generic
* Block URL - Generic

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
| IPBlacklistMiner | The name of the IP address block list Miner in Minemeld. | - | - | Optional |
| URLBlacklistMiner | The name of the URL block list Miner in  Minemeld. | - | - | Optional |
| IP | The array of malicious IP addresses to block. | Indicator | DBotScore | Optional |
| URL | The array of malicious URLs to block. | Indicator | DBotScore | Optional |
| Username | The array of malicious usernames to block. | Indicator | DBotScore | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Domain | The information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Enabled | Whether to enable or disable the rule. | unknown |
| CheckpointFWRule.Name | The object name. This should be unique in the domain. | unknown |
| CheckpointFWRule.UID | The object unique identifier. | unknown |
| CheckpointFWRule.Type | The type of the object. | unknown |
| CheckpointFWRule.DestinationNegate | True if negate is set for destination. | unknown |
| CheckpointFWRule.Action | The Accept, Drop, Apply Layer, Ask, Info. The level of detail returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.Destination | The collection of Network objects identified by the name or UID. The level of detail depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.ActionSetting | The action settings. | unknown |
| CheckpointFWRule.CustomFields | The custom fields. | unknown |
| CheckpointFWRule.Data | The level of detail returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DataDirection | On which direction the file types processing is applied. | unknown |
| CheckpointFWRule.DataNegate | True if negate is set for data. | unknown |
| CheckpointFWRule.Hits | The hits count object. | unknown |
| PanoramaRule.Direction | The direction of the Panorama rule. Can be 'to','from', or 'both'. | string |
| PanoramaRule.IP | The IP the Panorama rule blocks. | string |
| PanoramaRule.Name | The name of the Panorama rule. | string |
| CheckpointFWRule.Data.Name | The object name. This should be unique in the domain. | unknown |
| CheckpointFWRule.Data.Domain | The information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | The object name. This should be unique in the domain. | unknown |
| CheckpointFWRule.Domain.UID | The object unique identifier. | unknown |
| CheckpointFWRule.Domain.Type | The domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The first of hits. | unknown |
| CheckpointFWRule.Hits.LastDate | The last date of hits. | unknown |
| CheckpointFWRule.Hits.Level | The level of hits. | unknown |
| CheckpointFWRule.Hits.Percentage | The percentage of hits. | unknown |
| CheckpointFWRule.Hits.Value | The value of hits. | unknown |

## Playbook Image
---
![Block_Indicators_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Indicators_Generic.png)
