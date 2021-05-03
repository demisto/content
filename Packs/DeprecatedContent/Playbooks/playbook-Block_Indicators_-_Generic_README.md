Deprecated. We recommend using the 'Block Indicators - Generic v2' playbook instead.
This playbook blocks malicious indicators using all integrations that are enabled.

Supported integrations for this playbook:
* Active Directory
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks Panorama
* Zscaler
* Carbon Black Enterprise Response


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block File - Generic
* Block Account - Generic
* Block URL - Generic
* Block IP - Generic
* Block IP - Generic v2

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
| IPBlacklistMiner | The name of the IP blacklist Miner in  Minemeld. |  | Optional |
| URLBlacklistMiner | The name of the URL blacklist Miner in  Minemeld. |  | Optional |
| IP | Array of malicious IPs to block. | DBotScore.Indicator | Optional |
| URL | Array of malicious URLs to block. | DBotScore.Indicator | Optional |
| Username | Array of malicious usernames to block. | DBotScore.Indicator | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Domain | Information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Enabled | Enable/Disable the rule. | unknown |
| CheckpointFWRule.Name | Object name. Should be unique in domain. | unknown |
| CheckpointFWRule.UID | Object unique identifier. | unknown |
| CheckpointFWRule.Type | Type of the object. | unknown |
| CheckpointFWRule.DestinationNegate | True if negate is set for destination. | unknown |
| CheckpointFWRule.Action | Accept, Drop, Apply Layer, Ask, Info. The level of detail returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.Destination | Collection of Network objects identified by the name or UID. The level of detail depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.ActionSetting | Action settings. | unknown |
| CheckpointFWRule.CustomFields | Custom fields. | unknown |
| CheckpointFWRule.Data | The level of detail returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DataDirection | On which direction the file types processing is applied. | unknown |
| CheckpointFWRule.DataNegate | True if negate is set for data. | unknown |
| CheckpointFWRule.Hits | Hits count object. | unknown |
| PanoramaRule.Direction | Direction of the Panorama rule. Can be 'to','from', 'both' | string |
| PanoramaRule.IP | The IP the Panorama rule blocks | string |
| PanoramaRule.Name | Name of the Panorama rule | string |
| CheckpointFWRule.Data.Name | Object name. Should be unique in domain. | unknown |
| CheckpointFWRule.Data.Domain | Information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | Object name. Should be unique in domain. | unknown |
| CheckpointFWRule.Domain.UID | Object unique identifier. | unknown |
| CheckpointFWRule.Domain.Type | Domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | First of hits. | unknown |
| CheckpointFWRule.Hits.LastDate | Last date of hits. | unknown |
| CheckpointFWRule.Hits.Level | Level of hits. | unknown |
| CheckpointFWRule.Hits.Percentage | Percentage of hits | unknown |
| CheckpointFWRule.Hits.Value | Value of hits. | unknown |

## Playbook Image
---
![Block Indicators - Generic](Insert the link to your image here)