Deprecated. Use "Block IP - Generic v2" playbook instead. This playbook blocks malicious IPs using all integrations that you have enabled.

Supported integrations for this playbook:
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks Panorama
* Zscaler

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Add Indicator to Miner - Minemeld

### Integrations
* Zscaler

### Scripts
* PanoramaBlockIP

### Commands
* zscaler-blacklist-ip
* checkpoint-block-ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPBlacklistMiner | The name of the IP blacklist Miner in  Minemeld. |  | Optional |
| IP | Array of malicious IPs to block. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Destination | Collection of Network objects identified by the name or UID. How much details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DestinationNegate | True if negate is set for destination. | unknown |
| PanoramaRule.Direction | Direction of the Panorama rule, could be 'to','from', 'both' | string |
| PanoramaRule.IP | The IP the Panorama rule blocks | string |
| CheckpointFWRule.Name | Object name. Should be unique in domain. | unknown |
| PanoramaRule.Name | Name of the Panorama rule | string |
| CheckpointFWRule.UID | Object unique identifier. | unknown |
| PanoramaRule | List of Panorama rules | unknown |
| CheckpointFWRule.Type | Type of the object. | unknown |
| CheckpointFWRule.Action | Accept, Drop, Apply Layer, Ask, Info. How much details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.ActionSetting | Action settings. | unknown |
| CheckpointFWRule.CustomFields | Custom fields. | unknown |
| CheckpointFWRule.Data | How much details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DataDirection | On which direction the file types processing is applied. | unknown |
| CheckpointFWRule.DataNegate | True if negate is set for data. | unknown |
| CheckpointFWRule.Domain | Information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Enabled | Enable/Disable the rule. | unknown |
| CheckpointFWRule.Hits | Hits count object. | unknown |
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
![Block IP - Generic](Insert the link to your image here)