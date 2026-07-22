DEPRECATED. Use "Block IP - Generic v2" playbook instead. Blocks malicious IP addresses using all integrations that you have enabled.

Supported integrations for this playbook:
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks Panorama
* Zscaler

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* Add Indicator to Miner - Minemeld

## Integrations
* Zscaler

## Scripts
* PanoramaBlockIP

## Commands
* zscaler-blacklist-ip
* checkpoint-block-ip

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| IPBlacklistMiner | The name of the IP address block list Miner in Minemeld. | Optional |
| IP | The array of malicious IP addresses to block. | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Destination | The collection of network objects identified by the name or UID. How much details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DestinationNegate | True if negate is set for destination. | unknown |
| PanoramaRule.Direction | The direction of the panorama rule. Can be, "to","from", or "both". | string |
| PanoramaRule.IP | The IP address the Panorama rule blocks. | string |
| CheckpointFWRule.Name | The object name. This should be unique in the domain. | unknown |
| PanoramaRule.Name | The name of the panorama rule | string |
| CheckpointFWRule.UID | The object unique identifier. | unknown |
| PanoramaRule | The list of panorama rules. | unknown |
| CheckpointFWRule.Type | The type of the object. | unknown |
| CheckpointFWRule.Action | The Accept, Drop, Apply Layer, Ask, Info. How much details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.ActionSetting | The action settings. | unknown |
| CheckpointFWRule.CustomFields | The custom fields. | unknown |
| CheckpointFWRule.Data | How many details are returned depends on the details-level field of the request. This table shows the level of detail shown when details-level is set to standard. | unknown |
| CheckpointFWRule.DataDirection | Which direction the file types processing is applied to. | unknown |
| CheckpointFWRule.DataNegate | True if negate is set for data. | unknown |
| CheckpointFWRule.Domain | The information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Enabled |Whether to enable or disable the rule. | unknown |
| CheckpointFWRule.Hits | The hits count object. | unknown |
| CheckpointFWRule.Data.Name | The object name. Should be unique in domain. | unknown |
| CheckpointFWRule.Data.Domain | The information about the domain the object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | The object name. This should be unique in the domain. | unknown |
| CheckpointFWRule.Domain.UID | The objects unique identifier. | unknown |
| CheckpointFWRule.Domain.Type | The domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The first of hits. | unknown |
| CheckpointFWRule.Hits.LastDate | The last date of hits. | unknown |
| CheckpointFWRule.Hits.Level | The level of hits. | unknown |
| CheckpointFWRule.Hits.Percentage | The percentage of hits | unknown |
| CheckpointFWRule.Hits.Value | The value of hits. | unknown |

## Playbook Image
---
![Block_IP_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_IP_Generic.png)
