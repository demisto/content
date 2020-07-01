Blocks malicious IP addressess using all integrations that are enabled.

Supported integrations for this playbook:
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks PAN-OS
* Zscaler

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* PAN-OS DAG Configuration
* PAN-OS - Block IP - Static Address Group
* PAN-OS - Block IP and URL - External Dynamic List
* PAN-OS - Block IP - Custom Block Rule
* Add Indicator to Miner - Minemeld

## Integrations
* Zscaler

## Scripts
This playbook does not use any scripts.

## Commands
* checkpoint-block-ip
* zscaler-blacklist-ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |**Required** |
| --- | --- | --- | --- |
| IPBlacklistMiner | The name of the IP address blacklist Miner in Minemeld. | - |Optional |
| IP | The aof malicious IP addresses to block. | - | Optional |
| CustomBlockRule | This input determines whether Palo Alto Networks Panorama or Firewall Custom Block Rules are used.Specify True to use Custom Block Rules. | True |Optional |
| LogForwarding | The Panorama log forwarding object name. | - | Optional |
| AutoCommit | This input determines whether to commit the configuration automatically. Yes - Commit automatically. No - Commit manually. | No | Optional |
| StaticAddressGroup | This input determines whether Palo Alto Networks Panorama or Firewall Static Address Groups are used. Specify the Static Address Group name for IP address handling. | - |Optional |
| IPListName | This input determines whether Palo Alto Networks Panorama or Firewall External Dynamic Lists are used for blocking IP addresses. Specify the EDL name for IP address handling. | - |Optional |
| EDLServerIP | This input determines whether Palo Alto Networks Panorama or Firewall External Dynamic Lists are used: * The IP address of the web server on which the files are stored. * The web server IP address is configured in the integration instance. | - | Optional |
| DAG | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used. Specify the Dynamic Address Group tag name for IP address handling. | - |Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Destination | The rule destination. | unknown |
| CheckpointFWRule.DestinationNegate | The rule destination negate status. Can be, "True" or "False". | unknown |
| PanoramaRule.Direction | The direction of the Panorama rule. Can be, "to","from", or "both". | string |
| PanoramaRule.IP | The IP address the Panorama rule blocks. | string |
| CheckpointFWRule.Name | The rule name. | unknown |
| PanoramaRule.Name | The name of the Panorama rule. | string |
| CheckpointFWRule.UID | The rule's UID. | unknown |
| PanoramaRule | The list of Panorama rules. | unknown |
| CheckpointFWRule.Type | The rule type. | unknown |
| CheckpointFWRule.Action | The rule action. Valid values are, "Accept", 'Drop", "Apply Layer", "Ask", or "Info". | unknown |
| CheckpointFWRule.ActionSetting | The rule action settings. | unknown |
| CheckpointFWRule.CustomFields | The rule custom fields. | unknown |
| CheckpointFWRule.Data | The rule data. | unknown |
| CheckpointFWRule.DataDirection | The rule data direction. | unknown |
| CheckpointFWRule.DataNegate | The rule data negate status. Can be, "True" or "False". | unknown |
| CheckpointFWRule.Domain | The rule domain. | unknown |
| CheckpointFWRule.Enabled | The rule status. | unknown |
| CheckpointFWRule.Hits | The rule hits count. | unknown |
| CheckpointFWRule.Data.Name | The rule data object name. | unknown |
| CheckpointFWRule.Data.Domain | The information about the domain the data object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | The rule domain name. | unknown |
| CheckpointFWRule.Domain.UID | The rule domain UID. | unknown |
| CheckpointFWRule.Domain.Type | The rule domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The date of the first hit for the rule. | unknown |
| CheckpointFWRule.Hits.LastDate | The date of the last hit for the rule. | unknown |
| CheckpointFWRule.Hits.Level | The level of rule hits. | unknown |
| CheckpointFWRule.Hits.Percentage | The percentage of rule hits. | unknown |
| CheckpointFWRule.Hits.Value | The value of rule hits. | unknown |

## Playbook Image
---
![Block_IP_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_IP_Generic_v2.png)
