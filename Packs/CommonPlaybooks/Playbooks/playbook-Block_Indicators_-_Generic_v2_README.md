This playbook blocks malicious indicators through all integrations that are enabled, using the following sub-playbooks:

- Block URL - Generic
- Block Account - Generic
- Block IP - Generic v2
- Block File - Generic v2



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block IP - Generic v2
* Block Email - Generic
* Block File - Generic v2
* Block Account - Generic
* Block URL - Generic

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
| IPBlacklistMiner | The name of the IP blacklist miner in Minemeld. |  | Optional |
| URLBlacklistMiner | The name of the URL blacklist miner in Minemeld. |  | Optional |
| IP | Array of malicious IPs to block. | DBotScore.Indicator | Optional |
| URL | Array of malicious URLs to block. | DBotScore.Indicator | Optional |
| Username | Array of malicious usernames to block. | DBotScore.Indicator | Optional |
| MD5 | The MD5 hash of the file you want to block. | File.MD5 | Optional |
| SHA256 | The SHA256 hash of the file you want to block. | File.SHA256 | Optional |
| CustomBlockRule | Whether Palo Alto Networks Panorama or Firewall Custom Block Rules is used.<br/>Specify True to use Custom Block Rules. | True | Optional |
| LogForwarding | Panorama log forwarding object name. |  | Optional |
| AutoCommit | Whether Palo Alto Networks Panorama or Firewall Static Address Groups is used.<br/>Specify the Static Address Group name for IP handling. | No | Optional |
| IPListName | Whether Palo Alto Networks Panorama or Firewall External Dynamic Lists is used for blocking IPs.<br/>Specify the EDL name for IP handling. |  | Optional |
| EDLServerIP | Whether Palo Alto Networks Panorama or Firewall External Dynamic Lists is used:<br/>\* The IP address of the web server on which the files are stored.<br/>\* The web server IP address is configured in the integration instance. |  | Optional |
| DAG | Whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups is used.<br/>Specify the Dynamic Address Group tag name for IP handling. |  | Optional |
| StaticAddressGroup | Whether Palo Alto Networks Panorama or Firewall Static Address Groups is used.<br/>Specify the Static Address Group name for IP handling. |  | Optional |
| URLListName | URL list from the instance context with which to override the remote file. | Demisto Remediation - URL EDL | Optional |
| CustomURLCategory | Custom URL category name. | Demisto Remediation - Malicious URLs | Optional |
| type | Custom URL category type. Insert "URL List"/ "Category Match". |  | Optional |
| device-group | Device group for the Custom URL Category \(Panorama instances\). |  | Optional |
| categories | The list of categories. Relevant from PAN-OS v9.x. |  | Optional |
| EmailToBlock | The email address that you wish to block.  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Domain | Rule domain. | unknown |
| CheckpointFWRule.Enabled | Rule status. | unknown |
| CheckpointFWRule.Name | Rule name. | unknown |
| CheckpointFWRule.UID | Rule UID. | unknown |
| CheckpointFWRule.Type | Rule Type. | unknown |
| CheckpointFWRule.DestinationNegate | Rule destination negate status. \(True/False\). | unknown |
| CheckpointFWRule.Action | Rule action \(Valid values are: Accept, Drop, Apply Layer, Ask, Info\). | unknown |
| CheckpointFWRule.Destination | Rule destination. | unknown |
| CheckpointFWRule.ActionSetting | Rule action settings. | unknown |
| CheckpointFWRule.CustomFields | Rule custom fields. | unknown |
| CheckpointFWRule.Data | Rule data. | unknown |
| CheckpointFWRule.DataDirection | Rule data direction. | unknown |
| CheckpointFWRule.DataNegate | Rule data negate status \(True/False\). | unknown |
| CheckpointFWRule.Hits | Rule hits count. | unknown |
| PanoramaRule.Direction | Direction of the Panorama rule. Can be 'to','from', 'both'. | string |
| PanoramaRule.IP | The IP the Panorama rule blocks. | string |
| PanoramaRule.Name | Name of the Panorama rule. | string |
| CheckpointFWRule.Data.Name | Rule data object name. | unknown |
| CheckpointFWRule.Data.Domain | Information about the domain the data object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | Rule domain name. | unknown |
| CheckpointFWRule.Domain.UID | Rule domain UID. | unknown |
| CheckpointFWRule.Domain.Type | Rule domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The date of the first hit for the rule. | unknown |
| CheckpointFWRule.Hits.LastDate | The date of the last hit for the rule. | unknown |
| CheckpointFWRule.Hits.Level | Level of rule hits. | unknown |
| CheckpointFWRule.Hits.Percentage | Percentage of rule hits | unknown |
| CheckpointFWRule.Hits.Value | Value of rule hits. | unknown |

## Playbook Image
---
![Block Indicators - Generic v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Block_Indicators_Generic_v2.png)
