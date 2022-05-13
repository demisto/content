This playbook blocks malicious IPs using all integrations that are enabled.

Supported integrations for this playbook:
* Check Point Firewall
* Palo Alto Networks Minemeld
* Palo Alto Networks PAN-OS
* Zscaler
* FortiGate

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Block IP - Custom Block Rule
* PAN-OS - Block IP - Static Address Group
* Add Indicator to Miner - Palo Alto MineMeld
* PAN-OS - Block IP and URL - External Dynamic List
* PAN-OS DAG Configuration

### Integrations
* Zscaler

### Scripts
This playbook does not use any scripts.

### Commands
* checkpoint-block-ip
* zscaler-blacklist-ip
* fortigate-ban-ip

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPBlacklistMiner | The name of the IP block list Miner in  Minemeld. |  | Optional |
| IP | Array of malicious IPs to block. |  | Optional |
| CustomBlockRule | This input determines whether Palo Alto Networks Panorama or Firewall Custom Block Rules are used.
Specify True to use Custom Block Rules. | True | Optional |
| LogForwarding | Panorama log forwarding object name. |  | Optional |
| AutoCommit | This input determines whether to commit the configuration automatically.
Yes \- Commit automatically.
No \- Commit manually. | No | Optional |
| StaticAddressGroup | This input determines whether Palo Alto Networks Panorama or Firewall Static Address Groups are used.
Specify the Static Address Group name for IP handling. |  | Optional |
| IPListName | This input determines whether Palo Alto Networks Panorama or Firewall External Dynamic Lists are used for blocking IPs.
Specify the EDL name for IP handling. |  | Optional |
| EDLServerIP | This input determines whether Palo Alto Networks Panorama or Firewall External Dynamic Lists are used:
\* The IP address of the web server on which the files are stored.
\* The web server IP address is configured in the integration instance. |  | Optional |
| DAG | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.
Specify the Dynamic Address Group tag name for IP handling. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointFWRule.Destination | Rule Destination. | unknown |
| CheckpointFWRule.DestinationNegate | Rule destination negate status \(True/False\). | unknown |
| PanoramaRule.Direction | Direction of the Panorama rule. Can be 'to','from', 'both' | string |
| PanoramaRule.IP | The IP the Panorama rule blocks | string |
| CheckpointFWRule.Name | Rule name. | unknown |
| PanoramaRule.Name | Name of the Panorama rule | string |
| CheckpointFWRule.UID | Rule UID. | unknown |
| PanoramaRule | List of Panorama rules | unknown |
| CheckpointFWRule.Type | Rule Type. | unknown |
| CheckpointFWRule.Action | Rule action \(Valid values are: Accept, Drop, Apply Layer, Ask, Info\). | unknown |
| CheckpointFWRule.ActionSetting | Rule action settings. | unknown |
| CheckpointFWRule.CustomFields | Rule custom fields. | unknown |
| CheckpointFWRule.Data | Rule data. | unknown |
| CheckpointFWRule.DataDirection | Rule data direction. | unknown |
| CheckpointFWRule.DataNegate | Rule data negate status \(True/False\). | unknown |
| CheckpointFWRule.Domain | Rule domain. | unknown |
| CheckpointFWRule.Enabled | Rule status. | unknown |
| CheckpointFWRule.Hits | Rule hits count. | unknown |
| CheckpointFWRule.Data.Name | Rule data object name. | unknown |
| CheckpointFWRule.Data.Domain | Information about the domain the data object belongs to. | unknown |
| CheckpointFWRule.Domain.Name | Rule domain name. | unknown |
| CheckpointFWRule.Domain.UID | Rule domain UID. | unknown |
| CheckpointFWRule.Domain.Type | Rule domain type. | unknown |
| CheckpointFWRule.Hits.FirstDate | The date of the first hit for the rule. | unknown |
| CheckpointFWRule.Hits.LastDate | The date of the last hit for the rule. | unknown |
| CheckpointFWRule.Hits.Level | Level of rule hits. | unknown |
| CheckpointFWRule.Hits.Percentage | Percentage of rule hits. | unknown |
| CheckpointFWRule.Hits.Value | Value of rule hits. | unknown |
