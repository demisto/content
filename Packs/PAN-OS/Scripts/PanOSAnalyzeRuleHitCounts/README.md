Processes the context output from !pan-os-get-rulehitcounts and returns data about unused local rules, unused rules from Panorama, and rules from Panorama that have hits on some firewalls but not all.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.UnusedRules.TotalLocalRulesAnalyzed | The total number of local rules analyzed. | Number |
| PANOS.UnusedRules.TotalPanoramaRulesAnalyzed | The total number of rules pushed from Panorama analyzed. | Number |
| PANOS.UnusedRules.UsedPanoramaRules.from_dg_name | Name of the device group the rule is inherited from. | String |
| PANOS.UnusedRules.UsedPanoramaRules.hostids_with_hits | Host IDs of firewalls where this rule has hits. | String |
| PANOS.UnusedRules.UsedPanoramaRules.hostnames_with_hits | Hostnames of firewalls where this rule has hits. | String |
| PANOS.UnusedRules.UsedPanoramaRules.hostids_with_zero_hits | Host IDs of firewalls where this rule has zero hits. | Unknown |
| PANOS.UnusedRules.UsedPanoramaRules.hostnames_with_zero_hits | Hostnames of firewalls where this rule has zero hits. | Unknown |
| PANOS.UnusedRules.UsedPanoramaRules.instanceName | Name of the PAN-OS Integration Instance used to collect rule hitcount data. | String |
| PANOS.UnusedRules.UsedPanoramaRules.name | The name of the rule. | String |
| PANOS.UnusedRules.UsedPanoramaRules.position | The position of the rule within the Panorama device-group rulebase \(pre-rulebase or post-rulebase\). | String |
| PANOS.UnusedRules.UsedPanoramaRules.rulebase | The rulebase where the rule is configured \(e.g. "Security", "NAT", etc\). | String |
| PANOS.UnusedRules.UnusedLocalRules.activeHAPeer | If the firewall where this rule data comes from is in an HA pair, contains the hostid of the active device in the pair. | Unknown |
| PANOS.UnusedRules.UnusedLocalRules.hostid | Host ID of the firewall where the rule is configured. | String |
| PANOS.UnusedRules.UnusedLocalRules.hostname | Hostname of the firewall where this rule is configured. | String |
| PANOS.UnusedRules.UnusedLocalRules.vsys | The virtual system \(vsys\) where the rule is configured. | String |
| PANOS.UnusedRules.UnusedLocalRules.instanceName | Name of the PAN-OS Integration Instance used to collect rule hitcount data. | String |
| PANOS.UnusedRules.UnusedLocalRules.name | The name of the rule. | String |
| PANOS.UnusedRules.UnusedLocalRules.position | The position of the rule within the Panorama device-group rulebase \(pre-rulebase or post-rulebase\). | String |
| PANOS.UnusedRules.UnusedLocalRules.rulebase | The rulebase where the rule is configured \(e.g. "Security", "NAT", etc\). | String |
| PANOS.UnusedRules.UnusedPanoramaRules.from_dg_name | The rulebase where the rule is configured \(e.g. "Security", "NAT", etc\). | String |
| PANOS.UnusedRules.UnusedPanoramaRules.instanceName | Name of the PAN-OS Integration Instance used to collect rule hitcount data. | String |
| PANOS.UnusedRules.UnusedPanoramaRules.name | The name of the rule. | String |
| PANOS.UnusedRules.UnusedPanoramaRules.position | The position of the rule within the Panorama device-group rulebase \(pre-rulebase or post-rulebase\). | String |
| PANOS.UnusedRules.UnusedPanoramaRules.rulebase | The rulebase where the rule is configured \(e.g. "Security", "NAT", etc\). | String |
| PANOS.UnusedRules.ignore_auto_extract | Instructs the system not to perform indicator extraction on returned data. | Boolean |
