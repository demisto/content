Sync a list of IP addresses to the Okta Network Zone with the given ID. 
Existing IPs in the Okta Zone which are not in the input list will be removed and the indicator will be untagged on XSOAR.
IDs can be retrieved  using !okta-list-zones. This playbook supports CIDR notation only (1.1.1.1/32) and not range notation (1.1.1.1-1.1.1.1)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Okta V2

### Scripts
* CompareLists
* Set

### Commands
* okta-get-zone
* setIndicator
* okta-update-zone
* removeIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| IP | IP addresses to set in the whitelist |  | Required |
| ZoneID | ID of the Okta Zone to update. Use \!okta\-list\-zones to obtain |  | Required |
| IndicatorTagName | Name of the Indicator Tag to apply to any IPs whitelisted by this playbook. | Okta_Zone | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

![Playbook Image](https://raw.githubusercontent.com/demisto/content/8d73e1dad4ba0f299d87526fac1b85e1a76792a7/Packs/IPWhitelisting/doc_files/IP_Whitelist_-_Okta_Zone.png)