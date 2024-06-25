Sync a list of IP addresses to the Okta Network Zone with the given ID. 
Existing IPs in the Okta Zone which are not in the input list will be removed and the indicator will be untagged in Cortex XSOAR.
IDs can be retrieved  using !okta-list-zones. This playbook supports CIDR notation only (1.1.1.1/32) and not range notation (1.1.1.1-1.1.1.1)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Okta_v2

### Scripts
* CompareLists
* Set

### Commands
* okta-get-zone
* okta-update-zone
* setIndicator
* removeIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| IP | IP addresses to set in the allow list |  | Required |
| ZoneID | ID of the Okta Zone to update. Use \!okta\-list\-zones to obtain |  | Required |
| IndicatorTagName | Name of the Indicator Tag to apply to any IPs allow listed by this playbook. | Okta_Zone | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Allow IP - Okta Zone](https://raw.githubusercontent.com/demisto/content/859f073f59aabaef8e36ec39eed63778cd2b9856/Packs/Okta/doc_files/Allow_IP_-_Okta_Zone.png)
