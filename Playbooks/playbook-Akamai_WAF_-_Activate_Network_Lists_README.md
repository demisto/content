Activates network lists in **Staging** or **Production** on Akamai WAF. The playbook finishes running when the network list is active on the requested enviorment.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Generic Polling

### Integrations
This playbook does not use any integrations.

### Scripts
* Print

### Commands
* akamai-activate-network-list

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_ids |  The comma-separated list of network list IDs to activate. For example, "id_list1,id_list2".  | Required |
| env | The enviorment type to activate the network list. Can be "STAGING" or "PRODUCTION". | Required |
| comment | The comment to log when activating the network lists. | Optional |
| notify | The comma-separated list of email addresses to notify when the network lists are activated. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Akamai_WAF_Activate_Network_Lists](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Akamai_WAF_Activate_Network_Lists.png)
