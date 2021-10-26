This Playbook will append a network group object with new elements ( IPs or network objects ).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cisco Firepower

### Scripts
* SetAndHandleEmpty

### Commands
* ciscofp-get-network-groups-object
* ciscofp-update-network-groups-objects

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ID | The Id of the network group object that you would like to append. This information can be retrieved using -  <br/>\!ciscofp-get-network-groups-object |  | Required |
| Name | The name of the Network Group |  | Required |
| Override | Possible Value: True / False<br/> | False | Optional |
| IP | Enter a list of IPs \( separated with,  \) that will be added to the list. |  | Optional |
| ObjectID | You may add a group of IPs by using the Object ID. You can use \!ciscofp-get-network-object for more details. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cisco FirePower- Append network group object](../doc_files/Cisco_FirePower-_Append_network_group_object.png)