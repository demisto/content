This playbook adds new Azure Network Security Groups (NSG) rules to NSGs attached to a NIC. The new rules will give access only to private ip address range and block traffic that's exposed to public internet ([using the private IP of the VM as stated in Azure documentation](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)).For example, if RDP is exposed to the public internet, this playbook adds new firewall rules that only allows traffic from private ip address and blocks rest of the RDP traffic.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Azure Network Security Groups

### Scripts

* Set
* AzureFindAvailableNSGPriorities

### Commands

* azure-nsg-security-rules-list
* azure-nsg-security-rule-update
* azure-nsg-security-rule-create

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AzureSecurityGroup | The Azure Network Security Group that will have new rules created or updated. | | Required |
| RemotePort | The remote port that is publicly exposed. | | Required |
| RemoteProtocol | The remote protocol that is publicly exposed. | | Required |
| RemoteIP | The remote IP that is publicly exposed. | | Required |
| AzureVMPrivateIP | The private IP of the Azure Virtual Machine. | | Required |

## Playbook Outputs

---
| **Path** | **Description** | **Type** |
| --- | --- | --- |

## Playbook Image

---
![Azure - Network Security Group Riation image](../doc_files/Azure_-_Network_Security_Group_Remediation.png)