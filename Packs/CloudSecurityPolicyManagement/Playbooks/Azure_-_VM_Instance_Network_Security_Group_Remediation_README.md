This playbook adds new Azure Network Security Group (NSG) rules to NSGs attached to a NIC. The new rules give access to only a private IP address range and block traffic exposed to the public internet using the private IP of the VM, as explained in the ([Azure documentation](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)). For example, if RDP is exposed to the public internet, this playbook adds new firewall rules that only allow traffic from private IP addresses and blocks the rest of the RDP traffic.

Conditions and limitations:
- Limited to a single resource group.
- Identifies the NSG rule exposing the VM to the public internet via IPv4/IPv6 (service tags are not supported).
- Requires at least two available priority slots lower than the offending rule.
- Applies only to NSGs associated with NICs.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Azure
* Cortex Core - Platform

### Scripts

* AzureIdentifyNSGExposureRule
* Print
* Set
* SetAndHandleEmpty

### Commands

* azure-nsg-security-rule-create
* azure-nsg-security-rule-update
* azure-nsg-security-rules-list
* azure-vm-network-interface-details-get
* azure-vm-public-ip-details-get
* core-get-asset-details

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AssetID | The asset ID of the VM Instance. |  | Required |
| PublicIP | The public IP address to remediate for public exposure. |  | Required |
| RemoteProtocol | The remote protocol that is publicly exposed. |  | Required |
| RemotePort | The remote port that is publicly exposed. |  | Required |
| IntegrationInstance | The Azure Network Security Groups integration instance to use if you have multiple instances configured \(optional\). |  | Optional |
| RemediationAllowRanges | A comma-separated list of IPv4 network ranges to be used as source addresses for the \`cortex-remediation-allow-port-&lt;port\#&gt;-&lt;tcp\|udp&gt;\` rule to be created.  Typically these are private IP ranges \(to allow access within the vnet and bastion hosts\), but other networks can be added as needed. | 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| remediatedFlag | Whether remediation was successfully done. | boolean |
| remediation_action | The summary of remediation actions that were performed. | string |

## Playbook Image

---

![Azure - VM Instance Network Security Group Remediation](../doc_files/Azure_-_VM_Instance_Network_Security_Group_Remediation.png)
