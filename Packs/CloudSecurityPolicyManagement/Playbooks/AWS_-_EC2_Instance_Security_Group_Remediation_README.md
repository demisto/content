This playbook identifies the security groups used on an EC2 interface with a specific public IP. It determines which rules allow access via the given port and protocol, creates a copy of the security groups with those rules removed, and updates the interface to use the modified security groups. The original security groups are left unmodified, and the remediated copy is applied to the exposed EC2 instance.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS
* Cortex Core - Platform

### Scripts

* AWSIdentifySGPublicExposure
* AWSRemediateSG
* GetTime
* Print
* Set

### Commands

* aws-ec2-network-interface-attribute-modify
* core-get-asset-details

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AssetID | The asset ID of the VM Instance. |  | Required |
| PublicIP | The public IP address to remediate for public exposure. |  | Required |
| RemotePort | The TCP/UDP port number to be restricted. |  | Required |
| RemoteProtocol | The protocol to be restricted \(tcp/udp\). |  | Required |
| RemediationAllowRanges | A comma-separated list of IPv4 network ranges to be used as source addresses for the \`cortex-remediation-allow-port-&lt;port\#&gt;-&lt;tcp\|udp&gt;\` rule to be created.  Typically these are private IP ranges \(to allow access within the VPC and bastion hosts\), but other networks can be added as needed. | 10.0.0.0/16,172.16.0.0/12,192.168.0.0/16 | Optional |
| IntegrationInstance | The AWS integration instance to use if multiple instances are configured \(optional\). |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| remediatedFlag | Whether remediation was successfully done. | boolean |
| remediation_action | The summary of remediation actions that were performed. | string |

## Playbook Image

---

![AWS - EC2 Instance Security Group Remediation](../doc_files/AWS_-_EC2_Instance_Security_Group_Remediation.png)
