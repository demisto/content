Replace current firewall rules with limited access firewall rules.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Google Cloud Compute

### Scripts
This playbook does not use any scripts.

### Commands
* gcp-compute-insert-firewall
* gcp-compute-add-network-tag
* gcp-compute-list-firewall
* gcp-compute-get-instance

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GcpInstance | The name of the GCP instance that has the public ip. |  | Required |
| GcpZone | The zone of the GCP instance that is hosted in. |  | Required |
| GcpNetwork | The VPC network of the GCP instance. |  | Required |
| RemotePort | The remote port that is publicly exposed to. | alert.remoteport | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![GCP - Firewall Remediation](../doc_files/GCP_-_Firewall_Remediation.png)