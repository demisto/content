Given the IP address this playbook enriches GCP and Firewall information.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Google Cloud Compute
* GCP-IAM

### Scripts
This playbook does not use any scripts.

### Commands
* gcp-compute-list-firewall
* gcp-compute-aggregated-list-instances-by-ip
* gcp-iam-project-iam-policy-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GcpIP | GCP IP in alert | 34.168.3.66 | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GoogleCloudCompute.Instances | GCP VM Instances information. | unknown |
| GoogleCloudCompute.Firewalls | GCP Firewall information | unknown |
| GCPIAM.Policy | GCP IAM information | unknown |

## Playbook Image
---
![GCP - Enrichment](../doc_files/GCP_-_Enrichment.png)