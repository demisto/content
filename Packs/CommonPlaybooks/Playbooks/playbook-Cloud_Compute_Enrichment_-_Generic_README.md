This playbook provides a generic enrichment of AWS, GCP, and Azure compute resources.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

* azure-vm-get-instance-details
* aws-ec2-describe-instances
* gcp-compute-get-instance

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| cloudProvider | The cloud provider involved. |  | Optional |
| instanceName | The instance name. |  | Optional |
| instanceID | The instance ID. |  | Optional |
| zone | The zone holding the instance. |  | Optional |
| region | The region holding the instance. |  | Optional |
| azureResourceGroup | The instance's resource group. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cloud Compute Enrichment - Generic](../doc_files/Cloud_Compute_Enrichment_-_Generic.png)
