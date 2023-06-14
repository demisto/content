---

## Generic Cloud Enrichment Playbook

The **Cloud Enrichment - Generic Playbook** is designed to unify all the relevant playbooks concerning the enrichment of information in the cloud. It provides a standardized approach to enriching information in cloud environments.

### Supported Blocks

1. **Cloud IAM Enrichment - Generic**
   
   Enriches information related to Identity and Access Management (IAM) in the cloud.

2. **Cloud Compute Enrichment - Generic**
   
   Enriches information related to cloud compute resources.

---

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cloud Compute Enrichment - Generic
* Cloud IAM Enrichment - Generic

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

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
| username | The username involved. |  | Optional |
| GCPProjectName | The GCP project name. |  | Optional |
| cloudIdentityType | The type of the GCP identity.<br/>Can be either Service Account or a user. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cloud Enrichment - Generic](../doc_files/Cloud_Enrichment_-_Generic.png)
