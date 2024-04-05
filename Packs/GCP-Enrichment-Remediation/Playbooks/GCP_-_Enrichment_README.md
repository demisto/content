Given the IP address this playbook enriches GCP and Firewall information.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* GCP-IAM
* Google Cloud Compute

### Scripts

* GCPOffendingFirewallRule
* Set
* GCPProjectHierarchy

### Commands

* gcp-iam-tagbindings-list
* gcp-iam-project-iam-policy-get
* gcp-compute-aggregated-list-instances-by-ip
* gcp-compute-get-instance

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GcpIP | GCP IP in alert | alert.remoteip | Required |
| port | Port to match traffic on for firewall rules. | ${alert.remoteport} | Optional |
| protocol | Protocol to match traffic on for firewall rules. | ${alert.protocol} | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GoogleCloudCompute.Instances | GCP VM Instances information. | unknown |
| GCPIAM.Policy | GCP IAM information | unknown |
| GCPIAM.TagBindings | Project/Folder/Organization level tags. | unknown |
| GCPHierarchy | GCP project hierarchy information. | unknown |
| GCPOffendingFirewallRule | One or more potential offending firewall rules in GCP based on port, protocol and possibly target tags \(network tags\). | unknown |

## Playbook Image

---

![GCP - Enrichment](../doc_files/GCP_-_Enrichment.png)
