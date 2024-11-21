This playbook fetches workload information for the provided IPs or domains, and then increases the incident severity based on the workload risk levels and threat information.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* RubrikPolaris

### Scripts

* DeleteContext
* RubrikSetIncidentSeverityUsingWorkLoadRiskLevel

### Commands

* domain
* ip
* findIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| increase_severity_by | Specify the level by which to increase the incident severity. Only applicable if match found for the malicious threat hunt or for the malicious threat monitoring of workload. | 1 | Optional |
| ip_addresses | The IP address\(es\) for which to use workload information to increase incident severity. |  | Optional |
| domains | The domain\(s\) for which to use workload information to increase incident severity. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Rubrik Workload Analysis - Rubrik Security Cloud](../doc_files/Rubrik_Workload_Analysis_-_Rubrik_Security_Cloud.png)
