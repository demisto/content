This playbook remediates Prisma Cloud GCP Compute Engine alerts.  It calls sub-playbooks that perform the actual remediation steps.

Remediation:
 - GCP VM instances have serial port access enabled
 - GCP VM instances have block project-wide SSH keys feature disabled
 - GCP VM instances without any custom metadata information


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Prisma Cloud Remediation - GCP Compute Engine Instance Misconfiguration

### Integrations

* PrismaCloud v2

### Scripts

This playbook does not use any scripts.

### Commands

* redlock-dismiss-alerts
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoRemediateComputeEngine | Execute GCP Compute Engine remediation automatically? | no | Optional |
| policyId | Grab the Prima Cloud policy Id. | incident.labels.policy | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Prisma Cloud Remediation - GCP Compute Engine Misconfiguration](../doc_files/Prisma_Cloud_Remediation_-_GCP_Compute_Engine_Misconfiguration_v2.png)
