Activates a CyberArk EPM SOC risk plan for a specified endpoint, based on the incident severity. Endpoint name and external IP are taken from the incident to uniquely identify the on EPM

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CyberArkEPMSOCResponse

### Scripts

This playbook does not use any scripts.

### Commands

* cyberarkepm-activate-risk-plan

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_name | FQDN of target endpoint |  | Optional |
| endpoint_external_ip | External IP of target endpoint |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![CyberArk EPM SOC Response](../doc_files/CyberArk_EPM_SOC_Response.png)
