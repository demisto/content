Given the IP address this playbook enriches information from Qualys assets.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* QualysV2

### Scripts

* GridFieldSetup
* GetTime

### Commands

* qualys-host-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| QualysIP | Remote IP in alert. | alert.remoteip | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Qualys Enrichment](../doc_files/Cortex_ASM_-_Qualys_Enrichment.png)
