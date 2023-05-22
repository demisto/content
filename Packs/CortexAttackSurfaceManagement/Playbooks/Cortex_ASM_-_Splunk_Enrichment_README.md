Given the IP address this playbook enriches information from Splunk results relevant to ASM alerts. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* GetTime
* GridFieldSetup

### Commands

* splunk-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | Remote IP in an incident/alert.  | alert.remoteip | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Splunk Enrichment](../doc_files/Cortex_ASM_-_Splunk_Enrichment.png)