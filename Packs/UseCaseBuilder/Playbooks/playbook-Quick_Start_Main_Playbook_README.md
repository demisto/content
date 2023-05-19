

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Quick Start Remediation
* Dedup - Generic v4
* Quick Start Investigation

### Integrations

This playbook does not use any integrations.

### Scripts

* AssignAnalystToIncident

### Commands

* jira-create-issue
* closeInvestigation
* servicenow-create-ticket
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Ticketing_type | You can use XSOAR, ServiceNow, Jira. Make sure to setup the ServiceNow and Jira integrations if you opt to choose these options. | XSOAR | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Quick Start Main Playbook](../doc_files/Quick_Start_Main_Playbook.png)