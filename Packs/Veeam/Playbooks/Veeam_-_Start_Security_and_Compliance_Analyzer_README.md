Starts a Security & Compliance Analyzer scan session for the Veeam Backup & Replication instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* VBR REST API

### Scripts

* DeleteContext

### Commands

* veeam-vbr-get-security-analyzer-best-practices
* veeam-vbr-get-security-analyzer-last-run
* veeam-vbr-start-security-analyzer

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Instance |  | incident.sourceInstance | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Veeam - Start Security & Compliance Analyzer](../doc_files/Veeam_-_Start_Security_and_Compliance_Analyzer.png)
