Starts Instant VM Recovery with manual configuration

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* VBR REST API

### Scripts

* DeleteContext
* GetRestoredVmName

### Commands

* veeam-vbr-start-instant-recovery-customized
* veeam-vbr-get-backup-object
* veeam-vbr-get-session
* veeam-vbr-get-restore-points

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Instance |  | incident.sourceInstance | Optional |
| backupObjectId |  | incident.backupobjectid | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Veeam - Start Instant VM Recovery Manually](../doc_files/Veeam_Start_Instant_VM_Recovery_Manually.png)
