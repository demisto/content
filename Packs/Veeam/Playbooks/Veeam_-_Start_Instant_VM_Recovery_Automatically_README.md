Starts Instant VM Recovery with automatic configuration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling
* Veeam - Start Instant VM Recovery Manually

### Integrations

* VBR REST API

### Scripts

* DeleteContext
* GetFolderName
* GetHostName
* GetRestoredVmName

### Commands

* veeam-vbr-get-backup-object
* veeam-vbr-get-inventory-objects
* veeam-vbr-get-restore-points
* veeam-vbr-get-session
* veeam-vbr-start-instant-recovery-customized

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Instance |  | incident.sourceInstance | Optional |
| backupObjectId |  | incident.veeambackupobjectid | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Veeam - Start Instant VM Recovery Automatically](../doc_files/Veeam_-_Start_Instant_VM_Recovery_Automatically.png)
