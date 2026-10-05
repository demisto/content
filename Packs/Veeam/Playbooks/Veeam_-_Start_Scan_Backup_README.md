Starts a Scan Backup session for a specific restore point.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* VBR REST API

### Scripts

* DeleteContext

### Commands

* veeam-vbr-get-restore-points
* veeam-vbr-get-session
* veeam-vbr-get-session-logs
* veeam-vbr-get-yara-rules
* veeam-vbr-start-malware-backup-scan

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

![Veeam - Start Scan Backup](../doc_files/Veeam_-_Start_Scan_Backup.png)
