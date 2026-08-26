Submits a file for Netskope's sandbox scan and polls for the result, since the scan is asynchronous and can take a while to complete.

Only certain file types are accepted for inspection - this is enforced by ***netskopev2-submit-file-scan*** itself: the file must be a password-protected .zip whose one member file is .exe, .pdf, .doc, .xls, .ppt, or .rtf. A plain .zip (the container format) is also accepted directly. Anything else is rejected with a clear error before an API call is even made.

Submits the file for scanning, then uses the GenericPolling sub-playbook to repeatedly call ***netskopev2-get-scan-report*** until the scan's status stops being "InProgress", and records the result (job ID, status, verdict, MD5, SHA256) as labels on the incident.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeFileScanLabels

### Commands

* netskopev2-submit-file-scan
* netskopev2-get-scan-report
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| EntryID | Entry ID of the file to submit for sandbox scanning. Must be one of: zip, exe, pdf, doc, xls, ppt, rtf. | ${File.EntryID} | Required |
| Interval | Minutes between each poll of the scan status. | 1 | Optional |
| Timeout | Maximum minutes to keep polling before giving up and resuming the playbook. | 15 | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
