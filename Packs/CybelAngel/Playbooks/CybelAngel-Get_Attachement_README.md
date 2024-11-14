Get attachments for a specified incident report.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CybelAngel

### Scripts

* Set

### Commands

* cybelangel-get-report-attachment

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Report ID | Report ID<br/> | ${incident.alertid} | Required |
| Attachment ID | Attachment ID | ${incident.filenames.0.id} | Required |
| File Name | File name for the attachment<br/><br/> | ${incident.filenames.0.name} | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![CybelAngel - Get Attachement](CybelAngel_image.png)
