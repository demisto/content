

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Ana Bildirim Otomasyon

### Integrations

* Mail Sender (New)
* QRadar v3

### Scripts

* CreateEmailHtmlBody

### Commands

* demisto-api-get
* qradar-offense-note-create
* send-mail
* setOwner
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Enrich |  | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![AnaPlaybook_Incident_Handling](../doc_files/AnaPlaybook_Incident_Handling.png)
