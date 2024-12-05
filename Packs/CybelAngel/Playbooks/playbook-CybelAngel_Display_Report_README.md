Display Report PDF to show all image.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CybelAngel

### Scripts

This playbook does not use any scripts.

### Commands

* cybelangel-get-report-pdf
* rasterize-pdf

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Incident ID | Incident ID \(Alertid\) needed to retrieve the report PDF | ${incident.alertid} | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![CybelAngel -  Display Report](CybelAngel_image.png)
