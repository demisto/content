

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* MISP - Add Several Tags to MISP Event
* MISP - Set Attributes to Update

### Integrations

* MISP V3

### Scripts

* CreateNewIndicatorsOnly
* Set
* CreateArray
* misp_set_classification
* DateTimeNowToEpoch
* SetAndHandleEmpty
* PrintErrorEntry
* SearchIndicator
* DeleteContext

### Commands

* misp-create-event
* misp-publish-event
* associateIndicatorsToIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| org_type | Please choose between "pt_org" \(Portuguese Organization\) and "non_pt_org" \(Non Portuguese Organization\) |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Playbook - MISP - Indicator Sharing](../doc_files/Playbook_-_MISP_-_Indicator_Sharing.png)
