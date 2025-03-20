This playbook addresses the challenge of efficiently sharing critical threat data with external partners, speeding up threat response and enhancing collective defense against cyberattacks.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* MISP - Set Attributes to Update
* MISP - Add Several Tags to MISP Event

### Integrations

* MISP V3

### Scripts

* CreateArray
* SearchIndicator
* misp_set_classification
* CreateNewIndicatorsOnly
* DateTimeNowToEpoch
* Set
* PrintErrorEntry
* DeleteContext
* SetAndHandleEmpty

### Commands

* misp-publish-event
* associateIndicatorsToIncident
* misp-create-event

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
