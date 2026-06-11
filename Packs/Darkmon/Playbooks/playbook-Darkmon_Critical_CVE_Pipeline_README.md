Daily filter of new CVEs (CVSS >= 9) against the customer's tech-stack tags. Matches open a 'Darkmon Critical CVE' incident per match and ticket via Generic Notify.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Darkmon - Generic Notify

### Integrations

* Darkmon

### Scripts

* DarkmonCreateIncidents
* DarkmonFilterCVEs
* DarkmonFilterUnseen

### Commands

* dmontip-get-cve

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FilteredCVEs | CVEs that passed the CVSS \+ tech-stack filter. | unknown |

## Playbook Image

---

![Darkmon_Critical_CVE_Pipeline](../doc_files/Darkmon_Critical_CVE_Pipeline.png)
