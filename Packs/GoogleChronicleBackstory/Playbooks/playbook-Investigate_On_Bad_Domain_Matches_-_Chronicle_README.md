Use this playbook to investigate and remediate Bad IOC domain matches with recent activity found in the enterprise, as well as notify the SOC lead and network team about the matches.
Supported Integrations:

- Chronicle
- Google SecOps
- Whois
- Mail Sender (New)
- Palo Alto Networks PAN-OS
- Palo Alto Networks AutoFocus v2

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Chronicle
* Google SecOps
* Whois
* Mail Sender (New)
* Palo Alto Networks PAN-OS
* Palo Alto Networks AutoFocus v2

### Scripts

* AssignAnalystToIncident
* GenerateInvestigationSummaryReport
* Print

### Commands

* domain
* gcb-assets
* gcb-ioc-details
* pan-os-register-user-tag
* send-mail
* whois

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| networkteam_email | Enter the email address of the network team that needs to be notified.  |  | Optional |
| stakeholder_email | Enter the email of the stakeholder to whom you want to send the investigation summary report. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---
![Investigate On Bad Domain Matches - Chronicle](./../doc_files/Investigate_On_Bad_Domain_Matches_-_Chronicle.png)