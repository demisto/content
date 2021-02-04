This is a generic playbook to be executed for the QRadar Generic incident type. The playbook performs all the common parts of the investigation including notifying the SOC, enriching the data for indicators and users, calculating the severity, assigning the incident, notifying the SIEM admin for false positives and more.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Entity Enrichment - Generic v2
* Calculate Severity - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* GenerateInvestigationSummaryReport
* AssignAnalystToIncident

### Commands
* send-mail
* setIncident
* extractIndicators
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Enrich | Determines whether to enrich all indicators in the incident. Specify true to perform enrichment or any other value not to perform enrichment. | true | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | false | Optional |
| SocEmailAddress | The SOC team's email address to send emails to. |  | Optional |
| SocMailSubject | The subject of the mail to send to the SOC. | XSOAR Summary report, ID -  | Optional |
| SiemAdminEmailAddress | The SIEM admin's email address to send emails to. |  | Optional |
| UseCalculateSeverity | Determines whether to use the Calculate Severity playbook to calculate the incident severity.  Specify true to use the playbook or any other value to accept the severity from the QRadar magnitude value. | true | Optional |
| SiemAdminMailSubject | The subject of the mail to send to the SIEM admin. | Adjustment/Exclusion for offense  | Optional |
| FieldToSetSeverityFrom | Specify the field to use for calculating the incident severity. The default field is magnitude. An additional field can be severity.<br/> | incident.magnitudeoffense | Optional |
| ScaleToSetSeverityFrom | Specify the severity to assign to the field value in FieldToSetSeverityFrom input<br/>values can be 0-4 with<br/>0 - Informational<br/>1 - Low<br/>2 - Medium<br/>3 - High<br/>4 - Critical<br/><br/>With the default values 1,1,1,2,2,2,2,3,3,3 <br/>1 - 3 is Low<br/>4 - 7 is Medium<br/>8 - 10 is High | 1,1,1,2,2,2,2,3,3,3 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![QRadar Generic](Insert the link to your image here)