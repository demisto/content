You should run this playbook as a scheduled job.  The playbook checks the health of all enabled integrations and open incidents.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Integrations and Incidents Health Check - Running Scripts
* JOB - Integrations and Incidents Health Check - Lists handling

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext
* CopyLinkedAnalystNotes
* FindSimilarIncidents

### Commands
* generateGeneralReport
* closeInvestigation
* send-mail
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SendHealthCheckReport | This input determines if the health check report should be sent automatically after running the playbook.<br/>True - Yes. |  | Optional |
| EmailReportTo | In case the 'SendHealthCheckReport' input equals to 'True', the email address the report will be sent to. |  | Optional |
| AutoCloseInvestigation | This input determines if the investigation should close automatically after the re-run of the scripts. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![JOB - Integrations and Playbooks Health Check](https://raw.githubusercontent.com/demisto/content/70deb610bd081957d58323b197d4648dc504722c/Packs/IntegrationsAndIncidentsHealthCheck/doc_files/JOB_-_Integrations_and_Playbooks_Checkup.png)