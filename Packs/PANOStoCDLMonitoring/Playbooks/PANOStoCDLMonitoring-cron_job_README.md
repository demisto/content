This playbook verifies that your FWs sent logs to the Strata Logging Service in the last 12 hours. An email notification will be sent if it's not the case.
This playbook is designed to run as a job.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Mail Sender (New)

### Scripts
* FW-to-CDL-monitoring
* IncreaseIncidentSeverity

### Commands
* createNewIncident
* send-mail
* closeInvestigation
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fw_serials | A comma-separated list of FW serials to monitor. Only applicable if no Panorama integration specified.  | ${incident.fwserials} | Optional |
| panorama_integration | Name of the Panorama integration to gather the list of monitored FWs. If none specified, the list of serials must be provided manually as "fw_serials". | ${incident.panoramaintegration} | Optional |
| email_notification | Email address to send a notification to in case detected problem. | ${incident.email} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
