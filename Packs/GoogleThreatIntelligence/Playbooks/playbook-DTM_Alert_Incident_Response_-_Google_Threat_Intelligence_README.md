This playbook initiates the response for DTM Alerts in XSOAR when an incident is investigated. For medium or higher severity, it creates a ServiceNow ticket; otherwise, the incident is assigned to an analyst. The ticket is enriched with GTI DTM Alert details, including alert type, status, monitor information, summary, AI Doc summary, and tags.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Create ServiceNow Ticket

### Integrations

This playbook does not use any integrations.

### Scripts

* AssignAnalystToIncident
* DeleteContext
* Print
* SetAndHandleEmpty

### Commands

* servicenow-update-ticket

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| alert_id | Collection DTM Alert ID from incident. | incident.alertid | Optional |
| incident_severity | Collect incident severity from incident. | incident.severity | Optional |
| onCall | Set to true to assign only the user that is currently on shift. Default is False. | false | Optional |
| severity_mapping | Set the alert severity mapping as per GTI platform. | incident.severity | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DTM Alert Incident Response - Google Threat Intelligence](../doc_files/DTM_Alert_Incident_Response_-_Google_Threat_Intelligence.png)
