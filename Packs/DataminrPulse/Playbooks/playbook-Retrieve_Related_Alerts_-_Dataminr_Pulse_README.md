This playbook is used to fetch related alerts for Dataminr Pulse. The information required to fetch related alerts will be used from the incident s alert ID for which the playbook is going to run. After that, it will store them in the context.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext

### Commands
* dataminrpulse-related-alerts-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| include_related_alerts | Boolean value indicating whether to include related alerts. If set to "true", it includes related alerts; otherwise, it does not. | ${incident.labels.include_related_alerts} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Retrieve Related Alerts - Dataminr Pulse](../doc_files/Retrieve_Related_Alerts_-_Dataminr_Pulse.png)