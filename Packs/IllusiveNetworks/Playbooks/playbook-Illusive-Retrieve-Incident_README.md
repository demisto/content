This playbook is used for retrieving an extensive view over a detected incident by retrieving the incident details and a forensics timeline if and when forensics have been successfully collected.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* IllusiveNetworks

### Scripts
* PrintErrorEntry
* Print

### Commands
* illusive-get-incidents
* illusive-get-forensics-timeline

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| incident_id | The desired incident ID to retrieve. |  |  | Optional |
| start_date | The starting date of the forensics timeline.start\_date is in Zulu time format, for example: 1993\-09\-24T17:30:00.000Z. |  |  | Optional |
| end_date | The last date of the forensics timeline.end\_date is in Zulu time format, for example: 1993\-09\-24T17:30:00.000Z. |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->