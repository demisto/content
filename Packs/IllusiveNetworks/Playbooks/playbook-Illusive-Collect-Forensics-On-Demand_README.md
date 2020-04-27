This playbook is used to collect forensics on-demand on any compromised host and retrieve the forensics timeline upon successful collection.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* IllusiveNetworks

### Scripts
* PrintErrorEntry
* Print

### Commands
* illusive-get-event-incident-id
* illusive-run-forensics-on-demand
* illusive-get-forensics-timeline

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| fqdn_or_ip  | The host fqdn or IP address on which to collect forensics |  |  | Optional |
| start_date | The starting date of the forensics timeline.start\_date is in Zulu time format, for example: 1993\-09\-24T17:30:00.000Z. |  |  | Optional |
| end_date | The last date of the forensics timeline.end\_date is in Zulu time format, for example: 1993\-09\-24T17:30:00.000Z.|  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->