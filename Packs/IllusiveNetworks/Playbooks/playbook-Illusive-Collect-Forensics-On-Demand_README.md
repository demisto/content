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
* DeleteContext

### Commands
* illusive-get-event-incident-id
* illusive-get-forensics-timeline
* illusive-run-forensics-on-demand

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fqdn_or_ip  | The host fqdn or IP address on which to collect forensics |  | Optional |
| start_date | The starting date of the forensics timeline.
 |  | Optional |
| end_date | The last date of the forensics timeline.
 |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->