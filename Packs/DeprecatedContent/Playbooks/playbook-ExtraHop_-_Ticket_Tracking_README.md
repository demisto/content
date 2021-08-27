Deprecated. Use the "ExtraHop - Ticket Tracking v2" playbook instead.
Links the Demisto incident back to the ExtraHop detection that created it for ticket tracking purposes.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SearchIncidentsV2
* Exists
* AssignAnalystToIncident

### Commands
* extrahop-track-ticket
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
