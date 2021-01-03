A Job to periodically query Cortex XDR device control violations by a given timestamp in a relative date playbook input.
The Collected data, if found will be generated for a new incident.
You can set the created new incident type in the playbook input, use XDR Device Control Violations incident type to associate it with the response playbook.
The job includes an incident type with a dedicated layout to visualize the collected data.
To set the job correctly, you will need to.

1. Create a new recurring job.
2. Set the recurring schedule.
3. Add a name.
4. Set type to XDR Device Control Violations.
5. Set this playbook as the job playbook.

The scheduled run time and the timestamp relative date should be identical.
If the job is recurring every 7 days, the timestamp should be 7 days as well.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-get-endpoint-device-control-violations
* createNewIncident
* setIncident
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TimeStamp | Timestamp in relative date format for fetching  device control events from Cortex XDR |  | Optional |
| Severity | The severity of the created incident when device control events were found. | 1 | Optional |
| IncidentType | The desired incident type for the created incident when device control violations are found. | XDR Device Control Violations | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![JOB - Cortex XDR query endpoint device control violations](Insert the link to your image here)