  A job to periodically query Cortex XDR device control violations by a given timestamp in a relative date playbook input.
  The collected data, if found, will be generated for a new incident.
  You can configure the created new incident type in the playbook input and use the XDR Device Control Violations incident type to associate it with the response playbook.
  The job includes an incident type with a dedicated layout to visualize the collected data.
  To configure the job correctly:
  1. Create a new recurring job.
  2. Configure the recurring schedule.
  3. Add a name.
  4. Configure the type to XDR Device Control Violations.
  5. Configure this playbook as the job playbook.
  The scheduled run time and the timestamp relative date should be identical.
  If the job recurs every 7 days, the timestamp should be 7 days as well.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR

### Scripts
* SetGridField

### Commands
* closeInvestigation
* createNewIncident
* setIncident
* xdr-get-endpoint-device-control-violations

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TimeStamp | Timestamp in relative date format for query device control events<br/>from Cortex XDR.<br/>For example "1 day", "3 weeks". |  | Optional |
| Severity | The severity of the created incident when the device control events were found.<br/>Valid values are; <br/>   0 - Unknown<br/>   0.5 - Informational<br/>   1 - Low<br/>   2 - Medium<br/>   3 - High<br/>   4 - Critical | 1 | Optional |
| IncidentType | The desired incident type for the created incident when the device control violations were found. | Cortex XDR Device Control Violations | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![JOB - Cortex XDR query endpoint device control violations](Insert the link to your image here)