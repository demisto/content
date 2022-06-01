Close the XSOAR incident if the IoT ServiceNow ticket was closed. This command should be run in a Job.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | iot |
| Cortex XSOAR Version | 5.5.0 |

This script is run by a playbook 'iot-check-service-playbook', that is run by a recurring XSOAR job.

First of all, we are looping all the open XSOAR incidents based on two incident types:
"IoT Alert" and "IoT Vulnerability"

Then we are only interested of the ones with a customized instance field: ServiceNow table name, that tells us a
corresponding ServiceNow ticket was created. Looping each one of this incident, and query ServiceNow for the ticket
status. If the status is "Closed", we are closing the XSOAR incident.

## Used In
---
This script is used in the following playbooks and scripts.
* PANW IoT ServiceNow Tickets Check

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
