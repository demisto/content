Closes the Cortex XSOAR incident if the Device Security ServiceNow ticket was closed. This command should be run in a Job.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | device security |
| Cortex XSOAR Version | 5.5.0 |

This script is run by a playbook 'device-security-check-service-playbook', that is run by a recurring XSOAR job.

First of all, we are looping all the open XSOAR incidents based on two incident types:
"Device Security Alert" and "Device Security Vulnerability"

Then we are only interested in incidents where the custom fields "Device Security ServiceNow Table Name" and
"Device Security ServiceNow Record ID" are populated, which indicates that a corresponding ServiceNow ticket was created.

For each matching incident, the script queries ServiceNow for the ticket status.
If the status is "Closed", the script closes the corresponding XSOAR incident.

## Used In

---
This script is used in the following playbooks and scripts.

* PANW Device Security ServiceNow Tickets Check

## Outputs

---
There are no outputs for this script.
