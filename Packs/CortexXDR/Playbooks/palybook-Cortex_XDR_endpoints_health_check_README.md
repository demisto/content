This playbook queries disconnected/lost Cortex XDR endpoints with a provided last seen time range playbook input.
The playbook generates a CSV report, including a detailed list of the unhealthy endpoints, and sends the report to the provided email addresses.
The playbook includes an incident type with a dedicated layout to visualize the collected data.
Supported Cortex XSOAR versions: 5.5.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
* send-mail
* setIncident
* xdr-get-endpoints

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| LastSeenStartDate | Last seen start date range filter in  yyyy-mm-dd format. |  | Optional |
| LastSeenEndDate | Last seen end date range filter in  yyyy-mm-dd format. |  | Optional |
| Email | Email addresses to send the disconnected endpoints report. |  | Optional |
| MessageBody | Body for the report email message.  | This message contains an automatically generated report by Cortex XSOAR, including a list of unhealthy and disconnected Cortex XDR endpoints.<br/>Please investigate and remediate according to the organization's policy. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR endpoints health check](Insert the link to your image here)
