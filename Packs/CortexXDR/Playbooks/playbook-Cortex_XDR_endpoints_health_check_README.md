This playbook will query disconnected/lost Cortex XDR endpoints with a provided last seen time range playbook input.
The playbook will also generate a CSV report, including a detailed list of the unhealthy endpoints, and send the report to the provided email addresses.
This playbook also includes an incident type with a dedicated layout to visualize the collected data.
Supported Cortex XSOAR versions: 5.5.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR

### Scripts
* ExportToCSV
* Set
* SetGridField

### Commands
* xdr-get-endpoints
* send-mail
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| LastSeenStartDate | Last seen start date, in relative timestamp - "1 Day" or  "7 days"  |  | Optional |
| LastSeenEndDate | Last seen end date, in relative timestamp - "1 Day" or  "7 days" <br/>for the current day use "0 days" |  | Optional |
| Email | Email addresses to send the disconnected endpoints report. |  | Optional |
| MessageBody | Body for the report email message.  | This message contains an automatically generated report by Cortex XSOAR, including a list of unhealthy and disconnected Cortex XDR endpoints.<br/>Please investigate and remediate according to the organisation's policy. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR endpoints health check](Insert the link to your image here)