A Job to periodically query disconnected Cortex XDR endpoints with a provided last seen time range playbook input.
The Collected data, if found will be generated to a CSV report, including a detailed list of the disconnected endpoints.
The report will be sent to the recipient's provided email addresses in the playbook input.
The playbook includes an incident type with a dedicated layout to visualize the collected data.
To set the job correctly, you will need to.
1. Create a new recurring job.
2. Set the recurring schedule.
3. Add a name.
4. Set type to Cortex XDR disconnected endpoints.
5. Set this playbook as the job playbook.

The scheduled run time and the timestamp relative date should be identical,
If the job is recurring every 7 days, the time range should be 7 days as well.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* send-mail
* xdr-get-endpoints
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| LastSeenStartDate | Last seen start date, in relative timestamp - "1 Day" or  "7 days"  | None | Optional |
| LastSeenEndDate | Last seen end date, in relative timestamp - "1 Day" or  "7 days" <br/>For the current day use "0 days" | None | Optional |
| Email | Email addresses to send the disconnected endpoints report. | None | Optional |
| MessageBody | Body for the report email message.  | This message contains an automatically generated report by Cortex XSOAR, including a list of  disconnected Cortex XDR endpoints.<br/>Please investigate and remediate according to the organization's policy. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR disconnected endpoints](https://raw.githubusercontent.com/demisto/content/eef4d1c2706bf41afa522d6cec8d092bc2e3e562/Packs/CortexXDR/doc_files/Cortex_XDR_disconnected_endpoints.png)