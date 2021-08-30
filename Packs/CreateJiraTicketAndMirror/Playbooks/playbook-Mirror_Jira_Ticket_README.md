Mirror ServiceNow Ticket is designed to serve as a sub-playbook, which enables ticket mirroring with ServiceNow.
It enables you to manage ServiceNow tickets in Cortex xSOAR while data is continuously synced between ServiceNow and Cortex xSOAR, including ServiceNow schema, fields, comments, work notes, and attachments.

To enable OOTB mirroring, use the ServiceNow Create ticket  - common mappers for incoming and outgoing mirroring.

FieldPolling - You can the FieldPolling value to true if you only want to be informed when the ticket is resolved or closed. If FieldPolling is set to true, the FieldPolling Playbook will poll for the state(ServiceNow State field) of the ServiceNow ticket until it marks as either resolved or closed.

In Addition to the playbook, we recommend that you use the included layout for ServiceNow Ticket, which helps visualize ServiceNow ticket information in Cortex xSOAR.
You can add the new layout as a tab to existing layouts using the Edit Layout page.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Field Polling - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TicketId | Jira Ticket ID to mirror. |  | Optional |
| MirrorInstanceName | Set the mirror instance name to enable mirroring with Jira. |  | Optional |
| MirrorDirection | Set the mirror direction, should be one of the following: <br/>1. In<br/>2. Out<br/>3. Both | Both | Optional |
| MirrorCommentTags | Set tags for mirror comments and files to ServiceNow | comment | Optional |
| FieldPolling  | Set the value to true or false to determine if the FieldPolling sub-playbook will be executed in the context of a parent playbook.<br/>This is useful in cases when it is needed to wait for the ServiceNow ticket to be resolved in order to continue the parent playbook.<br/> |  | Optional |
| FieldPollingInterval | Set interval time for the polling to run<br/>\(In minutes\) |  | Optional |
| FieldPollingTimeout | <br/>Set the amount of time to poll the status of the ticket before declaring a timeout and resuming the playbook.<br/>\(In minutes\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Mirror Jira Ticket](Insert the link to your image here)