Mirror Jira Ticket is designed to serve as a sub-playbook, which enables ticket mirroring with Jira.

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
| MirrorDirection | Set the mirror direction, should be one of the following: <br/>1. In<br/>2. Out<br/>3. Both |  | Optional |
| MirrorTags | Set tags for mirror comments and files to Jira |  | Optional |
| FieldPolling  | Set the value to true or false to determine if the FieldPolling sub-playbook will be executed in the context of a parent playbook.<br/>This is useful in cases when it is needed to wait for the Jira issue to be resolved in order to continue the parent playbook.<br/> |  | Optional |
| FieldPollingInterval | Set interval time for the polling to run<br/>\(In minutes\) |  | Optional |
| FieldPollingTimeout | <br/>Set the amount of time to poll the status of the ticket before declaring a timeout and resuming the playbook.<br/>\(In minutes\) |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Mirror Jira Ticket](../doc_files/Mirror_Jira_Ticket.png)