Create ServiceNow Ticket allows you to open new tickets as a task from a parent playbook.
It is an option to set sync with the ticket's state, which will wait for the ticket to resolve or close with StatePolling.
You can alternatively select to mirror the ServiceNow ticket and incident fields. Mirroring includes its equivalent for StatePolling -  FieldPolling.
To apply either of these options, set the SyncTicket value in the playbook inputs to one of the following options:
1. StatePolling
2. Mirror
3. Leave Blank to use none.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Mirror ServiceNow Ticket
* ServiceNow Ticket State Polling

### Integrations
* ServiceNow v2

### Scripts
This playbook does not use any scripts.

### Commands
* servicenow-create-ticket

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Category | Set the category of the ServiceNow Ticket. |  | Optional |
| AssignmentGroup | The group to assign the new ticket to  |  | Optional |
| ShortDescription | Set A short description of the ticket. |  | Optional |
| Impact | Set Impact for the new ticket, leave empty for ServiceNow default impact. |  | Optional |
| Urgency | Set urgency to the new ticket, leave empty for ServiceNow default urgency. |  | Optional |
| Severity  | Set severity to the new ticket, leave empty for ServiceNow default severity. |  | Optional |
| Comment | Add a comment for the created ticket. |  | Optional |
| SyncTicket | Set the value of the desired sync method with ServiceNow Ticket. you can choose one of three options:<br/>1. StatePolling<br/>2. Mirror <br/>3. Blank for none <br/><br/>GenericPolling uses as cold sync, which polls for the state of the ticket.<br/>GenericPoliing will run until the ticket state is either resolved or closed. <br/><br/>Mirror - You can use the Mirror option to perform a full sync with ServiceNow Ticket. The ticket data is synced automatically between ServiceNow and Cortex xSOAR with the ServiceNow mirror feature.<br/>If this option is selected, FieldPolling is true by default.  |  | Optional |
| PollingInterval | Set interval time for the polling to run<br/>\(In minutes\) |  | Optional |
| PollingTimeout | Set the amount of time to poll the status of the ticket before declaring a timeout and resuming the playbook.<br/>\(In minutes\) |  | Optional |
| AdditionalPollingCommandName | In this use case, Additional polling commands are relevant when using StatePolling, and there is more than one ServiceNow instance. It will specify the polling command to use a specific instance to run on. <br/>If so, please add "Using" to the value. <br/>The playbook will then take the instance name as the instance to use.  |  | Optional |
| InstanceName | Set the ServiceNow Instance that will be used for mirroring/running polling commands.<br/> |  | Optional |
| MirrorDirection | Set the mirror direction, should be one of the following: <br/>1. Out<br/>2. Both | Both | Optional |
| MirrorCommentTags | Set tags for mirror comments and files to ServiceNow. | comments,work_notes,ForServiceNow | Optional |
| FieldPolling | Set the value to true or false to determine if the paybook will execute the FieldPolling sub playbook.<br/>It is useful when it is needed to wait for the ServiceNow ticket to be resolved and continue the parent playbook.<br/>FieldPolling will run until the ticket state is either resolved or closed. | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Create ServiceNow Ticket](https://raw.githubusercontent.com/demisto/content/master/Packs/ServiceNow/doc_files/Create_ServiceNow_Ticket.png)
