Use ServiceNow Incident State Polling as a sub-playbook when required to pause the execution of a master playbook until the ServiceNow ticket state is either resolved or closed.
This playbook implements polling by continuously running the servicenow-get-ticket command until the state is either resolved or closed.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* ScheduleGenericPolling
* RunPollingCommand
* PrintErrorEntry

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TicketNumber | ServiceNow ticket number to poll its state. |  | Required |
| Interval | Frequency that the polling command will run \(minutes\). |  | Required |
| Timeout | Amount of time to poll before declaring a timeout and resuming the playbook \(in minutes\). |  | Required |
| InstanceName | Set the ServiceNow Instance that will be used by the polling command.<br/>Only relevant when there is more than one ServiceNow instance. |  | Optional |
| AdditionalPollingCommandName | Values of the additional arguments for the polling command, for example: \(value1,value2,...\). |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ServiceNow Ticket State Polling](https://raw.githubusercontent.com/demisto/content/master/Packs/ServiceNow/doc_files/ServiceNow_Ticket_State_Polling.png)
