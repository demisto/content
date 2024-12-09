Implements polling by continuously running the command in Step #2 (below) until the operation completes.
Use this playbook as a sub-playbook to block the execution of the master playbook until a remote action is complete.

The remote action should have the following structure:

1. Initiate the operation.
2. Poll to check if the operation completed.
3. (optional) Get the results of the operation.

For more information on polling, go to [Playbook Polling (Cortex XSOAR 6.x)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Playbook-Polling) or [Playbook Polling (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Playbook-polling) or [Playbook Polling (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Playbook-polling).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* PrintErrorEntry
* RunPollingCommand
* ScheduleGenericPolling

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| Ids | The list of IDs to poll. | - |Required |
| PollingCommandName | The name of the polling command to run. | - | Required |
| PollingCommandArgName | The argument name of the polling command. | ids | Required |
| Interval | The frequency that the polling command will run (in minutes). | 1 |Required |
| Timeout | The amount of time in which to poll before declaring a timeout and resuming the playbook (in minutes). | 10 | Required |
| dt | The DT filter for polling IDs. Polling will stop when no results are returned. Use single quotes, for example: WildFire.Report(val.Status!=='Success').SHA256. | - | Required |
| AdditionalPollingCommandArgNames | The names of additional arguments for the polling command. For example, "arg1,arg2,...". | - | Optional |
| AdditionalPollingCommandArgValues | The values of the additional arguments for the polling command. For example, "value1,value2,...". | - | Optional |
| ExtractMode | Indicator Extraction mode for the command sequence. (In XSOAR 8 and above, for first run command set manually the RunPollingCommand task in the playbook, Advanced -> Indicator Extraction mode). | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![GenericPolling](../doc_files/GenericPolling.png)
