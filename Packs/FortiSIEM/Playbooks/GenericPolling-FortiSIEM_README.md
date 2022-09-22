This playbook executes a search query to retrieve FortiSIEM Events.
​
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.
​
### Sub-playbooks
* GenericPolling
​
### Integrations
* FortiSIEMV2
​
### Scripts
This playbook does not use any scripts.
​
### Commands
***fortisiem-event-search-status***
***fortisiem-event-search-results***
***fortisiem-event-search***
​
## Playbook Inputs
---
​
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| query | The query for filtering the relevant events. For example, "eventId=9071234812319593968 AND eventType='type'". You can retrieve the attributes' names using the command's filtering arguments or using the event attributes returned in the context output. |  | Optional |
| limit | The number of results to retrieve. Minimum value is 1. Default value is 50. |  | Optional |
| page | The page number of the results to retrieve. Minimum value is 1. Default value is 1. |  | Optional |
| Start time | Start of the time filter for events. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". |  | Required |
| To Time | End of the time filter for events. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". |  | Required |
​
## Playbook Outputs
---
​
| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FortiSIEM.Event | The events retrieved from the search query. | unknown |
