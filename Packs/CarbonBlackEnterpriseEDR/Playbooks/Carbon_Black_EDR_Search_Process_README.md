Use this playbook to search processes in Carbon Black Enterprise EDR.
This playbook implements polling by continuously running the `cb-eedr-process-search-results` command
until the operation completes.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CarbonBlackEnterpriseEDR

### Scripts
This playbook does not use any scripts.

### Commands
* cb-eedr-process-search-results
* cb-eedr-process-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| query | Query with Carbon Black API syntax |  | Optional |
| process_name | Tokenized file path of the process’ main module. |  | Optional |
| process_hash | MD5 and SHA-256 hashes of process’ main module in a multi-valued field. |  | Optional |
| event_id | CBD Event id \(valid only for events coming through Analytics\) |  | Optional |
| limit | number of results to fetch |  | Optional |
| interval | determine how long to wait between fetching data for polling | 1 | Optional |
| timeout | determine timeout for polling | 10 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CarbonBlackEEDR.SearchProcess.job_id | A request job id. | string |
| CarbonBlackEEDR.SearchProcess.status | A request job current status. | string |
| CarbonBlackEEDR.SearchProcess.results.device_id | Device id that is guaranteed to be unique within each PSC environment, which is a set of organizations. | number |
| CarbonBlackEEDR.SearchProcess.results.process_username | Usernames related to process. | string |
| CarbonBlackEEDR.SearchProcess.results.backend_timestamp | Date/time field formatted as ISO-8601 string based on UTC timezone. For example, device_timestamp:2018-03-14T21:06:45.183Z | date |
| CarbonBlackEEDR.SearchProcess.results.childproc_count | Cumulative counts of child process creations since process tracking started. | number |
| CarbonBlackEEDR.SearchProcess.results.crossproc_count | Cumulative counts of cross-process events since process tracking started. | number |
| CarbonBlackEEDR.SearchProcess.results.device_group_id | Id of sensor group where the device belongs. | number |
| CarbonBlackEEDR.SearchProcess.results.device_name | Name of device. | string |
| CarbonBlackEEDR.SearchProcess.results.device_policy_id | Id of policy applied to the device. | number |
| CarbonBlackEEDR.SearchProcess.results.device_timestamp | Time seen on sensor, based on sensor’s clock. ISO-8601 formatted time string based on UTC. | date |
| CarbonBlackEEDR.SearchProcess.results.enriched | True if process document came from the CbD data stream. | boolean |
| CarbonBlackEEDR.SearchProcess.results.enriched_event_type | CbD enriched event type. | string |
| CarbonBlackEEDR.SearchProcess.results.event_type | CBD Event type \(valid only for events coming through Analytics\). One of CREATE_PROCESS, DATA_ACCESS, FILE_CREATE, INJECT_CODE, NETWORK, POLICY_ACTION, REGISTRY_ACCESS, SYSTEM_API_CALL. | string |
| CarbonBlackEEDR.SearchProcess.results.filemod_count | Cumulative counts of file modifications since process tracking started. | number |
| CarbonBlackEEDR.SearchProcess.results.ingress_time | Unknown | date |
| CarbonBlackEEDR.SearchProcess.results.legacy | True if process document came from the legacy data stream \(deprecated, use enriched\). | boolean |
| CarbonBlackEEDR.SearchProcess.results.modload_count | Cumulative counts of module loads since process tracking started. | number |
| CarbonBlackEEDR.SearchProcess.results.netconn_count | Cumulative counts of network connections since process tracking started. | number |
| CarbonBlackEEDR.SearchProcess.results.org_id | Globally unique organization key \(will likely be PSC organization id \+ PSC environment id or some other unique token used across environments\) | string |
| CarbonBlackEEDR.SearchProcess.results.parent_guid | process_guid of parent process. | string |
| CarbonBlackEEDR.SearchProcess.results.parent_pid | PID of parent process. | number |
| CarbonBlackEEDR.SearchProcess.results.process_guid | Unique id of process \(same as document_guid above but without the timestamp suffix\). | string |
| CarbonBlackEEDR.SearchProcess.results.process_hash | MD5 and SHA-256 hashes of process’ main module in a multi-valued field. | string |
| CarbonBlackEEDR.SearchProcess.results.process_name | Tokenized file path of the process’ main module. | string |
| CarbonBlackEEDR.SearchProcess.results.process_pid | PID of a process. Can be multi-valued in case of exec/fork on Linux/OSX. | number |
