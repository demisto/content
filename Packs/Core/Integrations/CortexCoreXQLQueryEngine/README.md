XQL Query Engine enables you to run XQL queries on your data sources.

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

## Important Information

Running commands via the XQL Query Engine integration will consume compute units.

### xdr-xql-generic-query

***
Execute an XQL query and retrieve results of an executed XQL query API. The command will be executed every 10 seconds until results are retrieved or until a timeout error is raised. When more than 1000 results are retrieved, the command will return a compressed gzipped JSON format file, unless the argument 'parse_result_file_to_context' is set to true and then the results will be extracted to the context.



#### Base Command

`xdr-xql-generic-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | XQL query string. By default up to 100 results are returned. To retrieve more results, enter a custom limit in the query. | Required | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| max_fields | The maximum number of returned fields per result. Default is 20. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |  


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.GenericQuery.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.GenericQuery.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.GenericQuery.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.GenericQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.GenericQuery.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.GenericQuery.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.GenericQuery.results._time | Date | Result time. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.GenericQuery.results.mac | Unknown | Host MAC address. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_effective_username | String | Parent user name. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_command_line | String | Command line arguments of the initiator. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_os_pid | Number | Initiator process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_signature_vendor | String | Initiator signer. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_signature_status | String | Signing status of the initiator. Possible values: Unsigned, Signed, Invalid Signature, and Unknown. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_name | String | The name of the process that initiated the causality chain. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_path | String | Causality group owner path of the initiating process. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_command_line | String | Command line arguments of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_os_pid | Number | Causality group owner process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_sha256 | String | The SHA256 value of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_signature_vendor | String | Causality group owner signer. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_signature_status | String | Signing status of the causality group owner. Possible values: Unsigned, Signed, Invalid Signature, and Unknown. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_type | String | The type of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_image_name | String | The name of the operating system that initiated the activity. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_image_path | String | Operating system parent path. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_command_line | String | Command line arguments of the operating system parent. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_os_pid | Number | Operating system parent process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.action_remote_process_image_sha256 | Unknown | The SHA256 value of the operating system parent. | 
| PaloAltoNetworksXQL.GenericQuery.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.GenericQuery.results._product | String | The result product. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_install_type | String | Initiator install type. | 


#### Command Example
```!xdr-xql-generic-query query=`dataset = xdr_data | fields action_evtlog_message, event_id | limit 10```

#### Human Readable Output

>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|---|
>| 12345678_inv | 10 | dataset = xdr_data &#124; fields action_evtlog_message, event_id &#124; limit 10 | 376699223: 0.0002125 | 999.9994905555556 | SUCCESS |

>### Data Results
>|Product|Time|Vendor|Action Evtlog Message|Event Id|Insert Timestamp|
>|---|---|---|---|---|---|
>| P1 | 2021-08-28T09:15:56.000Z | PANW |  | test1 | 2021-08-28T09:22:39.000Z |
>| P1 | 2021-08-28T09:17:55.000Z | PANW |  | test2 | 2021-08-28T09:22:39.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test3 | 2021-08-28T09:22:23.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test4 | 2021-08-28T09:22:29.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test5 | 2021-08-28T09:22:29.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test6 | 2021-08-28T09:22:14.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test7 | 2021-08-28T09:22:23.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test8 | 2021-08-28T09:22:14.000Z |
>| P1 | 2021-08-28T09:14:57.000Z | PANW |  | test9 | 2021-08-28T09:22:29.000Z |
>| P1 | 2021-08-28T09:12:57.000Z | PANW |  | test10 | 2021-08-28T09:22:23.000Z |


### xdr-xql-get-quota
***
Retrieve the amount of query quota available and used.


#### Base Command

`xdr-xql-get-quota`
#### Input

There are no input arguments for this command.


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.Quota.license_quota | Number | Amount of daily quota allocated to your tenant based on your license type and size. | 
| PaloAltoNetworksXQL.Quota.additional_purchased_quota | Number | Amount of query quota purchased. | 
| PaloAltoNetworksXQL.Quota.used_quota | Number | Amount of query quota used over the past 24 hours. | 


#### Command Example
```!xdr-xql-get-quota```

#### Context Example
```json
{
    "PaloAltoNetworksXQL": {
        "Quota": {
            "additional_purchased_quota": 0,
            "eval_quota": 0,
            "license_quota": 1000,
            "used_quota": 0.00299
        }
    }
}
```

#### Human Readable Output

>### Quota Results
>|Additional Purchased Quota|Eval Quota|License Quota|Used Quota|
>|---|---|---|---|
>| 0.0 | 0.0 | 1000 | 0.00299 |


### xdr-xql-get-query-results
***
Retrieve results of an executed XQL query API. When more than 1000 results are retrieved, the command will return a compressed gzipped JSON format file, unless the argument 'parse_result_file_to_context' is set to true and then the results will be extracted to the context.



#### Base Command

`xdr-xql-get-query-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | Integer representing the unique execution ID generated by the response to start an XQL query API. | Required | 
| max_fields | The maximum number of returned fields per result. Default is 20. | Optional |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |  


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.GenericQuery.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.GenericQuery.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.GenericQuery.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.GenericQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.GenericQuery.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.GenericQuery.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.GenericQuery.results._time | Date | Result time. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.GenericQuery.results.mac | Unknown | Host MAC address. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_effective_username | String | Parent user name. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_command_line | String | Command line arguments of the initiator. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_os_pid | Number | Initiator process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_signature_vendor | String | Initiator signer. | 
| PaloAltoNetworksXQL.GenericQuery.results.actor_process_signature_status | String | Signing status of the initiator. Possible values: Unsigned, Signed, Invalid Signature, and Unknown. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_name | String | The name of the process that initiated the causality chain. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_path | String | Causality group owner path of the initiating process. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_command_line | String | Command line arguments of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_os_pid | Number | Causality group owner process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_image_sha256 | String | The SHA256 value of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_signature_vendor | String | Causality group owner signer. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_process_signature_status | String | Signing status of the causality group owner. Possible values: Unsigned, Signed, Invalid Signature, and Unknown. | 
| PaloAltoNetworksXQL.GenericQuery.results.causality_actor_type | String | The type of the causality group owner. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_image_name | String | The name of the operating system that initiated the activity. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_image_path | String | Operating system parent path. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_command_line | String | Command line arguments of the operating system parent. | 
| PaloAltoNetworksXQL.GenericQuery.results.os_actor_process_os_pid | Number | Operating system parent process ID. | 
| PaloAltoNetworksXQL.GenericQuery.results.action_remote_process_image_sha256 | Unknown | The SHA256 value of the operating system parent. | 
| PaloAltoNetworksXQL.GenericQuery.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.GenericQuery.results._product | String | The result product. | 
| PaloAltoNetworksXQL.GenericQuery.results.agent_install_type | String | Initiator install type. | 


#### Command Example
``` !xdr-xql-get-query-results query_id=12345678_inv ```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|
>| 12345678_inv | 2 | 376699223: 0.0007208333333333333 | 999.9845016666667 | SUCCESS |
>### Data Results
>|Product|Time|Vendor|Event Id|Insert Timestamp|
>|---|---|---|---|---|
>| XDR agent | 2021-08-29T07:40:07.000Z | PANW | test1 | 2021-08-29T07:45:08.000Z |
>| XDR agent | 2021-08-29T07:40:06.000Z | PANW | test2 | 2021-08-29T07:45:08.000Z |


### xdr-xql-file-event-query
***
Query file events by the SHA256 file.


#### Base Command

`xdr-xql-file-event-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| file_sha256 | SHA256 file to run the query on. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.FileEvent.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.FileEvent.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.FileEvent.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.FileEvent.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.FileEvent.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.FileEvent.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.FileEvent.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.FileEvent.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.FileEvent.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.FileEvent.results.action_file_path | String | File path of the action. | 
| PaloAltoNetworksXQL.FileEvent.results.action_file_sha256 | String | SHA256 hash value of the file. | 
| PaloAltoNetworksXQL.FileEvent.results.actor_process_file_create_time | String | Initiator file create time. | 
| PaloAltoNetworksXQL.FileEvent.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.FileEvent.results._time | String | Result time. | 
| PaloAltoNetworksXQL.FileEvent.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.FileEvent.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-file-event-query file_sha256=12345,6789 endpoint_id=test1,test2 time_frame="1 month" ```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 12345678_inv | 1 | dataset = xdr_data &#124; filter agent_id in ("test1","test2")<br>           and event_type = FILE and action_file_sha256 in ("12345","6789")&#124;<br>           fields agent_hostname, agent_ip_addresses, agent_id, action_file_path,<br>           action_file_sha256, actor_process_file_create_time &#124; limit 200 | 376699223: 0.002704166666666667 | 999.9795586111111 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action File Path|Action File Sha256|Actor Process File Create Time|Agent Hostname|Agent Id|Agent Ip Addresses|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-04T10:57:09.000Z | PANW | C:\Users\test1\test2 | Action File SHA | 2021-05-21T11:20:52.000Z | WIN10X64 | AgentID | IP | 2021-08-04T11:01:08.000Z |


### xdr-xql-process-event-query
***
Query process events by the SHA256 process.


#### Base Command

`xdr-xql-process-event-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| process_sha256 | The SHA256 hash of the primary involved process to search on the XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.ProcessEvent.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.ProcessEvent.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.ProcessEvent.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.ProcessEvent.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.ProcessEvent.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.ProcessEvent.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.ProcessEvent.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.ProcessEvent.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.ProcessEvent.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_image_sha256 | String | Target SHA256 process. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_image_name | String | Target process name. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_image_path | String | Target process image path. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_instance_id | String | Target process instance ID. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_causality_id | String | Target process causality ID. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_signature_vendor | String | Process execution signer. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_signature_product | String | Process signature product. | 
| PaloAltoNetworksXQL.ProcessEvent.results.action_process_image_command_line | String | Target process command line. | 
| PaloAltoNetworksXQL.ProcessEvent.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.ProcessEvent.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.ProcessEvent.results.actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.ProcessEvent.results.actor_process_causality_id | String | Initiator causality ID. | 
| PaloAltoNetworksXQL.ProcessEvent.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.ProcessEvent.results._time | String | Result time. | 
| PaloAltoNetworksXQL.ProcessEvent.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.ProcessEvent.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-process-event-query process_sha256=12345,6789 endpoint_id=test1,test2 time_frame="1 month" ```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 2743_inv | 3 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = PROCESS and<br>            action_process_image_sha256 in ("abcd","acdb") &#124; fields agent_hostname, agent_ip_addresses,<br>            agent_id, action_process_image_sha256, action_process_image_name,<br>            action_process_image_path, action_process_instance_id, action_process_causality_id,<br>            action_process_signature_vendor, action_process_signature_product,<br>            action_process_image_command_line, actor_process_image_name, actor_process_image_path,<br>            actor_process_instance_id, actor_process_causality_id &#124; limit 200 | 376699223: 0.0013455555555555556 | 999.9782130555556 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action Process Causality Id|Action Process Image Command Line|Action Process Image Name|Action Process Image Path|Action Process Image Sha256|Action Process Instance Id|Action Process Signature Product|Action Process Signature Vendor|Actor Process Causality Id|Actor Process Image Name|Actor Process Image Path|Actor Process Instance Id|Agent Hostname|Agent Id|Agent Ip Addresses|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-01T12:39:04.000Z | PANW | test1 | C:\Windows\test1\test1.exe | test1.exe | C:\Windows\test1\test1.exe | test1 Action Process Image Sha256 | test1_id | Microsoft Windows | Microsoft Corporation | test1 ID | test.exe | C:\Windows\test.exe | ID | WIN10X64 | Agent ID | IP | 2021-08-01T12:43:59.000Z |
>| XDR agent | 2021-07-29T13:22:32.000Z | PANW | test2 | C:\Windows\test2\test2.exe  | test2.exe | C:\Windows\test2\test2.exe | test2 Action Process Image Sha256 | test2_id | Microsoft Windows | Microsoft Corporation | test2 ID | test.exe | C:\Windows\test.exe | ID | WIN10X64 | Agent ID | IP | 2021-07-29T13:26:32.000Z |
>| XDR agent | 2021-07-29T13:22:28.000Z | PANW | test3 | C:\Windows\test3\test3.exe  | test3.exe | C:\Windows\test3\test3.exe | test3 Action Process Image Sha256 | test3_id | Microsoft Windows | Microsoft Corporation | test3 ID | test.exe | C:\Windows\test.exe | ID | WIN10X64 | Agent ID | IP | 2021-07-29T13:26:32.000Z |



### xdr-xql-dll-module-query
***
Query DLL module events by the SHA256 DLL.


#### Base Command

`xdr-xql-dll-module-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| loaded_module_sha256 | SHA256 DLL module to search on the XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.DllModule.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.DllModule.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.DllModule.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.DllModule.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.DllModule.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.DllModule.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.DllModule.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.DllModule.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.DllModule.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.DllModule.results.actor_effective_username | String | Parent user name. | 
| PaloAltoNetworksXQL.DllModule.results.action_module_sha256 | String | Action SHA256 module. | 
| PaloAltoNetworksXQL.DllModule.results.action_module_path | String | Action module path. | 
| PaloAltoNetworksXQL.DllModule.results.action_module_file_info | String | Action module file information. | 
| PaloAltoNetworksXQL.DllModule.results.action_module_file_create_time | String | Action module file create time. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_command_line | String | Command line arguments of the initiator. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.DllModule.results.actor_process_causality_id | String | Initiator causality ID. | 
| PaloAltoNetworksXQL.DllModule.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.DllModule.results._time | String | Result time. | 
| PaloAltoNetworksXQL.DllModule.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.DllModule.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-dll-module-query loaded_module_sha256=1234,2345 endpoint_id=test1,test2```

#### Human Readable Output
### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|---|
>| 1234_inv | 3 | dataset = xdr_data &#124; filter agent_id in ("test1","test2")<br>           and event_type = LOAD_IMAGE and action_module_sha256 in ("1234","2345")&#124;<br>           fields agent_hostname, agent_ip_addresses, agent_id, actor_effective_username, action_module_sha256,<br>           action_module_path, action_module_file_info, action_module_file_create_time, actor_process_image_name,<br>           actor_process_image_path, actor_process_command_line, actor_process_image_sha256, actor_process_instance_id,<br>           actor_process_causality_id &#124; limit 200 | 376699223: 0.001661388888888889 | 999.9754347222222 | SUCCESS |
>### Data Results
>|Product|Time|Vendor|Action Module File Create Time|Action Module File Info|Action Module Path|Action Module Sha256|Actor Effective Username|Actor Process Causality Id|Actor Process Command Line|Actor Process Image Name|Actor Process Image Path|Actor Process Image Sha256|Actor Process Instance Id|Agent Hostname|Agent Id|Agent Ip Addresses|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-28T11:52:12.000Z | PANW | 2020-10-14T03:12:11.000Z | {"company":"Test Corporation","description":"" | 1234 | NT AUTHORITY\SYSTEM | id_test | "C:\Program Files (x86)\test1" | test1.exe | "C:\Program Files (x86)\test1" | ID_1 | ID_1 | WIN10X64 | 1234 | IP Addr | 2021-08-28T11:54:02.000Z |
>| XDR agent | 2021-08-28T15:49:52.000Z | PANW | 2021-01-12T21:25:51.000Z | {"company":"Test Corporation","description":"" | 2345 | NT AUTHORITY\SYSTEM | id_test | "C:\Program Files (x86)\test2" | test2.exe | "C:\Program Files (x86)\test2" | ID_2 | ID_2 | WIN10X64 | 1234 | IP Addr | 2021-08-28T15:54:40.000Z |
>| XDR agent | 2021-08-28T22:52:11.000Z | PANW | 2021-01-12T21:25:51.000Z | {"company":"Test Corporation","description":"" | 3456 | NT AUTHORITY\SYSTEM | id_test | "C:\Program Files (x86)\test3" | test3.exe | "C:\Program Files (x86)\test3" | ID_3 | ID_3 | WIN10X64 | 1234 | IP Addr | 2021-08-28T22:55:50.000Z |



### xdr-xql-network-connection-query
***
Query network connections between a source IP, destination IP and port.


#### Base Command

`xdr-xql-network-connection-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| local_ip | Source IP of the network connection query. | Optional | 
| remote_ip | Destination IP of the network connection query. | Required | 
| port | Destination port of the network connection query. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00").The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.NetworkConnection.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.NetworkConnection.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.NetworkConnection.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.NetworkConnection.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.NetworkConnection.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.NetworkConnection.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.NetworkConnection.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.NetworkConnection.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.NetworkConnection.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_effective_username | String | Parent user name. | 
| PaloAltoNetworksXQL.NetworkConnection.results.action_local_ip | String | Local IP address. | 
| PaloAltoNetworksXQL.NetworkConnection.results.action_remote_ip | String | Remote IP address. | 
| PaloAltoNetworksXQL.NetworkConnection.results.action_remote_port | String | Remote port. | 
| PaloAltoNetworksXQL.NetworkConnection.results.dst_action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXQL.NetworkConnection.results.action_country | String | Action country. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_command_line | String | Command line arguments of the initiator. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.NetworkConnection.results.actor_process_causality_id | String | Initiator causality ID. | 
| PaloAltoNetworksXQL.NetworkConnection.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.NetworkConnection.results._time | String | Result time. | 
| PaloAltoNetworksXQL.NetworkConnection.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.NetworkConnection.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-network-connection-query endpoint_id=1234,2345 local_ip=test_ip_1,test_ip_2 remote_ip=test_remote_ip_1,test_remote_ip_2 port=test_port1,test_port2 limit=2```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|---|
>| 2758_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = STORY and<br>           action_local_ip in("test_ip1","test_ip2") and action_remote_ip in("test_remote_ip_1","test_remote_ip2") and<br>           action_remote_port in(test_port_1,test_port_2) &#124; fields agent_hostname, agent_ip_addresses, agent_id,<br>           actor_effective_username, action_local_ip, action_remote_ip, action_remote_port,<br>           dst_action_external_hostname, action_country, actor_process_image_name, actor_process_image_path,<br>           actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id &#124; limit 2 | 376699223: 0.0004875 | 999.9737266666667 | SUCCESS |
>### Data Results
>|Product|Time|Vendor|Action Country|Action Local Ip|Action Remote Ip|Action Remote Port|Actor Effective Username|Actor Process Causality Id|Actor Process Command Line|Actor Process Image Name|Actor Process Image Path|Actor Process Image Sha256|Actor Process Instance Id|Agent Hostname|Agent Id|Agent Ip Addresses|Dst Action External Hostname|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P1 | 2021-08-28T12:08:23.000Z | PANW | UNKNOWN | Action Local Ip 1 | Action Remote Ip 1 | port1 |  |  |  |  |  |  |  | WIN10X64 | Agent1 |  |  | 2021-08-28T12:15:26.000Z |
>| P1 | 2021-08-28T12:05:42.000Z | PANW | UNKNOWN | Action Local Ip 2 | Action Remote Ip 2 | port2 |  |  |  |  |  |  |  | WIN10X64 | Agent2 |  |  | 2021-08-28T12:10:23.000Z |



### xdr-xql-registry-query
***
Query windows registry by registry key name.


#### Base Command

`xdr-xql-registry-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| reg_key_name | Registry key name to search (for example: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Drivers\Version-3\Remote Desktop Easy Print). | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.Registry.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.Registry.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.Registry.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.Registry.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.Registry.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.Registry.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.Registry.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.Registry.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.Registry.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.Registry.results.agent_os_type | String | Host operating system. | 
| PaloAltoNetworksXQL.Registry.results.agent_os_sub_type | String | Agent operating system subtype. | 
| PaloAltoNetworksXQL.Registry.results.event_type | String | Event type. | 
| PaloAltoNetworksXQL.Registry.results.event_sub_type | String | Event subtype. | 
| PaloAltoNetworksXQL.Registry.results.action_registry_key_name | String | Registry key name. | 
| PaloAltoNetworksXQL.Registry.results.action_registry_value_name | String | Registry value name. | 
| PaloAltoNetworksXQL.Registry.results.action_registry_data | String | Registry data. | 
| PaloAltoNetworksXQL.Registry.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.Registry.results._time | String | Result time. | 
| PaloAltoNetworksXQL.Registry.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.Registry.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-registry-query endpoint_id=1234,2345 reg_key_name=<reg_key_name> limit=2  time_frame="1 month"```

#### Human Readable Output

>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 2767_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = REGISTRY and<br>           action_registry_key_name in ("reg_key_name") &#124; fields agent_hostname, agent_id, agent_ip_addresses,<br>           agent_os_type, agent_os_sub_type, event_type, event_sub_type, action_registry_key_name,<br>           action_registry_value_name, action_registry_data &#124; limit 2 | 376699223: 0.0012475 | 999.9699388888889 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action Registry Data|Action Registry Key Name|Action Registry Value Name|Agent Hostname|Agent Id|Agent Ip Addresses|Agent Os Sub Type|Agent Os Type|Event Sub Type|Event Type|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-04T06:27:44.000Z | PANW | Action Registry Data | Action Registry Data |  | WIN10X64 | ID | IP | Windows 10 | AGENT_OS_WINDOWS | REGISTRY_SET_VALUE | REGISTRY | 2021-08-04T06:30:22.000Z |
>| XDR agent | 2021-08-04T06:27:44.000Z | PANW | Action Registry Data | Action Registry Data |  | WIN10X64 | ID | IP | Windows 10 | AGENT_OS_WINDOWS | REGISTRY_SET_VALUE | REGISTRY | 2021-08-04T06:30:22.000Z |


### xdr-xql-event-log-query
***
Query event logs by event ID.


#### Base Command

`xdr-xql-event-log-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| event_id | Event log ID to search. - Windows: Event ID of the event-log - Linux: For action_evtlog_source = AuthLog, one of the following: 0 = Unknown 1 = Successful Login 2 = Failed Login 3 = Failed Password (Same as failed login, but should include a username) 4 = Logout. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.EventLog.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.EventLog.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.EventLog.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.EventLog.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.EventLog.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.EventLog.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.EventLog.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.EventLog.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.EventLog.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.EventLog.results.agent_os_type | String | Host operating system. | 
| PaloAltoNetworksXQL.EventLog.results.agent_os_sub_type | String | Agent operating system subtype. | 
| PaloAltoNetworksXQL.EventLog.results.action_evtlog_event_id | String | Event log ID. | 
| PaloAltoNetworksXQL.EventLog.results.event_type | String | Event type. | 
| PaloAltoNetworksXQL.EventLog.results.event_sub_type | String | Event subtype. | 
| PaloAltoNetworksXQL.EventLog.results.action_evtlog_message | String | Event log message. | 
| PaloAltoNetworksXQL.EventLog.results.action_evtlog_provider_name | String | Event log provider name. | 
| PaloAltoNetworksXQL.EventLog.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.EventLog.results._time | String | Result time. | 
| PaloAltoNetworksXQL.EventLog.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.EventLog.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-event-log-query endpoint_id=1234,2345 event_id=4444,5555 limit=2```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|---|
>| 2773_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = EVENT_LOG and<br>           action_evtlog_event_id in (4444,5555) &#124; fields agent_hostname, agent_id, agent_ip_addresses,<br>           agent_os_type, agent_os_sub_type, action_evtlog_event_id, event_type, event_sub_type,<br>           action_evtlog_message, action_evtlog_provider_name &#124; limit 2 | 376699223: 0.0009633333333333333 | 999.9677783333333 | SUCCESS |
>### Data Results
>|Product|Time|Vendor|Action Evtlog Event Id|Action Evtlog Message|Action Evtlog Provider Name|Agent Hostname|Agent Id|Agent Ip Addresses|Agent Os Sub Type|Agent Os Type|Event Sub Type|Event Type|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-28T12:31:24.000Z | PANW | 4444 | Message  | Microsoft-Windows-Security-Auditing | DESKTOP-11 | ID | IP | Windows 10 | AGENT_OS_WINDOWS | EVENT_LOG_AGENT_EVENT_LOG | EVENT_LOG | 2021-08-28T12:36:21.000Z |
>| XDR agent | 2021-08-28T12:31:24.000Z | PANW | 5555 | Message  | Microsoft-Windows-Security-Auditing | DESKTOP-22 | ID | IP | Windows 10 | AGENT_OS_WINDOWS | EVENT_LOG_AGENT_EVENT_LOG | EVENT_LOG | 2021-08-28T12:36:21.000Z |


### xdr-xql-dns-query
***
Query by DNS query or domain name.


#### Base Command

`xdr-xql-dns-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| external_domain | Query by external domain name. | Optional | 
| dns_query | Query by DNS query. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.DNS.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.DNS.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.DNS.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.DNS.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.DNS.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.DNS.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.DNS.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.DNS.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.DNS.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.DNS.results.agent_os_type | String | Host operating system. | 
| PaloAltoNetworksXQL.DNS.results.agent_os_sub_type | String | Agent operating system subtype. | 
| PaloAltoNetworksXQL.DNS.results.action_local_ip | String | Local IP address. | 
| PaloAltoNetworksXQL.DNS.results.action_remote_ip | String | Remote IP address. | 
| PaloAltoNetworksXQL.DNS.results.action_remote_port | String | Remote port. | 
| PaloAltoNetworksXQL.DNS.results.dst_action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXQL.DNS.results.dns_query_name | String | DNS query name. | 
| PaloAltoNetworksXQL.DNS.results.action_app_id_transitions | String | List of application IDs action. Actual activities that took place and recorded by the agent | 
| PaloAltoNetworksXQL.DNS.results.action_total_download | String | Total downloads. | 
| PaloAltoNetworksXQL.DNS.results.action_total_upload | String | Total uploads. | 
| PaloAltoNetworksXQL.DNS.results.action_country | String | Action country. | 
| PaloAltoNetworksXQL.DNS.results.action_as_data | String | The action as data. | 
| PaloAltoNetworksXQL.DNS.results.os_actor_process_image_path | String | Operating system parent path. | 
| PaloAltoNetworksXQL.DNS.results.os_actor_process_command_line | String | Command line arguments of the operating system parent. | 
| PaloAltoNetworksXQL.DNS.results.os_actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.DNS.results.os_actor_process_causality_id | String | Initiator causality ID. | 
| PaloAltoNetworksXQL.DNS.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.DNS.results._time | String | Result time. | 
| PaloAltoNetworksXQL.DNS.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.DNS.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-dns-query endpoint_id=1234,2345 external_domain=<external_domain> limit=2```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|
>|---|---|---|---|---|---|
>| 2782_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = STORY and<br>           dst_action_external_hostname in ("<external_domain>") or dns_query_name in ("*")<br>           &#124; fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type, agent_os_sub_type, action_local_ip,<br>           action_remote_ip, action_remote_port, dst_action_external_hostname, dns_query_name, action_app_id_transitions,<br>           action_total_download, action_total_upload, action_country, action_as_data, os_actor_process_image_path,<br>           os_actor_process_command_line, os_actor_process_instance_id, os_actor_process_causality_id &#124; limit 2 | 376699223: 0.0009897222222222221 | 999.9651905555555 | SUCCESS |
>### Data Results
>|Product|Time|Vendor|Action App Id Transitions|Action As Data|Action Country|Action Local Ip|Action Remote Ip|Action Remote Port|Action Total Download|Action Total Upload|Agent Hostname|Agent Id|Agent Ip Addresses|Agent Os Sub Type|Agent Os Type|Dns Query Name|Dst Action External Hostname|Insert Timestamp|Os Actor Process Causality Id|Os Actor Process Command Line|Os Actor Process Image Path|Os Actor Process Instance Id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P1 | 2021-08-29T00:01:18.000Z | PANW | ip,<br>tcp |  | UNKNOWN | LOCAL_IP | REMOTE_IP | 443 | 3101 | 1413 | DESKTOP | ID | IP | Windows 10 | AGENT_OS_WINDOWS |  | array812.prod.do.dsp.mp.microsoft.com | 2021-08-29T00:07:38.000Z | ID_1 |  |  |
>| P1 | 2021-08-29T00:02:06.000Z | PANW | ip,<br>tcp |  | UNKNOWN | LOCAL_IP | REMOTE_IP | 443 | 4813 | 16311 | DESKTOP | ID | IP | Windows 10 | AGENT_OS_WINDOWS |  | us-v20.events.data.microsoft.com | 2021-08-29T00:07:38.000Z | ID_2 |  |  |



### xdr-xql-file-dropper-query
***
Search for the process that wrote the given file, by its SHA256 or file path.


#### Base Command

`xdr-xql-file-dropper-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| file_sha256 | SHA256 file to search on the XDR dataset. | Optional | 
| file_path | File path to search on the XDR dataset. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.FileDropper.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.FileDropper.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.FileDropper.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.FileDropper.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.FileDropper.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.FileDropper.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.FileDropper.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.FileDropper.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.FileDropper.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.FileDropper.results.action_file_sha256 | String | SHA256 hash value of the file. | 
| PaloAltoNetworksXQL.FileDropper.results.action_file_path | String | File path of the action. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_command_line | String | Command line arguments of the initiator. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_signature_vendor | String | Initiator signer. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_signature_product | String | Initiator product. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.FileDropper.results.actor_primary_normalized_user | String | Normalized user. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_process_image_path | String | Operating system parent path. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_process_command_line | String | Command line arguments of the operating system parent. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_process_signature_vendor | String | Operating system parent signer. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_process_signature_product | String | Operating system parent signer product. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_process_image_sha256 | String | The SHA256 value of the operating system parent. | 
| PaloAltoNetworksXQL.FileDropper.results.os_actor_effective_username | String | Operating system parent user name. | 
| PaloAltoNetworksXQL.FileDropper.results.causality_actor_remote_host | String | Remote host. | 
| PaloAltoNetworksXQL.FileDropper.results.causality_actor_remote_ip | String | remote IP address. | 
| PaloAltoNetworksXQL.FileDropper.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.FileDropper.results._time | String | Result time. | 
| PaloAltoNetworksXQL.FileDropper.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.FileDropper.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-file-dropper-query endpoint_id=1234,2345 file_path=<file_path> file_sha256=<file_SHA> limit=2 time_frame="1 month"```

#### Human Readable Output

>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 2788_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = FILE and<br>           event_sub_type in (FILE_WRITE, FILE_RENAME) and action_file_path in ("<file_path>") or<br>           action_file_sha256 in ("<file_SHA>") &#124; fields agent_hostname, agent_ip_addresses, agent_id,<br>           action_file_sha256, action_file_path, actor_process_image_name, actor_process_image_path,<br>           actor_process_image_path, actor_process_command_line, actor_process_signature_vendor,<br>           actor_process_signature_product, actor_process_image_sha256, actor_primary_normalized_user,<br>           os_actor_process_image_path, os_actor_process_command_line, os_actor_process_signature_vendor,<br>           os_actor_process_signature_product, os_actor_process_image_sha256, os_actor_effective_username,<br>           causality_actor_remote_host,causality_actor_remote_ip &#124; limit 2 | 376699223: 0.0014269444444444444 | 999.9627805555556 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action File Path|Action File Sha256|Actor Primary Normalized User|Actor Process Command Line|Actor Process Image Name|Actor Process Image Path|Actor Process Image Sha256|Actor Process Signature Product|Actor Process Signature Vendor|Agent Hostname|Agent Id|Agent Ip Addresses|Causality Actor Remote Host|Causality Actor Remote Ip|Insert Timestamp|Os Actor Effective Username|Os Actor Process Command Line|Os Actor Process Image Path|Os Actor Process Image Sha256|Os Actor Process Signature Product|Os Actor Process Signature Vendor|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-04T10:57:09.000Z | PANW | Path1 |  |  |  |  |  | X Corporation | WIN10X64 | ID | IP |  |  | 2021-08-04T11:01:08.000Z |  |  |  | ID | X Corporation | X Corporation |



### xdr-xql-process-instance-network-activity-query
***
Search for network connection created by a given process instance ID.


#### Base Command

`xdr-xql-process-instance-network-activity-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| process_instance_id | Process instance ID to search on the XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_local_ip | String | Local IP address. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_remote_ip | String | Remote IP address. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_remote_port | String | Remote port. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.dst_action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.dns_query_name | String | DNS query name. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_app_id_transitions | String | List of application IDs action. Actual activities that took place and recorded by the agent. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_total_download | String | Total downloads. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_total_upload | String | Total uploads. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_country | String | Action country. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.action_as_data | String | The action as data. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_signature_vendor | String | Initiator signer. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_signature_product | String | Initiator product. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_causality_id | String | Causality identifier (CID). | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_image_command_line | String | Image command line. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results._time | String | Result time. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.ProcessInstanceNetworkActivity.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-process-instance-network-activity-query endpoint_id=1234,2345 process_instance_id=<process_instance_id> limit=2 time_frame="1 month"```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 2791_inv | 2 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = NETWORK and<br>           actor_process_instance_id in ("<process_instance_id>") &#124; fields agent_hostname, agent_ip_addresses,<br>           agent_id, action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname,<br>           dns_query_name, action_app_id_transitions, action_total_download, action_total_upload, action_country,<br>           action_as_data, actor_process_image_sha256, actor_process_image_name , actor_process_image_path,<br>           actor_process_signature_vendor, actor_process_signature_product, actor_causality_id,<br>           actor_process_image_command_line, actor_process_instance_id &#124; limit 2 | 376699223: 0.0008680555555555555 | 999.9619125 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action App Id Transitions|Action As Data|Action Country|Action Local Ip|Action Remote Ip|Action Remote Port|Action Total Download|Action Total Upload|Actor Causality Id|Actor Process Image Command Line|Actor Process Image Name|Actor Process Image Path|Actor Process Image Sha256|Actor Process Instance Id|Actor Process Signature Product|Actor Process Signature Vendor|Agent Hostname|Agent Id|Agent Ip Addresses|Dns Query Name|Dst Action External Hostname|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-08-11T06:08:47.000Z | PANW |  |  | UNITED_KINGDOM | LOCAL_IP | REMOTE_IP | 443 |  |  | ID |  | x.exe |  |  |  |  Windows Publisher | X Corporation | WIN10X64 |  |  |  |  | 2021-08-11T06:09:34.000Z |


### xdr-xql-process-causality-network-activity-query
***
Search for network connection created by a given process causality ID.


#### Base Command

`xdr-xql-process-causality-network-activity-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| process_causality_id | Process causality ID to search on the XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date or range format (for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 +02:00 and between 2021-02-01 12:34:56 +02:00"). The default is the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=5000, 5,000 results are returned.<br/>If limit=null or empty (default) up to 100 results are returned. . Default is 100. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter a multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| query_name | The name of the query. | Required |
| parse_result_file_to_context | If set to 'true' and the query returns more than 1000 results, it will be extracted as JSON data to context instead of being returned as a .gz file. If set to 'false' and the query returns more than 1000 results, it will return the .gz file without extracting the results to context. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.query_name | String | The given name of the query. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The execution_id value can be passed to the xdr-xql-get-query-results command. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS means that at least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.query_cost | Unknown | Floating number representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.remaining_quota | Number | Floating number representing the number of query units available for you to use. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.agent_hostname | String | The agent host name. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.agent_ip_addresses | String | The agent IP addresses. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.agent_id | String | Endpoint ID. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_local_ip | String | Local IP address. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_remote_ip | String | Remote IP address. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_remote_port | String | Remote port. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.dst_action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.dns_query_name | String | DNS query name. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_app_id_transitions | String | List of application IDs action. Actual activities that took place and recorded by the agent. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_total_download | String | Total downloads. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_total_upload | String | Total uploads. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_country | String | Action country. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.action_as_data | String | The action as data. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_image_sha256 | String | The SHA256 value of the initiator. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_image_name | String | The name of the process that initiated the activity. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_image_path | String | Path of the initiating process. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_signature_vendor | String | Initiator signer. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_signature_product | String | Initiator product. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_causality_id | String | Causality identifier (CID). | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_image_command_line | String | Image command line. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.actor_process_instance_id | String | Initiator instance ID. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results._vendor | String | The result vendor. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results._time | String | Result time. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results.insert_timestamp | String | Result insert timestamp. | 
| PaloAltoNetworksXQL.ProcessCausalityNetworkActivity.results._product | String | The result product. | 


#### Command Example
```!xdr-xql-process-causality-network-activity-query endpoint_id=1234,2345  process_causality_id=<process_causality_id> limit=1 time_frame="1 month"```

#### Human Readable Output
>### General Results
>|Execution Id|Number Of Results|Query|Query Cost|Remaining Quota|Status|Time Frame|
>|---|---|---|---|---|---|---|
>| 2794_inv | 1 | dataset = xdr_data &#124; filter agent_id in ("1234","2345") and event_type = NETWORK and<br>           actor_process_causality_id in ("<process_causality_id>") &#124; fields agent_hostname, agent_ip_addresses,<br>           agent_id, action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname,<br>           dns_query_name, action_app_id_transitions, action_total_download, action_total_upload, action_country,<br>           action_as_data, actor_process_image_sha256, actor_process_image_name , actor_process_image_path,<br>           actor_process_signature_vendor, actor_process_signature_product, actor_causality_id,<br>           actor_process_image_command_line, actor_process_instance_id &#124; limit 1 | 376699223: 0.0007380555555555556 | 999.9611744444444 | SUCCESS | 1 month |
>### Data Results
>|Product|Time|Vendor|Action App Id Transitions|Action As Data|Action Country|Action Local Ip|Action Remote Ip|Action Remote Port|Action Total Download|Action Total Upload|Actor Causality Id|Actor Process Image Command Line|Actor Process Image Name|Actor Process Image Path|Actor Process Image Sha256|Actor Process Instance Id|Actor Process Signature Product|Actor Process Signature Vendor|Agent Hostname|Agent Id|Agent Ip Addresses|Dns Query Name|Dst Action External Hostname|Insert Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| XDR agent | 2021-07-31T01:47:07.000Z | PANW |  |  | ISRAEL | LOCAL_IP | REMOTE_IP | 80 |  |  |  |  | x.exe |  |  |  |  Windows Publisher | X Corporation | WIN10X64 |  | IP |  |  | 2021-07-31T01:48:03.000Z |