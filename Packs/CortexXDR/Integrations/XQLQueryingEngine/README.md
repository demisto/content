Cortex XDR - XQL query engine enables you to run XQL queries on your data sources using a series of APIs.
This integration was integrated and tested with version 3.0 of Cortex XDR - XQL query engine

## Configure Cortex XDR - XQL query engine on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex XDR - XQL query engine.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | API Key ID | The API Key ID to use for connection | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xdr-xql-generic-query
***
Execute an XQL query and retrieve results of an executed XQL query API.


#### Base Command

`xdr-xql-generic-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | String of the XQL query. By default up to 200 results are returned, in order to get more results, enter a custom limit in the query. | Required | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 
| interval_in_seconds | Interval in seconds between each poll, (default is 10 seconds). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.GenericQuery.execution_id | String | An integer representing a unique ID of a successful XQL query execution. The value is used to call the Get XQL Query Results API. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.query_cost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.remaining_quota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._time | Date |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.mac | Unknown |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_effective_username | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_signature_status | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_signature_status | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_type | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.action_remote_process_image_sha256 | Unknown |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._product | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_install_type | String |  | 


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
| PaloAltoNetworksXDR.XQL.Quota.license_quota | Number | Amount of daily quota allocated to your tenant based on your license type and size. | 
| PaloAltoNetworksXDR.XQL.Quota.additional_purchased_quota | Number | Amount of query quota purchased. | 
| PaloAltoNetworksXDR.XQL.Quota.used_quota | Number | Amount of query quota used over the past 24 hours. | 


#### Command Example
```!xdr-xql-get-quota```

#### Context Example
```json
{
    "PaloAltoNetworksXDR": {
        "XQL": {
            "Quota": {
                "additional_purchased_quota": 0,
                "license_quota": 1000,
                "used_quota": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Quota Results
>|Additional Purchased Quota|License Quota|Used Quota|
>|---|---|---|
>| 0 | 1000 | 0.0 |


### xdr-xql-get-query-results
***
Retrieve results of an executed XQL query API.


#### Base Command

`xdr-xql-get-query-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | Integer representing the unique execution ID generated by the response to Start an XQL Query API. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.GenericQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._time | Date |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.mac | Unknown |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_effective_username | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.actor_process_signature_status | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_process_signature_status | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.causality_actor_type | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.os_actor_process_os_pid | Number |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.action_remote_process_image_sha256 | Unknown |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results._product | String |  | 
| PaloAltoNetworksXDR.XQL.GenericQuery.results.agent_install_type | String |  | 


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
Query file events by file sha256.


#### Base Command

`xdr-xql-file-event-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| file_sha256 | File sha256 to run the query on. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_file_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_file_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_file_create_time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
Query process events by process sha256.


#### Base Command

`xdr-xql-process-event-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| process_sha256 | Process sha256 the search on XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_signature_product | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_process_image_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
Query DLL module events by DLL sha256.


#### Base Command

`xdr-xql-dll-module-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| loaded_module_sha256 | DLL Module sha256 the search on XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_effective_username | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_module_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_module_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_module_file_info | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_module_file_create_time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| local_ip | Source ip of the network connection query. | Optional | 
| remote_ip | Destination ip of the network connection query. | Required | 
| port | Destination port of the network connection query. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_effective_username | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_local_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_port | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dst_action_external_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_country | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_sub_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.event_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.event_sub_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_registry_key_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_registry_value_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_registry_data | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| event_id | event log ID to search. - Windows: Event ID of the event-log - Linux: For action_evtlog_source = AuthLog, one of the following: 0 = Unknown 1 = Successful Login 2 = Failed Login 3 = Failed Password (Same as failed login, but should include a username) 4 = Logout. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_sub_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_evtlog_event_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.event_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.event_sub_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_evtlog_message | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_evtlog_provider_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| external_domain | Query by extrenal domain name. | Optional | 
| dns_query | Query by dns query. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_os_sub_type | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_local_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_port | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dst_action_external_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dns_query_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_app_id_transitions | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_download | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_upload | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_country | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_as_data | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
Search for the process who wrote the given file, by its sha256 or file path.


#### Base Command

`xdr-xql-file-dropper-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | XDR endpoint ID to run the query on. | Optional | 
| file_sha256 | File sha256 to search on XDR dataset. | Optional | 
| file_path | File path to search on XDR dataset. | Optional | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_file_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_file_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_product | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_primary_normalized_user | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_signature_product | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.os_actor_effective_username | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.causality_actor_remote_host | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.causality_actor_remote_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| process_instance_id | Process insatce ID to search on XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_local_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_port | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dst_action_external_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dns_query_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_app_id_transitions | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_download | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_upload | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_country | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_as_data | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_product | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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
| process_causality_id | Process causality ID to search on XDR dataset. | Required | 
| extra_fields | Extra fields to add to the query results. | Optional | 
| time_frame | Time in relative date format (for example: "1 day", "3 weeks ago"). Cortex XDR calls by default the last 24 hours. | Optional | 
| limit | Integer representing the maximum number of results to return. For example:<br/>If limit = 100 and the query produced 1,000 results, only the first 100 results will be returned.<br/>If limit = 100 and the query produced 50 results, only 50 results will be returned.<br/>        If limit=null or empty (default) up to 200 results are returned. For example, if limit=5000, only 5,000 results are returned. Default is 200. | Optional | 
| tenant_id | List of strings used for running APIs on local and Managed Security tenants. Valid values:<br/><br/>For single tenant (local tenant) query, enter a single-item list with your tenant_id. Additional valid values are, empty list ([]) or null (default).<br/><br/>For multi-tenant investigations (Managed Security parent who investigate children and\or local), enter multi-item list with the required tenant_id. List of IDs can contain the parent, children, or both parent and children. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.XQL.BuiltInQuery.Status | String | String representing the status of the API call; SUCCESS, FAIL, or PENDING.
For multi-tenant queries, PARTIAL_SUCCESS—At least one tenant failed to execute the query. Only partial results are available. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.number_of_results | Number | Integer representing the number of results returned. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.QueryCost | Unknown | Float representing the number of query units collected for this API. For example, \{"local_tenant_id": 0.01\}.
For multi-tenant queries, the field displays a value per child tenant. For example, \{"tenant_id_1": 0.01, "tenant_id_2": 2.3\}. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.RemainingQuota | Number | Float representing the number of query units available for you to use. | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_ip_addresses | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.agent_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_local_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_ip | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_remote_port | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dst_action_external_hostname | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.dns_query_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_app_id_transitions | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_download | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_total_upload | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_country | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.action_as_data | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_sha256 | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_name | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_path | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_signature_product | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_causality_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_image_command_line | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.actor_process_instance_id | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._vendor | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._time | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results.insert_timestamp | String |  | 
| PaloAltoNetworksXDR.XQL.BuiltInQuery.results._product | String |  | 


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


