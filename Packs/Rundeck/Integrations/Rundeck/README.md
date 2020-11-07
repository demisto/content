Rundeck is runbook automation for incident management, business continuity, and self-service operations.
This integration was integrated and tested with version xx of Rundeck
## Configure Rundeck on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rundeck.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://soar.monstersofhack.com\) | True |
| token | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| project_name | Project Name | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rundeck-projects-list
***
Gets all existing projects on the server.


#### Base Command

`rundeck-projects-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Projects.name | String | Name of an existing project | 
| Rundeck.Projects.description | String | Description of an existing project | 


#### Command Example
!rundeck-projects-list

#### Human Readable Output
### Projects List:
|Name|Description|
|---|---|
| Demisto | Demisto Test |



### rundeck-jobs-list
***
Gets a list of all the jobs exist in a project


#### Base Command

`rundeck-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_list | A list of job IDs. | Optional | 
| group_path | A path for a specific group to include all jobs within that group path. | Optional | 
| job_filter | Specify a filter for a job Name, apply this command to any job name that contains this value.<br/>Example: to find 'testJob' you can pass 'test'. | Optional | 
| job_exact_filter | Specify an exact job name to match.<br/>Example: to find 'testJob' you should pass 'testJob'. | Optional | 
| group_path_exact | Specify an exact group path to match. if not specified, default is: "*". | Optional | 
| scheduled_filter | 'true' to return only scheduled or 'false' for only not scheduled jobs. | Optional | 
| server_node_uuid_filter | A UUID for a selected server to return all jobs related to it. | Optional | 
| max_results | maximum number of results to retun. The Default is 100. | Optional | 
| project_name | The name of the project to list its jobs | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Jobs.id | String | UUID of the job | 
| Rundeck.Jobs.name | String | Name of the job. | 
| Rundeck.Jobs.group | String | Group of the job. | 
| Rundeck.Jobs.project | String | Project of the job. | 


#### Command Example
!rundeck-jobs-list scheduled_filter=false id_list={first_id},{second_id}

#### Human Readable Output
### Jobs List:
|Id|Schedule Enabled|Scheduled|Enabled|Group|Description|Project|Name|
|---|---|---|---|---|---|---|---|
| 123 | true | false | true |  | just a sample job | Demisto | Arseny\'s Job |



### rundeck-job-execute
***
Executes a new job


#### Base Command

`rundeck-job-execute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Id for a job to execute | Required | 
| arg_string | Execution arguments for the selected job. for example: -opt1 value1 -opt2 value2 | Optional | 
| log_level | specifying the log level to use | Optional | 
| as_user | Username for identifying the user who ran the job. | Optional | 
| node_filter | node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntex checking:<br/>attribute: /regex/<br/><br/>for more information: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
| run_at_time | A time to run the job.<br/>Can pass either run_at_time_raw, run_at_time or neither.<br/>when passing both run_at_time_raw and run_at_time, the default is run_at_time. | Optional | 
| options | Options for running the job.<br/>For example, if you have a 'foo' and 'bar' options set for a job, you can pass values to them using the next syntax: 'foo=someValue,bar=someValue' | Optional | 
| run_at_time_raw | A time to run the job in a ISO-8601 date and time stamp with timezone, with optional milliseconds. e.g. 2019-10-12T12:20:55-0800 or 2019-10-12T12:20:55.123-0800.<br/><br/>Can pass either run_at_time_raw, run_at_time or neither.<br/>when passing both run_at_time_raw and run_at_time, the default is run_at_time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutedJobs.id | Number | Id of the execution. | 
| Rundeck.ExecutedJobs.status | String | Status of the executed job. | 
| Rundeck.ExecutedJobs.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.executionType | String | Type of execution | 
| Rundeck.ExecutedJobs.user | String | User executed the job. | 
| Rundeck.ExecutedJobs.datestarted.unixtime | Number | Date of the job execution in unix time. | 
| Rundeck.ExecutedJobs.datestarted.date | Date | Date of the job execution. | 
| Rundeck.ExecutedJobs.job.id | String | Id of the executed job. | 
| Rundeck.ExecutedJobs.job.averageDuration | Number | Average time for the job's execution | 
| Rundeck.ExecutedJobs.job.name | String | Name of the job | 
| Rundeck.ExecutedJobs.job.group | String | The job's group. | 
| Rundeck.ExecutedJobs.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.job.description | String | Description of the executed job. | 
| Rundeck.ExecutedJobs.job.options | String | Options for the job's execution. | 
| Rundeck.ExecutedJobs.description | String | Description for the execution. | 
| Rundeck.ExecutedJobs.argstring | String | Arguments for the job's execution. | 


#### Command Example
!rundeck-job-execute job_id={job_id} arg_string="-arg1 value1" as_user=galb log_level=ERROR

#### Human Readable Output
### Execute Job:
|Id|Status|Project|Execution Type|User|Datestarted|Job|Description|Argstring|
|---|---|---|---|---|---|---|---|---|
| 194 | running | Demisto | user | Galb | unixtime: 123 date: 123 | id: 123 averageDuration: 463 name:  Test Job group:  project: Demisto description: just a sample job options: {"foo": "0"} | 123 | -foo 0 |



### rundeck-job-retry
***
Retry running a failed execution


#### Base Command

`rundeck-job-retry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| arg_string | Execution arguments for the selected job. for example: -opt1 value1 -opt2 value2 | Optional | 
| execution_id | Id of the execution you want to retry execute. | Required | 
| log_level | specifying the log level to use | Optional | 
| as_user | Username for identifying the user who ran the job. | Optional | 
| failed_nodes | 'true' for run all nodes and 'false' for running only failed nodes | Optional | 
| options | Options for the job's execution. For example: 'foo=someValue,bar=someValue' | Optional | 
| job_id | Id for a job to execute | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutedJobs.id | Number | Id of the execution. | 
| Rundeck.ExecutedJobs.status | String | Status of the executed job. | 
| Rundeck.ExecutedJobs.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.executionType | String | Type of execution | 
| Rundeck.ExecutedJobs.user | String | User executed the job. | 
| Rundeck.ExecutedJobs.datestarted.unixtime | Number | Date of the job execution in unix time. | 
| Rundeck.ExecutedJobs.datestarted.date | Date | Date of the job execution. | 
| Rundeck.ExecutedJobs.job.id | String | Id of the executed job. | 
| Rundeck.ExecutedJobs.job.averageDuration | Number | Average time for the job's execution | 
| Rundeck.ExecutedJobs.job.name | String | Name of the job | 
| Rundeck.ExecutedJobs.job.group | String | The job's group. | 
| Rundeck.ExecutedJobs.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.job.description | String | Description of the executed job. | 
| Rundeck.ExecutedJobs.job.options | String | Options for the job's execution. | 
| Rundeck.ExecutedJobs.description | String | Description for the execution. | 
| Rundeck.ExecutedJobs.argstring | String | Arguments for the job's execution. | 


#### Command Example
!rundeck-job-retry execution_id=122 job_id={job_id}

#### Human Readable Output
### Execute Job:
|Id|Status|Project|Execution Type|User|Datestarted|Job|Description|Argstring|
|---|---|---|---|---|---|---|---|---|
| 194 | running | Demisto | user | Galb | unixtime: 123 date: 123 | id: 123 averageDuration: 463 name:  Test Job group: project: Demisto description: just a sample job options: {"foo": "0"} | 123 | -foo 0 |



### rundeck-job-executions-query
***
Gets all exections base on job or execution details


#### Base Command

`rundeck-job-executions-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Name of the project to query its executions | Optional | 
| status_filter | Status of the execution | Optional | 
| aborted_by_filter | Username of the person aborted to execution | Optional | 
| user_filter | Username of the person stated the execution | Optional | 
| recent_filter | Specify when the execution has occur. The format is 'XY' when 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year.<br/>Example: 2w returns executions that completed within the last two weeks. | Optional | 
| older_filter | specify executions that completed before the specified relative period of time.<br/>the format is 'XY' when 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year.<br/>Example: 30d returns executions older than 30 days. | Optional | 
| begin | Exact date for the earliest execution completion time. | Optional | 
| end | Exact date for the latest execution completion time. | Optional | 
| adhoc | 'true' for include Adhoc executions. 'false' otherwise. | Optional | 
| job_id_list_filter | List of job IDs to filter by | Optional | 
| exclude_job_id_list_filter | List of job IDs to exclude | Optional | 
| job_list_filter | List of full job group/name to include. | Optional | 
| exclude_job_list_filter | List of full job group/name to exclude. | Optional | 
| group_path | Full or partical group path to include all jobs within that group path. | Optional | 
| group_path_exact | Full group path to include all jobs within that group path. | Optional | 
| exclude_group_path | Full or partical group path to exclude all jobs within that group path. | Optional | 
| exclude_group_path_exact | Full group path to exclude all jobs within that group path. | Optional | 
| job_filter | Filter for a job name. Include any job name that matches this value.<br/>Example: to find 'testJob' you can pass 'test'. | Optional | 
| exclude_job_filter | Filter for the job Name. Exclude any job name that matches this value.<br/>Example: to find 'testJob' you can pass 'test'. | Optional | 
| job_exact_filter | Filter for an exact job name. Include any job name that matches this value.<br/>Example: to find 'testJob' you should pass 'testJob'. | Optional | 
| exclude_job_exact_filter | Filter for an exact job name. Exclude any job name that matches this value.<br/>Example: to find 'testJob' you should pass 'testJob'. | Optional | 
| execution_type_filter | Type of execution. | Optional | 
| max_results | maximum number of results to retun. The Default is 100. | Optional | 
| offset | Offset for first result to include.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutionsQuery.paging.count | Number | Number of results | 
| Rundeck.ExecutionsQuery.paging.total | Number | Number of total executions | 
| Rundeck.ExecutionsQuery.paging.offset | Number | Number of offset for first result to include.  | 
| Rundeck.ExecutionsQuery.paging.max | Number | Maximum number of results to retun | 
| Rundeck.ExecutionsQuery.executions.id | Number | Id of the execution | 
| Rundeck.ExecutionsQuery.executions.status | String | Status of the execution | 
| Rundeck.ExecutionsQuery.executions.project | String | The project name of the execution. | 
| Rundeck.ExecutionsQuery.executions.executionType | String | Type of the execution | 
| Rundeck.ExecutionsQuery.executions.user | String | Username of the person executing the job | 
| Rundeck.ExecutionsQuery.executions.datestarted.unixtime | Number | Date of the job execution in unix time. | 
| Rundeck.ExecutionsQuery.executions.datestarted.date | Date | Date of the job execution. | 
| Rundeck.ExecutionsQuery.executions.dateended.unixtime | Unknown | Date of the end of job execution in unix time. | 
| Rundeck.ExecutionsQuery.executions.dateend.time | Date | Date of the end of job execution. | 
| Rundeck.ExecutionsQuery.executions.job.id | String | Id of the executed job. | 
| Rundeck.ExecutionsQuery.executions.job.averageDuration | Number | Average time for the job's execution | 
| Rundeck.ExecutionsQuery.executions.job.name | String | Name of the job | 
| Rundeck.ExecutionsQuery.executions.job.group | String | The job's group. | 
| Rundeck.ExecutionsQuery.executions.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutionsQuery.executions.job.description | String | Description of the job. | 
| Rundeck.ExecutionsQuery.executions.job.options | String | Options for the job's execution. | 
| Rundeck.ExecutionsQuery.executions.description | String | Description of the execution. | 
| Rundeck.ExecutionsQuery.executions.argstring | String | Arguments for the job's execution. | 
| Rundeck.ExecutionsQuery.executions.failedNodes | String | List of failed nodes | 
| Rundeck.ExecutionsQuery.paging.total | Number | Indicate the total results that returned from the api | 
| Rundeck.ExecutionsQuery.paging.offset | Number | Indicate the 0 indexed offset for the first result to return. | 
| Rundeck.ExecutionsQuery.paging.max | Number | Indicate the maximum number of results to return. If unspecified, all results are returned. | 
| Rundeck.ExecutionsQuery.paging.count | Number | Indicates the number of results that accually retuned, after filter them out using the 'offest' and 'max' parameters. | 


#### Command Example
!rundeck-job-executions-query adhoc=false max_results=3 project_name=Demisto user_filter=galb status_filter=failed

#### Human Readable Output
### Job Execution Query - got total results: 2
|Id|Status|Project|Execution Type|User|Datestarted|Dateended|Job|Description|Argstring|Failed Nodes|
|---|---|---|---|---|---|---|---|---|---|---|
| 195 | failed | Demisto | user | Galb | unixtime: 123 date: 123 | unixtime: 123 date: 123 | id: 123 averageDuration: 463 name:  Test Job group:  project: Demisto description: just a sample job options: {"foo": "0"} | 123 | -foo 0 | localhost |



### rundeck-job-execution-output
***
Gets the metadata associated with workflow step state


#### Base Command

`rundeck-job-execution-output`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| execution_id | Id of the execution | Required | 
| return_full_output | If 'true' output saves in a returned file and not in Demisto context.<br/>If 'false', the number of outputs is limited to 100 and the returned data save in context.<br/>The default is 'false'. | Optional | 
| max_results | maximum number of results to retun. The Default is 100. | Optional | 
| aggregate_log | if 'true', all entries of type 'log' are saved in context under 'listEntry' in  ExecutionsOutput under the execution you selected to run this command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutionsOutput.id | Number | Id of the execution | 
| Rundeck.ExecutionsOutput.offset | String | Byte offset to read from in the file. 0 indicates the beginning. | 
| Rundeck.ExecutionsOutput.completed | Boolean | 'true' if the current log entries or request parameters include all of the available data, 'false' otherwise. | 
| Rundeck.ExecutionsOutput.execCompleted | Boolean | 'true' if execution has finished. 'false' otherwise. | 
| Rundeck.ExecutionsOutput.hasFailedNodes | Boolean | 'true' if there are nodes that failed. 'false' otherwise. | 
| Rundeck.ExecutionsOutput.execState | String | Execution state. can be: 'running','succeeded','failed', or 'aborted'. | 
| Rundeck.ExecutionsOutput.lastModified | String | Millisecond timestamp of the last modification of the log file. | 
| Rundeck.ExecutionsOutput.execDuration | Number | Millisecond duration of the execution | 
| Rundeck.ExecutionsOutput.percentLoaded | Number | Percentage of the output which has been loaded by the parameters | 
| Rundeck.ExecutionsOutput.totalSize | Number | Total bytes available in the output file | 
| Rundeck.ExecutionsOutput.retryBackoff | Number | RetryBackoff number. | 
| Rundeck.ExecutionsOutput.clusterExec | Boolean | 'true' is there was a cluster execution. 'false' otherwise. | 
| Rundeck.ExecutionsOutput.compacted | Boolean | 'true' if compacted form was requested and is used. 'false' otherwise. | 
| Rundeck.ExecutionsOutput.entries.node | String | Node name. | 
| Rundeck.ExecutionsOutput.entries.user | String | User name performed the execution. | 
| Rundeck.ExecutionsOutput.entries.time | String | Time of the output. | 
| Rundeck.ExecutionsOutput.entries.level | String | Log level | 
| Rundeck.ExecutionsOutput.entries.type | String | Output type | 
| Rundeck.ExecutionsOutput.entries.absolutetime | Date | Absolute time of the output. | 
| Rundeck.ExecutionsOutput.entries.log | String | Log message. | 


#### Command Example
!rundeck-job-execution-output execution_id=118 aggregate_log=true

#### Human Readable Output
### Job Execution Output:
|Id|Offset|Completed|Exec Completed|Has Failed Nodes|Exec State|Last Modified|Exec Duration|Percent Loaded|Total Size|Retry Backoff|Cluster Exec|Compacted|Entries|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 69 | 3732 | true | true | true | failed | 123 | 237 | 12 | 3738 | 0 | false | false | {'node': 'localhost', 'step': '1', 'stepctx': '1', 'user': 'admin', 'time': '10:54:52', 'level': 'NORMAL', 'type': 'stepbegin', 'absolute_time': '123', 'log': ''} |
### Job Execution Entries View:
|Log|Node|Step|Stepctx|User|Time|Level|Type|Absolute Time|Log|
|---|---|---|---|---|---|---|---|---|---|
|  | localhost | 1 | 1 | admin | 10:54:52 | NORMAL | stepbegin |  |  |



### rundeck-job-execution-abort
***
Aborts an active execution


#### Base Command

`rundeck-job-execution-abort`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| execution_id | Id of the execution you want to abort. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Aborted.abort.status | String | can be either: 'pending', 'failed' or 'aborted'. | 
| Rundeck.Aborted.abort.reason | String | Reason for the 'status' | 
| Rundeck.Aborted.execution.id | String | Id of the aborted execution. | 
| Rundeck.Aborted.execution.status | String | Execution's status. | 


#### Command Example
!rundeck-job-execution-abort execution_id=65

#### Human Readable Output
### Job Execution Abort:
|Abort|Execution|
|---|---|
| status: failed reason: Job is not running | id: 69 status: failed |



### rundeck-adhoc-command-run
***
Executes shell commands in nodes


#### Base Command

`rundeck-adhoc-command-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Project name to execute the command | Optional | 
| exec_command | Shell command to run | Required | 
| node_thread_count | Threadcount to use | Optional | 
| node_keepgoing | 'true' for continue executing on other nodes after a failure. 'false' otherwise. | Optional | 
| as_user | Username identifying the user who ran the command. | Optional | 
| node_filter | node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntex checking:<br/>attribute: /regex/<br/><br/>for more information: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteCommand.message | String | Message regarding the execution progress. | 
| Rundeck.ExecuteCommand.execution.id | String | Execution id | 


#### Command Example
!rundeck-adhoc-command-run exec_command="echo hello" as_user=adhocTest project_name=Demisto node_keepgoing=true

#### Human Readable Output
### Adhoc Run:
|Message|Execution|
|---|---|
| Immediate execution scheduled (196) | id: 196 |



### rundeck-adhoc-script-run
***
Runs a script from file


#### Base Command

`rundeck-adhoc-script-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Demisto id for the uploaded script file. | Required | 
| project_name | Project name to execute the script. | Optional | 
| arg_string | Arguments to pass to the script when executed. | Optional | 
| node_thread_count | threadcount to use | Optional | 
| node_keepgoing | 'true' for continue executing on other nodes after a failure. 'false' otherwise. | Optional | 
| as_user | Username identifying the user who rans the script. | Optional | 
| node_filter | node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntex checking:<br/>attribute: /regex/<br/><br/>for more information: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
| script_interpreter | Command to use to run the script file | Optional | 
| interpreter_args_quoted | 'true', the script file and arguments will be quoted as the last argument to the script_interpreter. 'false' otherwise. | Optional | 
| file_extension | Extension of the script file | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteScriptFile.message | String | Message regarding the execution progress. | 
| Rundeck.ExecuteScriptFile.execution.id | String | Execution id | 


#### Command Example
!rundeck-adhoc-script-run entry_id=@121 as_user='test'

#### Human Readable Output
### Adhoc Run Script:
|Message|Execution|
|---|---|
| Immediate execution scheduled (196) | id: 196 |



### rundeck-adhoc-script-run-from-url
***
Runs a script from URL


#### Base Command

`rundeck-adhoc-script-run-from-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Project name to execute the script. | Optional | 
| script_url | Url for the script file | Required | 
| node_thread_count | threadcount to use. | Optional | 
| node_keepgoing | 'true' for continue executing on other nodes after a failure. 'false' otherwise. | Optional | 
| as_user | Username identifying the user who rans the script file. | Optional | 
| node_filter | node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntex checking:<br/>attribute: /regex/<br/><br/>for more information: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
| script_interpreter | Command to use to run the script file | Optional | 
| interpreter_args_quoted | 'true', the script file and arguments will be quoted as the last argument to the script_interpreter. 'false' otherwise. | Optional | 
| file_extension | Extension of the script file | Optional | 
| arg_string | Arguments to pass to the script when executed. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
!rundeck-adhoc-script-run-from-url script_url='URL' node_keepgoing=true

#### Human Readable Output
### Adhoc Run Script From Url:
|Message|Execution|
|---|---|
| Immediate execution scheduled (196) | id: 196 |



### rundeck-webhooks-list
***
Gets a list of all existing webhooks


#### Base Command

`rundeck-webhooks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Name of the project to get its webhooks. | Optional | 
| max_results | maximum number of results to retun. The Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Webhooks.id | Number | Id of the webhook. | 
| Rundeck.Webhooks.uuid | String | Uuid of the webhook. | 
| Rundeck.Webhooks.name | String | Name of the webhook. | 
| Rundeck.Webhooks.project | String | Name of the project the webhook relates to. | 
| Rundeck.Webhooks.enabled | String | 'true' if the webhook is enabled. 'false' otherwise. | 
| Rundeck.Webhooks.user | String | User name of the webhook user | 
| Rundeck.Webhooks.creator | String | User name of the webhook creator. | 
| Rundeck.Webhooks.roles | String | Rolers of the webhooks | 
| Rundeck.Webhooks.authToken | String | Auth token of the webhook. | 
| Rundeck.Webhooks.eventPlugin | String | Plug in that is being used. | 
| Rundeck.Webhooks.config.jobId | String | Id of the job related to the webhook | 


#### Command Example
!rundeck-webhooks-list project_name="TEST"

#### Human Readable Output
### Webhooks List:
|Id|Uuid|Name|Project|Enabled|User|Creator|Roles|Auth Token|Event Plugin|Config|
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 123 |  Test hook | Demisto | true | admin | admin | 123 | 123 | webhook-run-job | jobId: 123 argString: 123 |



### rundeck-webhook-event-send
***
Send webhook event


#### Base Command

`rundeck-webhook-event-send`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| auth_token | Auto token of the webhook | Required | 
| options | Data you want to post to the webhook endpoint. example: 'op1=val1,op2=val2'.<br/>can pass either 'options' or 'json'. | Optional | 
| json | Json you want to post to the webhook endpoint.<br/>can pass either 'options' or 'json'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.WebhookEvent.jobId | String | Id of the executed job. | 
| Rundeck.WebhookEvent.executionId | String | Id of the execution. | 


#### Command Example
!rundeck-webhook-event-send json=`{"test":1}` auth_token={auth_id}

#### Human Readable Output
### Webhook event send:
|Job Id|Execution Id|
|---|---|
| 123 | 199 |


