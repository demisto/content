Rundeck is a runbook automation for incident management, business continuity, and self-service operations. The integration enables you to install software on a list of machines or perform a task periodically. Can be used when there is a new attack and you want to perform an update of the software to block the attack.
This integration was integrated and tested with version 24 of Rundeck.
## Configure Rundeck on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rundeck.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://soar.monstersofhack.com\) | True |
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
| Rundeck.Projects.name | String | Name of an existing project. | 
| Rundeck.Projects.description | String | Description of an existing project. | 


#### Command Example
!rundeck-projects-list

#### Human Readable Output
### Projects List:
|Name|Description|
|---|---|
| Demisto | Demisto Test |



### rundeck-jobs-list
***
Gets a list of all the jobs that exist in a project.


#### Base Command

`rundeck-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_list | A comma-separated list of job IDs. | Optional | 
| group_path | A group or partial group path to include all jobs within that group path. | Optional | 
| job_filter | A filter for the job name. Matches any job name that contains this value. For example: To return 'testJob', set this argument to 'test'. | Optional | 
| job_exact_filter | An exact job name to match.For example: To return 'testJob', set this argument to 'testJob'. | Optional | 
| group_path_exact | An exact group path to match. If not specified, default is: "*". | Optional | 
| scheduled_filter | Whether to return only scheduled jobs or only unscheduled jobs. Specify "true" for scheduled jobs only, or "false" for unscheduled jobs only. | Optional | 
| server_node_uuid_filter | A UUID. Used to select scheduled jobs assigned to the server with the given UUID. | Optional | 
| max_results | The maximum number of results to return. Default is 100. | Optional | 
| project_name | The name of the project from which to list its jobs. | Optional | 


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
| 123 | true | false | true |  | just a sample job | Cortex XSOAR | Arseny\'s Job |



### rundeck-job-execute
***
Executes a new job.


#### Base Command

`rundeck-job-execute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | ID of the job to execute | Required | 
| arg_string | Execution arguments for the selected job. For example: -opt1 value1 -opt2 value2 | Optional | 
| log_level | The log level. Possible values are: "DEBUG", "VERBOSE", "INFO", "WARN", and "ERROR". | Optional | 
| as_user | The name of the user who ran the job. | Optional | 
| node_filter | Node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntax checking:<br/>attribute: /regex/<br/><br/>For more information, see: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
| run_at_time | The time to run the job. Possible values are: "1 hour", "1 day", and "1 week".<br/>You can pass either the run_at_time_raw argument, the run_at_time argument, or neither argument.<br/>When passing both the run_at_time_raw and run_at_time arguments, the default is the run_at_time argument. | Optional | 
| options | Options for running the job.<br/>For example, if you have the 'foo' and 'bar' options set for a job, you can pass values to them using the syntax: 'foo=someValue,bar=someValue' | Optional | 
| run_at_time_raw | A time to run the job in an ISO-8601 date and timestamp with the timezone. You can also optionally include milliseconds. For example, 2019-10-12T12:20:55-0800 or 2019-10-12T12:20:55.123-0800.<br/><br/>You can pass either the run_at_time_raw argument, the run_at_time argument, or neither argument.<br/>When passing both the run_at_time_raw and run_at_time arguments, the default is the run_at_time argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutedJobs.id | Number | The ID of the execution. | 
| Rundeck.ExecutedJobs.status | String | The status of the executed job. | 
| Rundeck.ExecutedJobs.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.executionType | String | The type of execution | 
| Rundeck.ExecutedJobs.user | String | The user who executed the job. | 
| Rundeck.ExecutedJobs.datestarted.unixtime | Number | The date of the job execution in Unix time. | 
| Rundeck.ExecutedJobs.datestarted.date | Date | The date of the job execution. | 
| Rundeck.ExecutedJobs.job.id | String | The ID of the executed job. | 
| Rundeck.ExecutedJobs.job.averageDuration | Number | The average time for the job's execution. | 
| Rundeck.ExecutedJobs.job.name | String | The name of the job. | 
| Rundeck.ExecutedJobs.job.group | String | The job's group. | 
| Rundeck.ExecutedJobs.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.job.description | String | A description of the executed job. | 
| Rundeck.ExecutedJobs.job.options | String | The options for the job's execution. | 
| Rundeck.ExecutedJobs.description | String | A description for the execution. | 
| Rundeck.ExecutedJobs.argstring | String | The arguments for the job's execution. | 


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
| arg_string | Execution arguments for the selected job. For example: -opt1 value1 -opt2 value2 | Optional | 
| execution_id | ID of the execution you want to retry execute. | Required | 
| log_level | The log level. Possible values are: "DEBUG", "VERBOSE", "INFO", "WARN", and "ERROR". | Optional | 
| as_user | The name of the user who ran the job. | Optional | 
| failed_nodes | Whether to run all nodes or only failed notes. Specify "true" to run all nodes, or "false" to run only failed nodes. | Optional | 
| options | Options for running the job. For example: 'foo=someValue,bar=someValue'. | Optional | 
| job_id | The ID of the job to execute. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutedJobs.id | Number | The ID of the execution. | 
| Rundeck.ExecutedJobs.status | String | The status of the executed job. | 
| Rundeck.ExecutedJobs.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.executionType | String | The type of execution | 
| Rundeck.ExecutedJobs.user | String | The user who executed the job. | 
| Rundeck.ExecutedJobs.datestarted.unixtime | Number | The date of the job execution in Unix time. | 
| Rundeck.ExecutedJobs.datestarted.date | Date | The date of the job execution. | 
| Rundeck.ExecutedJobs.job.id | String | The ID of the executed job. | 
| Rundeck.ExecutedJobs.job.averageDuration | Number | The average time for the job's execution. | 
| Rundeck.ExecutedJobs.job.name | String | The name of the job. | 
| Rundeck.ExecutedJobs.job.group | String | The job's group. | 
| Rundeck.ExecutedJobs.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutedJobs.job.description | String | A description of the executed job. | 
| Rundeck.ExecutedJobs.job.options | String | The options for the job's execution. | 
| Rundeck.ExecutedJobs.description | String | A description for the execution. | 
| Rundeck.ExecutedJobs.argstring | String | The arguments for the job's execution. | 


#### Command Example
!rundeck-job-retry execution_id=122 job_id={job_id}

#### Human Readable Output
### Execute Job:
|Id|Status|Project|Execution Type|User|Datestarted|Job|Description|Argstring|
|---|---|---|---|---|---|---|---|---|
| 194 | running | Demisto | user | Galb | unixtime: 123 date: 123 | id: 123 averageDuration: 463 name:  Test Job group: project: Demisto description: just a sample job options: {"foo": "0"} | 123 | -foo 0 |



### rundeck-job-executions-query
***
Gets all executions based on the job or execution details.


#### Base Command

`rundeck-job-executions-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Name of the project to query its executions. | Optional | 
| status_filter | Status of the execution. Possible values are: "running", "succeeded", "failed", and "aborted". | Optional | 
| aborted_by_filter | Name of the person who aborted the execution. | Optional | 
| user_filter | Name of the person who stated the execution. | Optional | 
| recent_filter | A number and value used to filter executions that completed within the time period. The format is 'XY', where 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year.<br/>Example: 2w returns executions that completed within the last two weeks. | Optional | 
| older_filter | A number and value used to filter executions that completed after the specified period of time. The format is 'XY', where 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year.<br/>Example: 30d returns executions older than 30 days. | Optional | 
| begin | Exact date for the earliest execution completion time. | Optional | 
| end | Exact date for the latest execution completion time. | Optional | 
| adhoc | Whether to return Adhoc executions. Specify "true" to include Adhoc executions. | Optional | 
| job_id_list_filter | A comma-separated list of job IDs to filter by. | Optional | 
| exclude_job_id_list_filter | A comma-separated list of job IDs to exclude. | Optional | 
| job_list_filter | A comma-separated list of full job groups/names to include. | Optional | 
| exclude_job_list_filter | A comma-separated list of full job groups/names to exclude. | Optional | 
| group_path | Full or partial group path to include all jobs within that group path. | Optional | 
| group_path_exact | Full group path to include all jobs within that group path. | Optional | 
| exclude_group_path | Full or partial group path to exclude all jobs within that group path. | Optional | 
| exclude_group_path_exact | Full group path to exclude all jobs within that group path. | Optional | 
| job_filter | Filter for a job name. Include any job name that matches this value.<br/>For example: To return 'testJob', set this argument to 'test'. | Optional | 
| exclude_job_filter | Filter for the job Name. Exclude any job name that matches this value.<br/>For example: To exclude 'testJob', set this argument to 'test'. | Optional | 
| job_exact_filter | Filter for an exact job name. Include any job name that matches this value.<br/>For example: To return 'testJob', set this argument to 'testJob'. | Optional | 
| exclude_job_exact_filter | Filter for an exact job name. Exclude any job name that matches this value.<br/>For example: To exclude 'testJob', set this argument to 'testJob'. | Optional | 
| execution_type_filter | Type of execution. Possible values are: "scheduled", "user", "user-scheduled" | Optional | 
| max_results | The maximum number of results to return. Default is 100. | Optional | 
| offset | The offset for first result to include.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutionsQuery.paging.count | Number | The number of results | 
| Rundeck.ExecutionsQuery.paging.total | Number | The number of total executions | 
| Rundeck.ExecutionsQuery.paging.offset | Number | The number of the offset for first result to include.  | 
| Rundeck.ExecutionsQuery.paging.max | Number | The maximum number of results to return. | 
| Rundeck.ExecutionsQuery.executions.id | Number | The ID of the execution. | 
| Rundeck.ExecutionsQuery.executions.status | String | The status of the execution. | 
| Rundeck.ExecutionsQuery.executions.project | String | The project name of the execution. | 
| Rundeck.ExecutionsQuery.executions.executionType | String | The type of the execution | 
| Rundeck.ExecutionsQuery.executions.user | String | The name of the person executing the job. | 
| Rundeck.ExecutionsQuery.executions.datestarted.unixtime | Number | The date of the job execution in Unix time. | 
| Rundeck.ExecutionsQuery.executions.datestarted.date | Date | The date of the job execution. | 
| Rundeck.ExecutionsQuery.executions.dateended.unixtime | Unknown | The date of the end of job execution in Unix time. | 
| Rundeck.ExecutionsQuery.executions.dateend.time | Date | The date of the end of job execution. | 
| Rundeck.ExecutionsQuery.executions.job.id | String | The ID of the executed job. | 
| Rundeck.ExecutionsQuery.executions.job.averageDuration | Number | The average time for the job's execution | 
| Rundeck.ExecutionsQuery.executions.job.name | String | The name of the job. | 
| Rundeck.ExecutionsQuery.executions.job.group | String | The job's group. | 
| Rundeck.ExecutionsQuery.executions.job.project | String | The project name of the executed job. | 
| Rundeck.ExecutionsQuery.executions.job.description | String | A description of the job. | 
| Rundeck.ExecutionsQuery.executions.job.options | String | The options for the job's execution. | 
| Rundeck.ExecutionsQuery.executions.description | String | A description of the execution. | 
| Rundeck.ExecutionsQuery.executions.argstring | String | The arguments for the job's execution. | 
| Rundeck.ExecutionsQuery.executions.failedNodes | String | A list of the failed nodes | 
| Rundeck.ExecutionsQuery.paging.total | Number | Indicates the total results that were returned from the API. | 
| Rundeck.ExecutionsQuery.paging.offset | Number | Indicates the 0 indexed offset for the first result to return. | 
| Rundeck.ExecutionsQuery.paging.max | Number | Indicates the maximum number of results to return. If unspecified, all results are returned. | 
| Rundeck.ExecutionsQuery.paging.count | Number | Indicates the number of results that were actually returned, after filter them using the 'offest' and 'max' parameters. | 


#### Command Example
!rundeck-job-executions-query adhoc=false max_results=3 project_name=Demisto user_filter=galb status_filter=failed

#### Human Readable Output
### Job Execution Query - got total results: 2
|Id|Status|Project|Execution Type|User|Datestarted|Dateended|Job|Description|Argstring|Failed Nodes|
|---|---|---|---|---|---|---|---|---|---|---|
| 195 | failed | Demisto | user | Galb | unixtime: 123 date: 123 | unixtime: 123 date: 123 | id: 123 averageDuration: 463 name:  Test Job group:  project: Demisto description: just a sample job options: {"foo": "0"} | 123 | -foo 0 | localhost |



### rundeck-job-execution-output
***
Gets the metadata associated with the workflow step state.


#### Base Command

`rundeck-job-execution-output`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| execution_id | The ID of the execution | Required | 
| return_full_output | Defines how to return the output. If 'true', the output is saved in a returned file and not in Cortex XSOAR context.<br/>If 'false', the number of outputs is limited to 100 and the returned data is saved in context.<br/>Default is 'false'. | Optional | 
| max_results | The maximum number of results to return. Default is 100. | Optional | 
| aggregate_log | Whether all of type 'log' are saved in Cortex XSOAR context under 'listEntry' in  ExecutionsOutput under the execution you selected to run this command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecutionsOutput.id | Number | ID of the execution. | 
| Rundeck.ExecutionsOutput.offset | String | Byte offset to read from in the file. 0 indicates the beginning. | 
| Rundeck.ExecutionsOutput.completed | Boolean | Whether to include all the available data."true" if the current log entries or request parameters include all of the available data. Otherwise, "false". | 
| Rundeck.ExecutionsOutput.execCompleted | Boolean | Whether the execution finished. | 
| Rundeck.ExecutionsOutput.hasFailedNodes | Boolean | Whether there are nodes that failed. | 
| Rundeck.ExecutionsOutput.execState | String | The execution state. Possible values are: "running", "succeeded", "failed", or "aborted". | 
| Rundeck.ExecutionsOutput.lastModified | String | The timestamp of the last modification of the log file in milliseconds. | 
| Rundeck.ExecutionsOutput.execDuration | Number | The duration of the execution in milliseconds. | 
| Rundeck.ExecutionsOutput.percentLoaded | Number | The percentage of the output that was loaded by the parameters. | 
| Rundeck.ExecutionsOutput.totalSize | Number | The total bytes available in the output file. | 
| Rundeck.ExecutionsOutput.retryBackoff | Number | The maximum number of times to retry an execution when the job is directly invoked. | 
| Rundeck.ExecutionsOutput.clusterExec | Boolean | Whether there was a cluster execution. | 
| Rundeck.ExecutionsOutput.compacted | Boolean | Whether a compacted form was requested and is used in the response. | 
| Rundeck.ExecutionsOutput.entries.node | String | The name of the node. | 
| Rundeck.ExecutionsOutput.entries.user | String | The name of the user who performed the execution. | 
| Rundeck.ExecutionsOutput.entries.time | String | The time of the output. | 
| Rundeck.ExecutionsOutput.entries.level | String | The log level | 
| Rundeck.ExecutionsOutput.entries.type | String | The output type | 
| Rundeck.ExecutionsOutput.entries.absolutetime | Date | The absolute time of the output in the format "yyyy-MM-dd'T'HH:mm:ssZ". | 
| Rundeck.ExecutionsOutput.entries.log | String | The log message. | 


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
Aborts an active execution.


#### Base Command

`rundeck-job-execution-abort`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| execution_id | The ID of the execution you want to abort. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Aborted.abort.status | String | The status of the abort process. Possible values are: "pending", "failed", or "aborted". | 
| Rundeck.Aborted.abort.reason | String | The reason for the abort status. | 
| Rundeck.Aborted.execution.id | String | The ID of the aborted execution. | 
| Rundeck.Aborted.execution.status | String | The status of the execution. | 


#### Command Example
!rundeck-job-execution-abort execution_id=65

#### Human Readable Output
### Job Execution Abort:
|Abort|Execution|
|---|---|
| status: failed reason: Job is not running | id: 69 status: failed |



### rundeck-adhoc-command-run
***
Executes shell commands in nodes.


#### Base Command

`rundeck-adhoc-command-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project in which to execute the command | Optional | 
| exec_command | Shell command to run. For example "echo hello". | Required | 
| node_thread_count | The threadcount to use. | Optional | 
| node_keepgoing | Whether to continue executing on other nodes after a failure. | Optional | 
| as_user | The name of the user who ran the command. | Optional | 
| node_filter | Node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntax checking:<br/>attribute: /regex/<br/><br/>For more information, see: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteCommand.message | String | A message regarding the execution progress. | 
| Rundeck.ExecuteCommand.execution.id | String | The execution ID. | 


#### Command Example
!rundeck-adhoc-command-run exec_command="echo hello" as_user=adhocTest project_name=Demisto node_keepgoing=true

#### Human Readable Output
### Adhoc Run:
|Message|Execution|
|---|---|
| Immediate execution scheduled (196) | id: 196 |



### rundeck-adhoc-script-run
***
Runs a script from file.


#### Base Command

`rundeck-adhoc-script-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Cortex XSOAR ID of the uploaded script file. | Required | 
| project_name | The name of the project in which to execute the script. | Optional | 
| arg_string | The arguments to pass to the script when executed. | Optional | 
| node_thread_count | The threadcount to use. | Optional | 
| node_keepgoing | Whether to continue executing on other nodes after a failure. | Optional | 
| as_user | The name of the user who ran the script. | Optional | 
| node_filter | Node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntax checking:<br/>attribute: /regex/<br/><br/>For more information, see: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
| script_interpreter | Command to use to run the script file | Optional | 
| interpreter_args_quoted | Whether the script file and arguments will be quoted as the last argument to the script_interpreter.  | Optional | 
| file_extension | Extension of the script file, | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteScriptFile.message | String | A message regarding the execution progress. | 
| Rundeck.ExecuteScriptFile.execution.id | String | The execution ID. | 


#### Command Example
!rundeck-adhoc-script-run entry_id=@121 as_user='test'

#### Human Readable Output
### Adhoc Run Script:
|Message|Execution|
|---|---|
| Immediate execution scheduled (196) | id: 196 |



### rundeck-adhoc-script-run-from-url
***
Runs a script downloaded from a URL.


#### Base Command

`rundeck-adhoc-script-run-from-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project from which to execute the script. | Optional | 
| script_url | The URL of the script file. | Required | 
| node_thread_count | The threadcount to use. | Optional | 
| node_keepgoing | Whether to continue executing on other nodes after a failure. | Optional | 
| as_user | The name of the user who ran the script file. | Optional | 
| node_filter | Node filter string, or .* for all nodes.<br/><br/>Examples:<br/>To select a specific node by its name:<br/>nodeName1 nodeName2<br/><br/>To filter nodes by attribute value:<br/>Include: attribute: value<br/>Exclude: !attribute: value<br/><br/>To use regular expressions:<br/>Hostname: dev(\d+).com<br/><br/>To use Regex syntax checking:<br/>attribute: /regex/<br/><br/>For more information, see: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 
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
| project_name | The name of the project for which to get its webhooks. | Optional | 
| max_results | The maximum number of results to return. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Webhooks.id | Number | The ID of the webhook. | 
| Rundeck.Webhooks.uuid | String | The UUID of the webhook. | 
| Rundeck.Webhooks.name | String | The name of the webhook. | 
| Rundeck.Webhooks.project | String | The name of the project the webhook relates to. | 
| Rundeck.Webhooks.enabled | String | Whether the webhook is enabled. | 
| Rundeck.Webhooks.user | String | The user name of the webhook user. | 
| Rundeck.Webhooks.creator | String | The user name of the webhook creator. | 
| Rundeck.Webhooks.roles | String | The roles of the webhooks. | 
| Rundeck.Webhooks.authToken | String | The auth token of the webhook. | 
| Rundeck.Webhooks.eventPlugin | String | The plugin that is being used. | 
| Rundeck.Webhooks.config.jobId | String | The ID of the job related to the webhook. | 


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
| auth_token | The auth token of the webhook. | Required | 
| options | Data you want to post to the webhook endpoint. For example: 'op1=val1,op2=val2'.<br/>You can pass either the 'options' or 'json' argument. | Optional | 
| json | JSON you want to post to the webhook endpoint.<br/>You can pass either the 'options' or 'json' argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.WebhookEvent.jobId | String | The ID of the executed job. | 
| Rundeck.WebhookEvent.executionId | String | The ID of the execution. | 


#### Command Example
!rundeck-webhook-event-send json=`{"test":1}` auth_token={auth_id}

#### Human Readable Output
### Webhook event send:
|Job Id|Execution Id|
|---|---|
| 123 | 199 |


