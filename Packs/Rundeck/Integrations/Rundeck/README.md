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
| project_name | project name | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
``` ```

#### Human Readable Output



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
| job_filter | Specify a filter for a job Name, apply this command to any job name that contains this value. | Optional | 
| job_exact_filter | Specify an exact job name to match. | Optional | 
| group_path_exact | Specify an exact group path to match. if not specified, default is: "*". | Optional | 
| scheduled_filter | 'true' to return only scheduled or 'false' for only not scheduled jobs. | Optional | 
| server_node_uuid_filter | A UUID for a selected server to return all jobs related to it. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.Jobs.id | String | UUID of the job | 
| Rundeck.Jobs.name | String | Name of the job. | 
| Rundeck.Jobs.group | String | Group of the job. | 
| Rundeck.Jobs.project | String | Project of the job. | 


#### Command Example
``` ```

#### Human Readable Output



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
| node_filter | Filter for executing the job. | Optional | 
| run_at_time | A time to run the job in a ISO-8601 date and time stamp with timezone, with optional milliseconds. e.g. 2019-10-12T12:20:55-0800 or 2019-10-12T12:20:55.123-0800 | Optional | 
| options | Options for running the job. | Optional | 


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
``` ```

#### Human Readable Output



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
| options | Options for the job's execution. | Optional | 
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
``` ```

#### Human Readable Output



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
| recent_filter | Specify when the execution has occur. The format is 'XY' when 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year | Optional | 
| older_filter | specify executions that completed before the specified relative period of time.<br/>the format is 'XY' when 'X' is a number and 'Y' can be: h - hour, d - day, w - week, m - month, y - year | Optional | 
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
| job_filter | Filter for a job name. Include any job name that matches this value. | Optional | 
| exclude_job_filter | Filter for the job Name. Exclude any job name that matches this | Optional | 
| job_exact_filter | Filter for an exact job name. Include any job name that matches this value. | Optional | 
| exclude_job_exact_filter | Filter for an exact job name. Exclude any job name that matches this value. | Optional | 
| execution_type_filter | Type of execution. | Optional | 
| max_results | maximum number of results to retun | Optional | 
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


#### Command Example
``` ```

#### Human Readable Output



### rundeck-job-execution-output
***
Gets the metadata associated with workflow step state


#### Base Command

`rundeck-job-execution-output`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| execution_id | Id of the execution | Required | 


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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
| node_filter | Node filter to add to the execution.<br/>for more information: https://docs.rundeck.com/docs/api/rundeck-api.html#using-node-filters | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteCommand.message | String | Message regarding the execution progress. | 
| Rundeck.ExecuteCommand.execution.id | String | Execution id | 


#### Command Example
``` ```

#### Human Readable Output



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
| node_filter | Node filter string | Optional | 
| script_interpreter | Command to use to run the script file | Optional | 
| interpreter_args_quoted | 'true', the script file and arguments will be quoted as the last argument to the script_interpreter. 'false' otherwise. | Optional | 
| file_extension | Extension of the script file | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.ExecuteScriptFile.message | String | Message regarding the execution progress. | 
| Rundeck.ExecuteScriptFile.execution.id | String | Execution id | 


#### Command Example
``` ```

#### Human Readable Output



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
| node_filter | Node filter string | Optional | 
| script_interpreter | Command to use to run the script file | Optional | 
| interpreter_args_quoted | 'true', the script file and arguments will be quoted as the last argument to the script_interpreter. 'false' otherwise. | Optional | 
| file_extension | Extension of the script file | Optional | 
| arg_string | Arguments to pass to the script when executed. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### rundeck-webhooks-list
***
Gets a list of all existing webhooks


#### Base Command

`rundeck-webhooks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | Name of the project to get its webhooks. | Optional | 


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
``` ```

#### Human Readable Output



### rundeck-webhook-event-send
***
Send webhook event


#### Base Command

`rundeck-webhook-event-send`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| auth_token | Auto token of the webhook | Required | 
| options | Data you want to post to the webhook endpoint. example: op1=val1,op2=val2.<br/>can pass either 'options' or 'json'. | Optional | 
| json | Json you want to post to the webhook endpoint.<br/>can pass either 'options' or 'json'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rundeck.WebhookEvent.jobId | String | Id of the executed job. | 
| Rundeck.WebhookEvent.executionId | String | Id of the execution. | 


#### Command Example
``` ```

#### Human Readable Output


