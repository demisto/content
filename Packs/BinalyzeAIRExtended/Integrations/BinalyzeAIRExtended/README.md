Manage Binalyze AIR forensic acquisition, endpoint isolation, triage, cases, tasks, assets, repositories, and evidence artifacts from Cortex XSOAR.
## Configure Binalyze AIR Extended in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Binalyze AIR Server URL | Binalyze AIR Server URL, for example https://air.example.com | True |
| API Key | Binalyze AIR API token, for example api_1234567890abcdef1234567890abcdef | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### binalyze-air-isolate

***
Isolate an endpoint or release endpoint isolation.

#### Base Command

`binalyze-air-isolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| organization_id | Organization ID of the endpoint. | Required | 
| isolation | Use enable to isolate the endpoint or disable to release isolation. Possible values are: enable, disable. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Isolate.Result.ID | string | Isolation task ID. | 
| BinalyzeAIR.Isolate.Result.Name | string | Isolation task name. | 
| BinalyzeAIR.Isolate.Result.OrganizationID | number | Endpoint organization ID. | 

### binalyze-air-acquire

***
Start forensic evidence acquisition from an endpoint.

#### Base Command

`binalyze-air-acquire`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| profile | Acquisition profile name. Custom profile names can also be provided. Possible values are: compromise-assessment, browsing-history, event-logs, memory-ram-pagefile, quick, full. | Required | 
| case_id | Binalyze AIR case ID. | Required | 
| organization_id | Organization ID of the endpoint. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Acquire.Result.ID | string | Acquisition task ID. | 
| BinalyzeAIR.Acquire.Result.Name | string | Acquisition task name. | 
| BinalyzeAIR.Acquire.Result.OrganizationID | number | Endpoint organization ID. | 

### binalyze-air-create-case

***
Create a Binalyze AIR case.

#### Base Command

`binalyze-air-create-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Case name. | Required | 
| organization_id | Organization ID. | Required | 
| owner_user_id | Owner user ID. | Required | 
| visibility | Case visibility. Possible values are: public-to-organization, private-to-users, Public to Organization, Private to Users. | Required | 
| assigned_user_ids | Comma-separated assigned user IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Case.Result.ID | string | Case ID. | 
| BinalyzeAIR.Case.Result.Name | string | Case name. | 

### binalyze-air-get-case

***
Get a Binalyze AIR case by ID.

#### Base Command

`binalyze-air-get-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Case | unknown | Case details. | 

### binalyze-air-list-cases

***
List Binalyze AIR cases.

#### Base Command

`binalyze-air-list-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Optional case name filter. | Optional | 
| organization_ids | Optional comma-separated organization IDs. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Cases | unknown | Case list response. | 

### binalyze-air-close-case

***
Close a Binalyze AIR case.

#### Base Command

`binalyze-air-close-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| reason | Closure reason. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CloseCase | unknown | Close case response. | 

### binalyze-air-get-case-tasks

***
Get tasks associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| task_id | Optional task ID filter. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseTask | unknown | Case task response. | 

### binalyze-air-get-case-endpoints

***
Get endpoints associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseEndpoint | unknown | Case endpoint response. | 

### binalyze-air-get-case-activities

***
Get activity history associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-activities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseActivity | unknown | Case activity response. | 

### binalyze-air-list-assets

***
List Binalyze AIR endpoints/assets with optional filters.

#### Base Command

`binalyze-air-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Optional hostname filter. | Optional | 
| organization_id | Optional organization ID filter. | Optional | 
| organization_ids | Optional comma-separated organization IDs. | Optional | 
| online_status | Optional online status filter. | Optional | 
| isolation_status | Optional isolation status filter. | Optional | 
| platform | Optional platform filter. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset | unknown | Asset list response. | 

### binalyze-air-get-asset

***
Get a Binalyze AIR endpoint/asset by asset ID.

#### Base Command

`binalyze-air-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset | unknown | Asset details. | 

### binalyze-air-get-asset-by-hostname

***
Find a Binalyze AIR endpoint/asset by hostname and organization ID.

#### Base Command

`binalyze-air-get-asset-by-hostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| organization_id | Organization ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset.Result | unknown | First matching asset. | 

### binalyze-air-get-asset-tasks

***
Get tasks associated with an endpoint/asset.

#### Base Command

`binalyze-air-get-asset-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AssetTask | unknown | Asset task response. | 

### binalyze-air-get-task

***
Get task details and normalized terminal status flags for polling.

#### Base Command

`binalyze-air-get-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Task.Result | unknown | Task details. | 
| BinalyzeAIR.Task.Status | string | Normalized task status. | 
| BinalyzeAIR.Task.IsDone | boolean | Whether the task is in a terminal state. | 
| BinalyzeAIR.Task.IsSuccess | boolean | Whether the task completed successfully. | 

### binalyze-air-list-tasks

***
List Binalyze AIR tasks.

#### Base Command

`binalyze-air-list-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Optional case ID filter. | Optional | 
| organization_id | Optional organization ID filter. | Required | 
| organization_ids | Optional comma-separated organization IDs. | Optional | 
| status | Optional status filter. | Optional | 
| task_type | Optional task type filter. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Task | unknown | Task list response. | 

### binalyze-air-get-task-assignments

***
Get task assignment details for a Binalyze AIR task.

#### Base Command

`binalyze-air-get-task-assignments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TaskAssignment | unknown | Task assignment response. | 

### binalyze-air-wait-task-completion

***
Wait for a Binalyze AIR task to reach a terminal state. Use GenericPolling for large-scale production playbooks.

#### Base Command

`binalyze-air-wait-task-completion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required | 
| poll_interval_seconds | Poll interval in seconds. Default is 30. | Optional | 
| timeout_seconds | Maximum wait time in seconds. Default is 900. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TaskWait.TaskID | string | Task ID. | 
| BinalyzeAIR.TaskWait.Status | string | Last observed task status. | 
| BinalyzeAIR.TaskWait.IsDone | boolean | Whether the task reached a terminal state. | 

### binalyze-air-create-triage-rule

***
Create a YARA, Sigma, or osquery triage rule.

#### Base Command

`binalyze-air-create-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Rule description. | Optional | 
| rule | Rule content. | Required | 
| engine | Rule engine. Possible values are: yara, sigma, osquery. | Required | 
| search_in | Search scope. Possible values are: system, memory, both, event-records. | Optional | 
| organization_ids | Comma-separated organization IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | Created triage rule response. | 

### binalyze-air-update-triage-rule

***
Update an existing triage rule.

#### Base Command

`binalyze-air-update-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Triage rule ID. | Required | 
| description | Rule description. | Optional | 
| rule | Rule content. | Optional | 
| search_in | Search scope. Possible values are: system, memory, both, event-records. | Optional | 
| organization_ids | Comma-separated organization IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | Updated triage rule response. | 

### binalyze-air-validate-triage-rule

***
Validate a YARA, Sigma, or osquery triage rule before assignment.

#### Base Command

`binalyze-air-validate-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule | Rule content. | Required | 
| engine | Rule engine. Possible values are: yara, sigma, osquery. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRuleValidation.Result | unknown | Validation result payload. | 
| BinalyzeAIR.TriageRuleValidation.Success | boolean | Whether validation succeeded. | 

### binalyze-air-list-triage-rules

***
List triage rules.

#### Base Command

`binalyze-air-list-triage-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | Optional organization ID filter. | Required | 
| organization_ids | Optional comma-separated organization IDs. | Optional | 
| engine | Optional rule engine filter. Possible values are: yara, sigma, osquery. | Optional | 
| search_in | Optional search scope filter. Possible values are: system, memory, both, event-records. | Optional | 
| description | Optional description filter. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | Triage rule list response. | 

### binalyze-air-get-triage-rule

***
Get a triage rule by ID.

#### Base Command

`binalyze-air-get-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Triage rule ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | Triage rule details. | 

### binalyze-air-delete-triage-rule

***
Delete a triage rule by ID.

#### Base Command

`binalyze-air-delete-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Triage rule ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.DeleteTriageRule | unknown | Delete triage rule response. | 

### binalyze-air-assign-triage-task

***
Assign one or more triage rules to endpoints by filter.

#### Base Command

`binalyze-air-assign-triage-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| triage_rule_ids | Comma-separated triage rule IDs. | Required | 
| organization_id | Organization ID. | Required | 
| task_config_choice | Task configuration mode. Possible values are: use-policy, use-custom-options. Default is use-policy. | Optional | 
| task_config_cpu_limit | CPU limit. Minimum 1, maximum 100. Default is 8. | Optional | 
| hostname | Endpoint hostname filter. | Optional | 
| mitre_attack | Enable MITRE ATT&amp;CK mapping. Possible values are: True, False. Default is False. | Optional | 
| included_endpoint_ids | Comma-separated included endpoint IDs. | Optional | 
| excluded_endpoint_ids | Comma-separated excluded endpoint IDs. | Optional | 
| group_id | Optional endpoint group ID. | Optional | 
| group_full_path | Optional endpoint group full path. | Optional | 
| isolation_status | Optional comma-separated isolation status filter. | Optional | 
| platform | Optional comma-separated platform filter. | Optional | 
| issue | Optional issue filter. | Optional | 
| online_status | Optional comma-separated online status filter. | Optional | 
| tags | Optional comma-separated tag filter. | Optional | 
| version | Optional agent version filter. | Optional | 
| policy | Optional policy filter. | Optional | 
| when | Scheduler value. Default is now. Default is now. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageTask | unknown | Assign triage task response. | 

### binalyze-air-list-acquisition-profiles

***
List acquisition profiles.

#### Base Command

`binalyze-air-list-acquisition-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Optional profile name filter. | Optional | 
| organization_id | Optional organization ID filter. | Required | 
| organization_ids | Optional comma-separated organization IDs. | Optional | 
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AcquisitionProfile | unknown | Acquisition profile list response. | 

### binalyze-air-get-acquisition-profile

***
Get acquisition profile details by ID.

#### Base Command

`binalyze-air-get-acquisition-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | Acquisition profile ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AcquisitionProfile | unknown | Acquisition profile details. | 

### binalyze-air-list-repositories

***
List Binalyze AIR repositories.

#### Base Command

`binalyze-air-list-repositories`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional | 
| limit | Page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Repository | unknown | Repository list response. | 

### binalyze-air-get-repository

***
Get repository details by ID.

#### Base Command

`binalyze-air-get-repository`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository_id | Repository ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Repository | unknown | Repository details. | 

### binalyze-air-download-file

***
Download a file from the Binalyze AIR InterACT library into the War Room.

#### Base Command

`binalyze-air-download-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | File name to download from the InterACT library. | Required | 

#### Context Output

There is no context output for this command.
