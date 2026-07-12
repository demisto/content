Manage Binalyze AIR forensic acquisition, endpoint isolation, triage, cases, tasks, assets, repositories, and evidence artifacts from Cortex XSOAR.
This integration was integrated and tested with version xx of Binalyze AIR Extended.

## Configure Binalyze AIR Extended in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Binalyze AIR Server URL | The Binalyze AIR Server URL, for example <https://air.example.com>. | True |
| API Key | The Binalyze AIR API token, for example api_1234567890abcdef1234567890abcdef. | True |
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
| hostname | The endpoint hostname. | Required | 
| organization_id | The organization ID of the endpoint. | Required | 
| isolation | The isolation action to perform. Possible values are: enable, disable. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Isolate.Result.ID | string | The isolation task ID. | 
| BinalyzeAIR.Isolate.Result.Name | string | The isolation task name. | 
| BinalyzeAIR.Isolate.Result.OrganizationID | number | The endpoint organization ID. | 

### binalyze-air-acquire

***
Start forensic evidence acquisition from an endpoint.

#### Base Command

`binalyze-air-acquire`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The endpoint hostname. | Required | 
| profile | The acquisition profile name. Possible values are: compromise-assessment, browsing-history, event-logs, memory-ram-pagefile, quick, full. | Required | 
| case_id | The Binalyze AIR case ID. | Required | 
| organization_id | The organization ID of the endpoint. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Acquire.Result.ID | string | The acquisition task ID. | 
| BinalyzeAIR.Acquire.Result.Name | string | The acquisition task name. | 
| BinalyzeAIR.Acquire.Result.OrganizationID | number | The endpoint organization ID. | 

### binalyze-air-create-case

***
Create a Binalyze AIR case.

#### Base Command

`binalyze-air-create-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The case name. | Required | 
| organization_id | The organization ID. | Required | 
| owner_user_id | The owner user ID. | Required | 
| visibility | The case visibility. Possible values are: public-to-organization, private-to-users, Public to Organization, Private to Users. | Required | 
| assigned_user_ids | A comma-separated list of assigned user IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Case.Result.ID | string | The case ID. | 
| BinalyzeAIR.Case.Result.Name | string | The case name. | 

### binalyze-air-get-case

***
Get a Binalyze AIR case by ID.

#### Base Command

`binalyze-air-get-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Case | unknown | The case details. | 

### binalyze-air-list-cases

***
List Binalyze AIR cases.

#### Base Command

`binalyze-air-list-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The optional case name filter. | Optional | 
| organization_id | The optional organization ID filter. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Cases | unknown | The case list response. | 

### binalyze-air-close-case

***
Close a Binalyze AIR case.

#### Base Command

`binalyze-air-close-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 
| reason | The closure reason. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CloseCase | unknown | The close case response. | 

### binalyze-air-get-case-tasks

***
Get tasks associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 
| task_id | The optional task ID filter. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseTask | unknown | The case task response. | 

### binalyze-air-get-case-endpoints

***
Get endpoints associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseEndpoint | unknown | The case endpoint response. | 

### binalyze-air-get-case-activities

***
Get activity history associated with a Binalyze AIR case.

#### Base Command

`binalyze-air-get-case-activities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.CaseActivity | unknown | The case activity response. | 

### binalyze-air-list-assets

***
List Binalyze AIR endpoints/assets with optional filters.

#### Base Command

`binalyze-air-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The optional endpoint hostname filter. | Optional | 
| organization_id | The optional organization ID filter. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 
| online_status | The optional online status filter. | Optional | 
| isolation_status | The optional isolation status filter. | Optional | 
| platform | The optional platform filter. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset | unknown | The asset list response. | 

### binalyze-air-get-asset

***
Get a Binalyze AIR endpoint/asset by asset ID.

#### Base Command

`binalyze-air-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset | unknown | The asset details. | 

### binalyze-air-get-asset-by-hostname

***
Find a Binalyze AIR endpoint/asset by hostname and organization ID.

#### Base Command

`binalyze-air-get-asset-by-hostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The endpoint hostname. | Required | 
| organization_id | The organization ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Asset.Result | unknown | The first matching asset. | 

### binalyze-air-get-asset-tasks

***
Get tasks associated with an endpoint/asset.

#### Base Command

`binalyze-air-get-asset-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID. | Required | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AssetTask | unknown | The asset task response. | 

### binalyze-air-get-task

***
Get task details and normalized terminal status flags for polling.

#### Base Command

`binalyze-air-get-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Task.Result | unknown | The task details. | 
| BinalyzeAIR.Task.Status | string | The normalized task status. | 
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
| case_id | The optional case ID filter. | Optional | 
| organization_id | The optional organization ID filter. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 
| status | The optional status filter. | Optional | 
| task_type | The optional task type filter. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Task | unknown | The task list response. | 

### binalyze-air-get-task-assignments

***
Get task assignment details for a Binalyze AIR task.

#### Base Command

`binalyze-air-get-task-assignments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. | Required | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TaskAssignment | unknown | The task assignment response. | 

### binalyze-air-create-triage-rule

***
Create a YARA, Sigma, or osquery triage rule.

#### Base Command

`binalyze-air-create-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The rule description. | Optional | 
| rule | The rule content. | Required | 
| engine | The rule engine. Possible values are: yara, sigma, osquery. | Required | 
| search_in | The search scope. Possible values are: system, memory, both, event-records. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | The created triage rule response. | 

### binalyze-air-update-triage-rule

***
Update an existing triage rule.

#### Base Command

`binalyze-air-update-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The triage rule ID. | Required | 
| description | The rule description. | Optional | 
| rule | The rule content. | Optional | 
| search_in | The search scope. Possible values are: system, memory, both, event-records. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | The updated triage rule response. | 

### binalyze-air-validate-triage-rule

***
Validate a YARA, Sigma, or osquery triage rule before assignment.

#### Base Command

`binalyze-air-validate-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule | The rule content. | Required | 
| engine | The rule engine. Possible values are: yara, sigma, osquery. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRuleValidation.Result | unknown | The validation result payload. | 
| BinalyzeAIR.TriageRuleValidation.Success | boolean | Whether validation succeeded. | 

### binalyze-air-list-triage-rules

***
List triage rules.

#### Base Command

`binalyze-air-list-triage-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | The optional organization ID filter. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 
| engine | The optional rule engine filter. Possible values are: yara, sigma, osquery. | Optional | 
| search_in | The optional search scope filter. Possible values are: system, memory, both, event-records. | Optional | 
| description | The optional description filter. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | The triage rule list response. | 

### binalyze-air-get-triage-rule

***
Get a triage rule by ID.

#### Base Command

`binalyze-air-get-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The triage rule ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageRule | unknown | The triage rule details. | 

### binalyze-air-delete-triage-rule

***
Delete a triage rule by ID.

#### Base Command

`binalyze-air-delete-triage-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The triage rule ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.DeleteTriageRule | unknown | The delete triage rule response. | 

### binalyze-air-assign-triage-task

***
Assign one or more triage rules to endpoints by filter.

#### Base Command

`binalyze-air-assign-triage-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 
| triage_rule_ids | A comma-separated list of triage rule IDs. | Required | 
| organization_id | The organization ID. | Required | 
| task_config_choice | The task configuration mode. Possible values are: use-policy, use-custom-options. Default is use-policy. | Optional | 
| task_config_cpu_limit | The CPU limit. Minimum 1, maximum 100. Default is 8. | Optional | 
| hostname | The endpoint hostname filter. | Optional | 
| mitre_attack | Whether to enable MITRE ATT&amp;CK mapping. Possible values are: True, False. Default is False. | Optional | 
| included_endpoint_ids | A comma-separated list of included endpoint IDs. | Optional | 
| excluded_endpoint_ids | A comma-separated list of excluded endpoint IDs. | Optional | 
| group_id | The optional endpoint group ID. | Optional | 
| group_full_path | The optional endpoint group full path. | Optional | 
| isolation_status | A comma-separated list of isolation status values. | Optional | 
| platform | A comma-separated list of platform values. | Optional | 
| issue | The optional issue filter. | Optional | 
| online_status | A comma-separated list of online status values. | Optional | 
| tags | A comma-separated list of tags. | Optional | 
| version | The optional agent version filter. | Optional | 
| policy | The optional policy filter. | Optional | 
| when | The scheduler value. Default is now. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.TriageTask | unknown | The assign triage task response. | 

### binalyze-air-list-acquisition-profiles

***
List acquisition profiles.

#### Base Command

`binalyze-air-list-acquisition-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The optional profile name filter. | Optional | 
| organization_id | The optional organization ID filter. | Optional | 
| organization_ids | A comma-separated list of organization IDs. | Optional | 
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AcquisitionProfile | unknown | The acquisition profile list response. | 

### binalyze-air-get-acquisition-profile

***
Get acquisition profile details by ID.

#### Base Command

`binalyze-air-get-acquisition-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The acquisition profile ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.AcquisitionProfile | unknown | The acquisition profile details. | 

### binalyze-air-list-repositories

***
List Binalyze AIR repositories.

#### Base Command

`binalyze-air-list-repositories`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. | Optional | 
| limit | The page size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Repository | unknown | The repository list response. | 

### binalyze-air-get-repository

***
Get repository details by ID.

#### Base Command

`binalyze-air-get-repository`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository_id | The repository ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Repository | unknown | The repository details. | 

### binalyze-air-download-file

***
Download a file from the Binalyze AIR InterACT library into the Cortex XSOAR War Room.

#### Base Command

`binalyze-air-download-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | The file name to download from the InterACT library. | Required | 

#### Context Output

There is no context output for this command.
