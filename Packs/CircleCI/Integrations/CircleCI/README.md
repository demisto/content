Get details of CircleCI workflows, including details of its last runs, jobs, and retrieve artifact of jobs.
This integration was integrated and tested with version v2 of CircleCI
## Configure CircleCI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CircleCI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | VC Type | Type of VC. | True |
    | Organization Name | Name of the organization. | True |
    | Project Name | Name of the project. | True |
    | Trust any certificate (not secure) |  | True |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### circleci-workflows-list
***
Get info of workflows.


#### Base Command

`circleci-workflows-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of workflows to retrieve. Default is 20. | Optional | 
| vcs_type | VC type of the project. Possible values are: github, bitbucket. Default is github. | Optional | 
| organization | Organization to retrieve workflows from. Defaults to organization instance parameter if none is given. | Optional | 
| project | Project to retrieve workflows from. Defaults to project instance parameter if none is given. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CircleCI.Workflow.metrics.duration_metrics.max | Number | Max time workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.mean | Number | Mean time workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.median | Number | Median time workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.min | Number | Min time workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.p95 | Number | P95 workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.standard_deviation | Number | Standard deviation workflow has run. | 
| CircleCI.Workflow.metrics.duration_metrics.total_duration | Number | Total duration. | 
| CircleCI.Workflow.metrics.failed_runs | Number | Number of workflow failed runs. | 
| CircleCI.Workflow.metrics.median_credits_used | Number | Median credits used. | 
| CircleCI.Workflow.metrics.mttr | Number | Mean time to recovery. | 
| CircleCI.Workflow.metrics.success_rate | Number | Success rate. | 
| CircleCI.Workflow.metrics.successful_runs | Number | Number of successful runs. | 
| CircleCI.Workflow.metrics.throughput | Number | Throughput. | 
| CircleCI.Workflow.metrics.total_credits_used | Number | Total credits used. | 
| CircleCI.Workflow.metrics.total_recoveries | Number | Total recoveries. | 
| CircleCI.Workflow.metrics.total_runs | Number | Total runs. | 
| CircleCI.Workflow.name | String | Workflow name. | 
| CircleCI.Workflow.project_id | String | Project ID workflow belongs to. | 
| CircleCI.Workflow.window_end | Date | When workflow has ended. | 
| CircleCI.Workflow.window_start | Date | When workflow has started. | 


#### Command Example
```!circleci-workflows-list limit=2```

#### Context Example
```json
{
    "CircleCI": {
        "Workflow": {
            "metrics": {
                "duration_metrics": {
                    "max": 6011,
                    "mean": 4508,
                    "median": 4508,
                    "min": 3005,
                    "p95": 5860,
                    "standard_deviation": 2125,
                    "total_duration": 0
                },
                "failed_runs": 1,
                "median_credits_used": 0,
                "mttr": 0,
                "success_rate": 0.5,
                "successful_runs": 1,
                "throughput": 0.2,
                "total_credits_used": 1900,
                "total_recoveries": 0,
                "total_runs": 2
            },
            "name": "bucket_upload_trigger",
            "project_id": "4eaba5af-8c43-43ec-b469-3968d8a76f68",
            "window_end": "2021-04-22T14:28:57.252Z",
            "window_start": "2021-04-13T12:31:14.409Z"
        }
    }
}
```

#### Human Readable Output

>### CircleCI Workflows
>|Metrics|Name|ProjectId|WindowEnd|WindowStart|
>|---|---|---|---|---|
>| total_runs: 181<br/>successful_runs: 136<br/>mttr: 93519<br/>total_credits_used: 323000<br/>failed_runs: 43<br/>median_credits_used: 0<br/>success_rate: 0.7513812154696132<br/>duration_metrics: {"min": 202, "mean": 8807, "median": 8606, "p95": 11307, "max": 16317, "standard_deviation": 1707.0, "total_duration": 0}<br/>total_recoveries: 0<br/>throughput: 2.033707865168539 | bucket_upload | 4eaba5af-8c43-43ec-b469-3968d8a76f68 | 2021-06-28T23:42:38.647Z | 2021-03-31T09:01:11.412Z |
>| total_runs: 2<br/>successful_runs: 1<br/>mttr: 0<br/>total_credits_used: 1900<br/>failed_runs: 1<br/>median_credits_used: 0<br/>success_rate: 0.5<br/>duration_metrics: {"min": 3005, "mean": 4508, "median": 4508, "p95": 5860, "max": 6011, "standard_deviation": 2125.0, "total_duration": 0}<br/>total_recoveries: 0<br/>throughput: 0.2 | bucket_upload_trigger | 4eaba5af-8c43-43ec-b469-3968d8a76f68 | 2021-04-22T14:28:57.252Z | 2021-04-13T12:31:14.409Z |


### circleci-artifacts-list
***
Retrieves artifacts list from CircleCI job.


#### Base Command

`circleci-artifacts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_number | Number of the job to retrieve its artifacts, e.g 31263. | Required | 
| artifact_suffix | Will return only artifact whom suffix corresponds to suffix given, e.g 'test_failures.txt' will retrieve only artifacts whom suffix ends with test_failures.txt. | Optional | 
| limit | Maximum number of artifacts to retrieve. Default is 20. | Optional | 
| vcs_type | VC type of the project. Possible values are: github, bitbucket. Default is github. | Optional | 
| organization | Organization to retrieve artifacts from. Defaults to organization instance parameter if none is given. | Optional | 
| project | Project to retrieve artifacts from. Defaults to project instance parameter if none is given. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CircleCI.Artifact.path | String | Artifact relative path. | 
| CircleCI.Artifact.node_index | Number | Artifact node index. | 
| CircleCI.Artifact.url | String | Artifact URL. | 


#### Command Example
```!circleci-artifacts-list job_number=390115 limit=2```

#### Context Example
```json
{
    "CircleCI": {
        "Artifact": [
            {
                "node_index": 0,
                "path": "artifacts/env.json",
                "url": "https://390115-12353212-gh.circle-artifacts.com/0/artifacts/env.json"
            },
            {
                "node_index": 0,
                "path": "artifacts/debug_log.log",
                "url": "https://390115-12353212-gh.circle-artifacts.com/0/artifacts/debug_log.log"
            }
        ]
    }
}
```

#### Human Readable Output

>### CircleCI Artifacts
>|NodeIndex|Path|Url|
>|---|---|---|
>| 0 | artifacts/env.json | https://390115-12353212-gh.circle-artifacts.com/0/artifacts/env.json |
>| 0 | artifacts/debug_log.log | https://390115-12353212-gh.circle-artifacts.com/0/artifacts/debug_log.log |


### circleci-workflow-jobs-list
***
Retrieve jobs list from CircleCI workflow.


#### Base Command

`circleci-workflow-jobs-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | Workflow ID to retrieve its jobs, e.g 12zxcase-12za-as51-123zs4sdgf12. | Required | 
| limit | Maximum number of jobs to retrieve. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CircleCI.WorkflowJob.id | String | Job ID. | 
| CircleCI.WorkflowJob.job_number | Number | Job number. | 
| CircleCI.WorkflowJob.name | String | Job name. | 
| CircleCI.WorkflowJob.project_slug | String | The job project slug. | 
| CircleCI.WorkflowJob.started_at | Date | Time job was started. | 
| CircleCI.WorkflowJob.status | String | Job status. | 
| CircleCI.WorkflowJob.stopped_at | Date | Time when job was stopped. | 
| CircleCI.WorkflowJob.type | String | Job type. | 
| CircleCI.WorkflowJob.dependencies | String | The job dependencies. | 


#### Command Example
```!circleci-workflow-jobs-list workflow_id=f85efae0-cbf4-4b6d-b136-e3db67d41221 limit=2```

#### Context Example
```json
{
    "CircleCI": {
        "Workflow": {
            "Job": [
                {
                    "dependencies": [],
                    "id": "c7425325-bb57-4e78-968f-2c9867d31z11",
                    "job_number": 389133,
                    "name": "Setup Environment",
                    "project_slug": "gh/organization_name/repo_name",
                    "started_at": "2021-06-24T00:04:57Z",
                    "status": "success",
                    "stopped_at": "2021-06-24T00:06:32Z",
                    "type": "build"
                },
                {
                    "dependencies": [
                        "c7425325-bb57-4e78-968f-2c9867d31z11"
                    ],
                    "id": "89d36e04-5481-48a3-8be4-ddcb2bdcz1q1",
                    "job_number": 389166,
                    "name": "Run Validations",
                    "project_slug": "gh/organization_name/repo_name",
                    "started_at": "2021-06-24T00:06:35Z",
                    "status": "success",
                    "stopped_at": "2021-06-24T00:38:00Z",
                    "type": "build"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### CircleCI Workflow f85efae0-cbf4-4b6d-b136-e3db67d41221 Jobs
>|Dependencies|Id|JobNumber|Name|ProjectSlug|StartedAt|Status|StoppedAt|Type|
>|---|---|---|---|---|---|---|---|---|
>|  | c7425325-bb57-4e78-968f-2c9867d31z11 | 389133 | Setup Environment | gh/organization_name/repo_name | 2021-06-24T00:04:57Z | success | 2021-06-24T00:06:32Z | build |
>| c7425325-bb57-4e78-968f-2c9867d31z11 | 89d36e04-5481-48a3-8be4-ddcb2bdcz1q1 | 389166 | Run Validations | gh/organization_name/repo_name | 2021-06-24T00:06:35Z | success | 2021-06-24T00:38:00Z | build |


### circleci-workflow-last-runs
***
Retrieve jobs list from CircleCI workflow.


#### Base Command

`circleci-workflow-last-runs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_name | Name of workflow to retrieve its last runs details. | Required | 
| limit | Maximum number of workflow runs to retrieve. Default is 20. | Optional | 
| vcs_type | VC type of the project. Possible values are: github, bitbucket. Default is github. | Optional | 
| organization | Organization to retrieve workflow last runs from. Defaults to organization instance parameter if none is given. | Optional | 
| project | Project to retrieve workflow last runs from. Defaults to project instance parameter if none is given. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CircleCI.WorkflowRun.branch | String | Branch name. | 
| CircleCI.WorkflowRun.created_at | Date | Time run was created. | 
| CircleCI.WorkflowRun.credits_used | Number | Credits used. | 
| CircleCI.WorkflowRun.duration | Number | Duration of run in seconds. | 
| CircleCI.WorkflowRun.id | String | ID of the run. | 
| CircleCI.WorkflowRun.status | String | Run status. | 
| CircleCI.WorkflowRun.stopped_at | Date | Time when run was stopped. | 


#### Command Example
```!circleci-workflow-last-runs workflow_name=nightly limit=2```

#### Context Example
```json
{
    "CircleCI": {
        "WorkflowRun": [
            {
                "branch": "master",
                "created_at": "2021-06-29T00:04:56.069Z",
                "credits_used": 2482,
                "duration": 7743,
                "id": "d832d004-0069-4412-8e6d-41265143411z",
                "status": "failed",
                "stopped_at": "2021-06-29T02:13:59.354Z"
            },
            {
                "branch": "master",
                "created_at": "2021-06-28T00:04:55.409Z",
                "credits_used": 3129,
                "duration": 9778,
                "id": "531e678e-73e3-4f2a-ac80-55aa203461za",
                "status": "failed",
                "stopped_at": "2021-06-28T02:47:52.916Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### CircleCI Workflow nightly Last Runs
>|Branch|CreatedAt|CreditsUsed|Duration|Id|Status|StoppedAt|
>|---|---|---|---|---|---|---|
>| master | 2021-06-29T00:04:56.069Z | 2482 | 7743 | d832d004-0069-4412-8e6d-41265143411z | failed | 2021-06-29T02:13:59.354Z |
>| master | 2021-06-28T00:04:55.409Z | 3129 | 9778 | 531e678e-73e3-4f2a-ac80-55aa203461za | failed | 2021-06-28T02:47:52.916Z |

