Scale IT automation, manage complex deployments and speed productivity.
This integration was integrated and tested with version xx of AnsibleTower
## Configure AnsibleTower on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AnsibleTower.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL | True |
    | credentials | Username | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ansible-tower-inventories-list
***
Retrieve the list of inventories


#### Base Command

`ansible-tower-inventories-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | If given an inventory id, will retrieve the specific inventory. | Optional | 
| page_number | Number of page to retrieve. Default page number is 1. Default is 1. | Optional | 
| page_size | Default page size is 50. Default is 50. | Optional | 
| search | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-inventories-list page_number=1 page_size=50```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Inventory": {
            "created": "2019-11-19T11:53:43.325946Z",
            "description": "",
            "groups_with_active_failures": 0,
            "has_active_failures": true,
            "has_inventory_sources": false,
            "host_filter": null,
            "hosts_with_active_failures": 1,
            "id": 1,
            "insights_credential": null,
            "inventory_sources_with_failures": 0,
            "kind": "",
            "modified": "2021-01-04T14:47:32.388642Z",
            "name": "Demo Inventory",
            "organization": 1,
            "pending_deletion": false,
            "total_groups": 0,
            "total_hosts": 2,
            "total_inventory_sources": 0,
            "type": "inventory",
            "url": "/api/v2/inventories/1/",
            "variables": ""
        }
    }
}
```

#### Human Readable Output

>### Results
>|created|groups_with_active_failures|has_active_failures|has_inventory_sources|hosts_with_active_failures|id|inventory_sources_with_failures|modified|name|organization|pending_deletion|total_groups|total_hosts|total_inventory_sources|type|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2019-11-19T11:53:43.325946Z | 0 | true | false | 1 | 1 | 0 | 2021-01-04T14:47:32.388642Z | Demo Inventory | 1 | false | 0 | 2 | 0 | inventory | /api/v2/inventories/1/ |


### ansible-tower-hosts-list
***
Retrieve the list of hosts. If an inventory id is given, retrieve the host under the specific inventory


#### Base Command

`ansible-tower-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Host id, to retrieve a specific host. | Optional | 
| inventory_id | inventory id. | Optional | 
| page | page number. Default is 1. | Optional | 
| page_size | page size. Possible values are: Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model.. Default is 50. | Optional | 
| search | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-hosts-list inventory_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Host": [
            {
                "ansible_facts_modified": null,
                "created": "2021-01-04T14:46:58.333375Z",
                "description": "",
                "enabled": true,
                "has_active_failures": true,
                "has_inventory_sources": false,
                "id": 26,
                "insights_system_id": null,
                "instance_id": "",
                "inventory": 1,
                "last_job": 382,
                "last_job_host_summary": 124,
                "modified": "2021-01-04T16:14:32.317997Z",
                "name": "example",
                "type": "host",
                "url": "/api/v2/hosts/26/",
                "variables": ""
            },
            {
                "ansible_facts_modified": null,
                "created": "2019-11-19T11:53:43.427675Z",
                "description": "",
                "enabled": true,
                "has_active_failures": false,
                "has_inventory_sources": false,
                "id": 1,
                "insights_system_id": null,
                "instance_id": "",
                "inventory": 1,
                "last_job": 382,
                "last_job_host_summary": 125,
                "modified": "2021-01-04T16:14:32.334362Z",
                "name": "localhost",
                "type": "host",
                "url": "/api/v2/hosts/1/",
                "variables": "ansible_connection: local"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|created|enabled|has_active_failures|has_inventory_sources|id|inventory|last_job|last_job_host_summary|modified|name|type|url|variables|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-04T14:46:58.333375Z | true | true | false | 26 | 1 | 382 | 124 | 2021-01-04T16:14:32.317997Z | example | host | /api/v2/hosts/26/ |  |
>| 2019-11-19T11:53:43.427675Z | true | false | false | 1 | 1 | 382 | 125 | 2021-01-04T16:14:32.334362Z | localhost | host | /api/v2/hosts/1/ | ansible_connection: local |


### ansible-tower-host-create
***
Create a host under the given inventory id and with the given name


#### Base Command

`ansible-tower-host-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | The value used by the remote inventory source to uniquely identify the host. | Required | 
| host_name | Name of this host, must be a unique name. | Required | 
| description | Optional description of this host. | Optional | 
| enabled |  Is this host online and available for running jobs? . Default is True. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### ansible-tower-host-delete
***
Delete host


#### Base Command

`ansible-tower-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | host is to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### ansible-tower-job-templates-list
***
Retrieve the list of job templates


#### Base Command

`ansible-tower-job-templates-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | Inventory id to list all jobs that are managed with hosts under this inventory. | Optional | 
| page | Number of page to retrieve. Default page number is 1. Default is 1. | Optional | 
| page_size | Default page size is 50. Default is 50. | Optional | 
| query | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 
| id | job template id. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-job-templates-list```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobTemplate": {
            "allow_simultaneous": false,
            "ask_credential_on_launch": false,
            "ask_diff_mode_on_launch": false,
            "ask_inventory_on_launch": false,
            "ask_job_type_on_launch": false,
            "ask_limit_on_launch": false,
            "ask_skip_tags_on_launch": false,
            "ask_tags_on_launch": false,
            "ask_variables_on_launch": false,
            "ask_verbosity_on_launch": false,
            "become_enabled": false,
            "created": "2019-11-19T11:53:43.446968Z",
            "credential": 1,
            "custom_virtualenv": null,
            "description": "",
            "diff_mode": false,
            "extra_vars": "",
            "force_handlers": false,
            "forks": 0,
            "host_config_key": "",
            "id": 5,
            "inventory": 1,
            "job_slice_count": 1,
            "job_tags": "",
            "job_type": "run",
            "last_job_failed": true,
            "last_job_run": "2021-01-04T16:14:32.445333Z",
            "limit": "",
            "modified": "2021-01-04T16:14:32.489714Z",
            "name": "Demo Job Template",
            "next_job_run": null,
            "playbook": "hello_world.yml",
            "project": 4,
            "skip_tags": "",
            "start_at_task": "",
            "status": "failed",
            "survey_enabled": false,
            "timeout": 0,
            "type": "job_template",
            "url": "/api/v2/job_templates/5/",
            "use_fact_cache": false,
            "vault_credential": null,
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|allow_simultaneous|ask_credential_on_launch|ask_diff_mode_on_launch|ask_inventory_on_launch|ask_job_type_on_launch|ask_limit_on_launch|ask_skip_tags_on_launch|ask_tags_on_launch|ask_variables_on_launch|ask_verbosity_on_launch|become_enabled|created|credential|custom_virtualenv|description|diff_mode|extra_vars|force_handlers|forks|host_config_key|id|inventory|job_slice_count|job_tags|job_type|last_job_failed|last_job_run|limit|modified|name|next_job_run|playbook|project|skip_tags|start_at_task|status|survey_enabled|timeout|type|url|use_fact_cache|vault_credential|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | false | false | false | false | false | false | false | false | false | false | 2019-11-19T11:53:43.446968Z | 1 |  |  | false |  | false | 0 |  | 5 | 1 | 1 |  | run | true | 2021-01-04T16:14:32.445333Z |  | 2021-01-04T16:14:32.489714Z | Demo Job Template |  | hello_world.yml | 4 |  |  | failed | false | 0 | job_template | /api/v2/job_templates/5/ | false |  | 0 |


### ansible-tower-credentials-list
***
Retrieve the list of credentials. If an id is given, retrive the specific one


#### Base Command

`ansible-tower-credentials-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | id of a specific credential. | Optional | 
| page | Number of page to retrieve. Default page number is 1. Default is 1. | Optional | 
| page_size | Default page size is 50. Default is 50. | Optional | 
| search | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-credentials-list```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Credential": {
            "created": "2019-11-19T11:53:43.220855Z",
            "credential_type": 1,
            "description": "",
            "id": 1,
            "inputs": {
                "username": "admin"
            },
            "modified": "2019-11-19T11:53:43.289192Z",
            "name": "Demo Credential",
            "organization": null,
            "type": "credential",
            "url": "/api/v2/credentials/1/"
        }
    }
}
```

#### Human Readable Output

>### Results
>|created|credential_type|description|id|inputs|modified|name|organization|type|url|
>|---|---|---|---|---|---|---|---|---|---|
>| 2019-11-19T11:53:43.220855Z | 1 |  | 1 | username: admin | 2019-11-19T11:53:43.289192Z | Demo Credential |  | credential | /api/v2/credentials/1/ |


### ansible-tower-job-launch
***
Launch job template


#### Base Command

`ansible-tower-job-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_template_id | job template id  to launch. | Required | 
| inventory_id | If the job template do not have an inventory to start,  select the inventory containing the host you want this job to manage. | Optional | 
| credentials_id | Credentials that allow Tower to access the node this job will be ran against. | Optional | 
| extra_variables | Command line variables pass to the playbook (json format). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Unknown | Job id | 
| AnsibleAWX.Job.status | Unknown | Job status | 


#### Command Example
```!ansible-tower-job-launch job_template_id=5```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "allow_simultaneous": false,
            "artifacts": {},
            "controller_node": "",
            "created": "2021-01-04T16:14:54.210852Z",
            "credential": 1,
            "description": "",
            "diff_mode": false,
            "elapsed": 0,
            "event_processing_finished": false,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": false,
            "finished": null,
            "force_handlers": false,
            "forks": 0,
            "id": 385,
            "ignored_fields": {},
            "instance_group": null,
            "inventory": 1,
            "job": 385,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_slice_count": 1,
            "job_slice_number": 0,
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-04T16:14:54.306298Z",
            "name": "Demo Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "start_at_task": "",
            "started": null,
            "status": "pending",
            "timeout": 0,
            "type": "job",
            "unified_job_template": 5,
            "url": "/api/v2/jobs/385/",
            "use_fact_cache": false,
            "vault_credential": null,
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Job 385 status pending
>|allow_simultaneous|created|credential|diff_mode|elapsed|event_processing_finished|extra_vars|failed|force_handlers|forks|id|inventory|job|job_slice_count|job_slice_number|job_template|job_type|launch_type|modified|name|playbook|project|status|timeout|type|unified_job_template|url|use_fact_cache|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-01-04T16:14:54.210852Z | 1 | false | 0.0 | false | {} | false | false | 0 | 385 | 1 | 385 | 1 | 0 | 5 | run | manual | 2021-01-04T16:14:54.306298Z | Demo Job Template | hello_world.yml | 4 | pending | 0 | job | 5 | /api/v2/jobs/385/ | false | 0 |


### ansible-tower-job-relaunch
***
Relaunch a job


#### Base Command

`ansible-tower-job-relaunch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id to relaunch. | Required | 
| relaunch_hosts | Which hosts to relaunch the job. Can be all the host or only the ones where the job failed. Possible values are: all, failed. Default is all. | Optional | 
| credentials_id | credential id. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-job-relaunch job_id=282```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "allow_simultaneous": false,
            "artifacts": {},
            "ask_credential_on_launch": false,
            "ask_diff_mode_on_launch": false,
            "ask_inventory_on_launch": false,
            "ask_job_type_on_launch": false,
            "ask_limit_on_launch": false,
            "ask_skip_tags_on_launch": false,
            "ask_tags_on_launch": false,
            "ask_variables_on_launch": false,
            "ask_verbosity_on_launch": false,
            "controller_node": "",
            "created": "2021-01-04T16:14:56.423397Z",
            "credential": 1,
            "description": "",
            "diff_mode": false,
            "elapsed": 0,
            "event_processing_finished": false,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": false,
            "finished": null,
            "force_handlers": false,
            "forks": 0,
            "id": 387,
            "instance_group": null,
            "inventory": 1,
            "job": 387,
            "job_args": "",
            "job_cwd": "",
            "job_env": {},
            "job_explanation": "",
            "job_slice_count": 1,
            "job_slice_number": 0,
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "relaunch",
            "limit": "",
            "modified": "2021-01-04T16:14:56.544638Z",
            "name": "Demo Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "start_at_task": "",
            "started": null,
            "status": "pending",
            "timeout": 0,
            "type": "job",
            "unified_job_template": 5,
            "url": "/api/v2/jobs/387/",
            "use_fact_cache": false,
            "vault_credential": null,
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Job 387 status pending
>|allow_simultaneous|created|credential|diff_mode|elapsed|event_processing_finished|extra_vars|failed|force_handlers|forks|id|inventory|job|job_slice_count|job_slice_number|job_template|job_type|launch_type|modified|name|playbook|project|status|timeout|type|unified_job_template|url|use_fact_cache|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-01-04T16:14:56.423397Z | 1 | false | 0.0 | false | {} | false | false | 0 | 387 | 1 | 387 | 1 | 0 | 5 | run | relaunch | 2021-01-04T16:14:56.544638Z | Demo Job Template | hello_world.yml | 4 | pending | 0 | job | 5 | /api/v2/jobs/387/ | false | 0 |


### ansible-tower-job-cancel
***
Cancel a pending or running job


#### Base Command

`ansible-tower-job-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id tp cancel. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### ansible-tower-job-stdout
***
Retrieve the stdout from running the given job


#### Base Command

`ansible-tower-job-stdout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.JobStdout.job_id | Unknown | Job id | 
| AnsibleAWX.JobStdout.content | Unknown | job content output | 


#### Command Example
```!ansible-tower-job-stdout job_id=348```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobStdout": {
            "content": "\n\nPLAY [Hello World Sample] ******************************************************\n\nTASK [Gathering Facts] *********************************************************\n\u001b[1;31mfatal: [check8]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname check8: Name or service not known\\\\r\\\\n\", \"unreachable\": true}\u001b[0m\n\u001b[0;32mok: [localhost]\u001b[0m\n\nTASK [Hello Message] ***********************************************************\n\u001b[0;32mok: [localhost] => {\u001b[0m\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\n\u001b[0;32m}\u001b[0m\n\nPLAY RECAP *********************************************************************\n\u001b[0;31mcheck8\u001b[0m                     : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \n\n",
            "job_id": "348",
            "range": {
                "absolute_end": 17,
                "end": 17,
                "start": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Job 348 output ### 
>
>
>
>PLAY [Hello World Sample] ******************************************************
>
>TASK [Gathering Facts] *********************************************************
>[1;31mfatal: [check8]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname check8: Name or service not known\\r\\n", "unreachable": true}[0m
>[0;32mok: [localhost][0m
>
>TASK [Hello Message] ***********************************************************
>[0;32mok: [localhost] => {[0m
>[0;32m    "msg": "Hello World!"[0m
>[0;32m}[0m
>
>PLAY RECAP *********************************************************************
>[0;31mcheck8[0m                     : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   
>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   
>
>


### ansible-tower-job-status
***
Retrieve job status


#### Base Command

`ansible-tower-job-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | job id status. | Required | 
| search | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Unknown | Job id | 
| AnsibleAWX.Job.status | Unknown | Job status | 


#### Command Example
```!ansible-tower-job-status job_id=282```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "allow_simultaneous": false,
            "artifacts": {},
            "ask_credential_on_launch": false,
            "ask_diff_mode_on_launch": false,
            "ask_inventory_on_launch": false,
            "ask_job_type_on_launch": false,
            "ask_limit_on_launch": false,
            "ask_skip_tags_on_launch": false,
            "ask_tags_on_launch": false,
            "ask_variables_on_launch": false,
            "ask_verbosity_on_launch": false,
            "controller_node": "",
            "created": "2020-12-30T16:12:05.529479Z",
            "credential": 1,
            "description": "",
            "diff_mode": false,
            "elapsed": 0,
            "event_processing_finished": true,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": true,
            "finished": "2020-12-30T16:12:08.434925Z",
            "force_handlers": false,
            "forks": 0,
            "host_status_counts": {},
            "id": 282,
            "instance_group": null,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_env": {},
            "job_explanation": "",
            "job_slice_count": 1,
            "job_slice_number": 0,
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2020-12-30T16:12:08.435262Z",
            "name": "Demo Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "playbook_counts": {
                "play_count": 0,
                "task_count": 0
            },
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "start_at_task": "",
            "started": null,
            "status": "canceled",
            "timeout": 0,
            "type": "job",
            "unified_job_template": 5,
            "url": "/api/v2/jobs/282/",
            "use_fact_cache": false,
            "vault_credential": null,
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Job 282 status canceled
>|allow_simultaneous|created|credential|diff_mode|elapsed|event_processing_finished|extra_vars|failed|finished|force_handlers|forks|id|inventory|job_slice_count|job_slice_number|job_template|job_type|launch_type|modified|name|playbook|playbook_counts|project|status|timeout|type|unified_job_template|url|use_fact_cache|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2020-12-30T16:12:05.529479Z | 1 | false | 0.0 | true | {} | true | 2020-12-30T16:12:08.434925Z | false | 0 | 282 | 1 | 1 | 0 | 5 | run | manual | 2020-12-30T16:12:08.435262Z | Demo Job Template | hello_world.yml | play_count: 0<br/>task_count: 0 | 4 | canceled | 0 | job | 5 | /api/v2/jobs/282/ | false | 0 |


### ansible-tower-job-events-list
***
Retrieve the list of job events.


#### Base Command

`ansible-tower-job-events-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | job event id. | Optional | 
| page | Number of page to retrieve. Default page number is 1. Default is 1. | Optional | 
| page_size | Default size is 50. Default is 50. | Optional | 
| search | Use the search query string parameter to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-job-events-list```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobEvents": [
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-20T15:27:19.104059Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 484,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 1,
                "job": 114,
                "modified": "2020-12-20T15:27:19.137215Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/1/",
                "uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-20T15:27:19.165403Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 2,
                "job": 114,
                "modified": "2020-12-20T15:27:19.184199Z",
                "parent": null,
                "parent_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/2/",
                "uuid": "0242ac11-0006-dfb8-315d-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-20T15:27:19.179387Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-dfb8-315d-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 3,
                "job": 114,
                "modified": "2020-12-20T15:27:19.193831Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/3/",
                "uuid": "0242ac11-0006-dfb8-315d-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-20T15:27:19.468399Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-dfb8-315d-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 4,
                "job": 114,
                "modified": "2020-12-20T15:27:19.485575Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-dfb8-315d-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/4/",
                "uuid": "82f2796c-a1e8-495c-a10f-76ca5bfcbbaf",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-20T15:27:26.242320Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-20",
                                "day": "20",
                                "epoch": "1608478040",
                                "hour": "15",
                                "iso8601": "2020-12-20T15:27:20Z",
                                "iso8601_basic": "20201220T152720280472",
                                "iso8601_basic_short": "20201220T152720",
                                "iso8601_micro": "2020-12-20T15:27:20.280545Z",
                                "minute": "27",
                                "month": "12",
                                "second": "20",
                                "time": "15:27:20",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Sunday",
                                "weekday_number": "0",
                                "weeknumber": "50",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 174,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1766,
                                    "used": 2119
                                },
                                "real": {
                                    "free": 174,
                                    "total": 3885,
                                    "used": 3711
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45443298,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365267,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150734,
                                    "inode_total": 25600000,
                                    "inode_used": 449266,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135748608,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443298,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365267,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150734,
                                    "inode_total": 25600000,
                                    "inode_used": 449266,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135748608,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443298,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365267,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150734,
                                    "inode_total": 25600000,
                                    "inode_used": 449266,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135748608,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443310,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365255,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150734,
                                    "inode_total": 25600000,
                                    "inode_used": 449266,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135797760,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34316178,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-dfb8-315d-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 5,
                "job": 114,
                "modified": "2020-12-20T15:27:26.267039Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-dfb8-315d-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/5/",
                "uuid": "c2211a59-9eb9-4db5-80c0-d59ddbaf8a15",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-20T15:27:26.275328Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-dfb8-315d-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 6,
                "job": 114,
                "modified": "2020-12-20T15:27:26.302687Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/6/",
                "uuid": "0242ac11-0006-dfb8-315d-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-20T15:27:26.304700Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 484,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-dfb8-315d-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-dfb8-315d-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 7,
                "job": 114,
                "modified": "2020-12-20T15:27:26.338249Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-dfb8-315d-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/7/",
                "uuid": "bcddde61-4b53-4b6c-b149-04f0ff38fff8",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-20T15:27:26.318986Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 484,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 8,
                "job": 114,
                "modified": "2020-12-20T15:27:26.370682Z",
                "parent": null,
                "parent_uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/8/",
                "uuid": "8509f423-4156-4c78-8828-c2d650a0e2a8",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-20T15:39:09.664293Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 714,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 9,
                "job": 117,
                "modified": "2020-12-20T15:39:09.694985Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/9/",
                "uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-20T15:39:09.726361Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 10,
                "job": 117,
                "modified": "2020-12-20T15:39:09.739767Z",
                "parent": null,
                "parent_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/10/",
                "uuid": "0242ac11-0006-52a6-60e5-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-20T15:39:09.743578Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-52a6-60e5-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 11,
                "job": 117,
                "modified": "2020-12-20T15:39:09.754049Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/11/",
                "uuid": "0242ac11-0006-52a6-60e5-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-20T15:39:09.885094Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-52a6-60e5-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 12,
                "job": 117,
                "modified": "2020-12-20T15:39:09.900657Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-52a6-60e5-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/12/",
                "uuid": "1eb38b2b-2435-4e2b-8070-ca21dbf01b35",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-20T15:39:16.714529Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-20",
                                "day": "20",
                                "epoch": "1608478750",
                                "hour": "15",
                                "iso8601": "2020-12-20T15:39:10Z",
                                "iso8601_basic": "20201220T153910763816",
                                "iso8601_basic_short": "20201220T153910",
                                "iso8601_micro": "2020-12-20T15:39:10.763889Z",
                                "minute": "39",
                                "month": "12",
                                "second": "10",
                                "time": "15:39:10",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Sunday",
                                "weekday_number": "0",
                                "weeknumber": "50",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 117,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1713,
                                    "used": 2172
                                },
                                "real": {
                                    "free": 117,
                                    "total": 3885,
                                    "used": 3768
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45443187,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365378,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150729,
                                    "inode_total": 25600000,
                                    "inode_used": 449271,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135293952,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443187,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365378,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150729,
                                    "inode_total": 25600000,
                                    "inode_used": 449271,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135293952,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443187,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365378,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150729,
                                    "inode_total": 25600000,
                                    "inode_used": 449271,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135293952,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443187,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365378,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150729,
                                    "inode_total": 25600000,
                                    "inode_used": 449271,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135293952,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34316889,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-52a6-60e5-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 13,
                "job": 117,
                "modified": "2020-12-20T15:39:16.736918Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-52a6-60e5-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/13/",
                "uuid": "b1e61a5b-8fd5-499d-869c-8303c081d9ad",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-20T15:39:16.751042Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-52a6-60e5-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 14,
                "job": 117,
                "modified": "2020-12-20T15:39:16.770665Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/14/",
                "uuid": "0242ac11-0006-52a6-60e5-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-20T15:39:16.779042Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 714,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-52a6-60e5-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-52a6-60e5-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 15,
                "job": 117,
                "modified": "2020-12-20T15:39:16.797575Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-52a6-60e5-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/15/",
                "uuid": "417ce730-7992-45bc-8887-a6abbf2c1b2e",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-20T15:39:16.799913Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 714,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 16,
                "job": 117,
                "modified": "2020-12-20T15:39:16.811357Z",
                "parent": null,
                "parent_uuid": "b1d04184-4686-4a6f-8953-74cef891f4e3",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/16/",
                "uuid": "123fb7ed-6878-4fd0-84c7-a03c92852b8c",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-20T15:40:26.636051Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 944,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 17,
                "job": 120,
                "modified": "2020-12-20T15:40:26.665310Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/17/",
                "uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-20T15:40:26.693355Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 18,
                "job": 120,
                "modified": "2020-12-20T15:40:26.703016Z",
                "parent": null,
                "parent_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/18/",
                "uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-20T15:40:26.708715Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-d2c4-69c4-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 19,
                "job": 120,
                "modified": "2020-12-20T15:40:26.722194Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/19/",
                "uuid": "0242ac11-0006-d2c4-69c4-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-20T15:40:26.836604Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-d2c4-69c4-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 20,
                "job": 120,
                "modified": "2020-12-20T15:40:26.856232Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-d2c4-69c4-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/20/",
                "uuid": "2f2d330b-38f6-4995-b5f1-b5c794a80526",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-20T15:40:33.588831Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-20",
                                "day": "20",
                                "epoch": "1608478827",
                                "hour": "15",
                                "iso8601": "2020-12-20T15:40:27Z",
                                "iso8601_basic": "20201220T154027737635",
                                "iso8601_basic_short": "20201220T154027",
                                "iso8601_micro": "2020-12-20T15:40:27.737695Z",
                                "minute": "40",
                                "month": "12",
                                "second": "27",
                                "time": "15:40:27",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Sunday",
                                "weekday_number": "0",
                                "weeknumber": "50",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 104,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1592,
                                    "used": 2293
                                },
                                "real": {
                                    "free": 104,
                                    "total": 3885,
                                    "used": 3781
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45443145,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365420,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150726,
                                    "inode_total": 25600000,
                                    "inode_used": 449274,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135121920,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443145,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365420,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150726,
                                    "inode_total": 25600000,
                                    "inode_used": 449274,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135121920,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443145,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365420,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150726,
                                    "inode_total": 25600000,
                                    "inode_used": 449274,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135121920,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443145,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365420,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150726,
                                    "inode_total": 25600000,
                                    "inode_used": 449274,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186135121920,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34316966,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-d2c4-69c4-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 21,
                "job": 120,
                "modified": "2020-12-20T15:40:33.612836Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-d2c4-69c4-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/21/",
                "uuid": "d28efbc3-b702-4a58-a374-978fb2939b95",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-20T15:40:33.620349Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-d2c4-69c4-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 22,
                "job": 120,
                "modified": "2020-12-20T15:40:33.647506Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/22/",
                "uuid": "0242ac11-0006-d2c4-69c4-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-20T15:40:33.660864Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 944,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 23,
                "job": 120,
                "modified": "2020-12-20T15:40:33.678193Z",
                "parent": null,
                "parent_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/23/",
                "uuid": "17888938-953b-4d5a-bd5f-481af006603e",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-20T15:40:33.650819Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 944,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-d2c4-69c4-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "21742f14-1e3b-4705-9cd3-f476f98afca9",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-d2c4-69c4-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 24,
                "job": 120,
                "modified": "2020-12-20T15:40:33.689699Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-d2c4-69c4-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/24/",
                "uuid": "e96e217d-4829-4c07-999f-84a78fb5bfe3",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-20T15:45:01.072980Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 1174,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 25,
                "job": 123,
                "modified": "2020-12-20T15:45:01.105605Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/25/",
                "uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-20T15:45:01.132351Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 26,
                "job": 123,
                "modified": "2020-12-20T15:45:01.142434Z",
                "parent": null,
                "parent_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/26/",
                "uuid": "0242ac11-0006-8dae-a802-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-20T15:45:01.148593Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-8dae-a802-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 27,
                "job": 123,
                "modified": "2020-12-20T15:45:01.161198Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-8dae-a802-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/27/",
                "uuid": "0242ac11-0006-8dae-a802-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-20T15:45:01.324692Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-8dae-a802-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 28,
                "job": 123,
                "modified": "2020-12-20T15:45:01.343824Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-8dae-a802-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/28/",
                "uuid": "4177b88c-1016-421e-ac85-55d37d67befb",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-20T15:45:08.028043Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-20",
                                "day": "20",
                                "epoch": "1608479102",
                                "hour": "15",
                                "iso8601": "2020-12-20T15:45:02Z",
                                "iso8601_basic": "20201220T154502175834",
                                "iso8601_basic_short": "20201220T154502",
                                "iso8601_micro": "2020-12-20T15:45:02.175922Z",
                                "minute": "45",
                                "month": "12",
                                "second": "02",
                                "time": "15:45:02",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Sunday",
                                "weekday_number": "0",
                                "weeknumber": "50",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 118,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1584,
                                    "used": 2301
                                },
                                "real": {
                                    "free": 118,
                                    "total": 3885,
                                    "used": 3767
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45443085,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365480,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150722,
                                    "inode_total": 25600000,
                                    "inode_used": 449278,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186134876160,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443085,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365480,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150722,
                                    "inode_total": 25600000,
                                    "inode_used": 449278,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186134876160,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443085,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365480,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150722,
                                    "inode_total": 25600000,
                                    "inode_used": 449278,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186134876160,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45443085,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5365480,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150722,
                                    "inode_total": 25600000,
                                    "inode_used": 449278,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186134876160,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34317240,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-8dae-a802-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 29,
                "job": 123,
                "modified": "2020-12-20T15:45:08.051138Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-8dae-a802-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/29/",
                "uuid": "53c38d4b-06f9-477d-b911-fe6b27f7509d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-20T15:45:08.065324Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-8dae-a802-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 30,
                "job": 123,
                "modified": "2020-12-20T15:45:08.080849Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-8dae-a802-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/30/",
                "uuid": "0242ac11-0006-8dae-a802-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-20T15:45:08.105432Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 1174,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 31,
                "job": 123,
                "modified": "2020-12-20T15:45:08.115925Z",
                "parent": null,
                "parent_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/31/",
                "uuid": "5fe1c5f7-04db-4888-9a51-b5251bf0bbfe",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-20T15:45:08.097415Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1174,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-8dae-a802-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "332f1315-4fa6-47ec-8282-66c6c224c26e",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-8dae-a802-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 32,
                "job": 123,
                "modified": "2020-12-20T15:45:08.126780Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-8dae-a802-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/32/",
                "uuid": "6e306fb5-547a-4b6d-9566-10912d7f6401",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-21T09:52:10.157175Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 1404,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 33,
                "job": 126,
                "modified": "2020-12-21T09:52:10.184226Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/33/",
                "uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-21T09:52:10.214671Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 34,
                "job": 126,
                "modified": "2020-12-21T09:52:10.224963Z",
                "parent": null,
                "parent_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/34/",
                "uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-21T09:52:10.228399Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-9c79-d6b0-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 35,
                "job": 126,
                "modified": "2020-12-21T09:52:10.243743Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/35/",
                "uuid": "0242ac11-0006-9c79-d6b0-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-21T09:52:10.395481Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-9c79-d6b0-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 36,
                "job": 126,
                "modified": "2020-12-21T09:52:10.410222Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-9c79-d6b0-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/36/",
                "uuid": "9d7a21c9-8cc9-429a-bc0f-0426563dda83",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-21T09:52:17.179687Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-21",
                                "day": "21",
                                "epoch": "1608544331",
                                "hour": "09",
                                "iso8601": "2020-12-21T09:52:11Z",
                                "iso8601_basic": "20201221T095211272402",
                                "iso8601_basic_short": "20201221T095211",
                                "iso8601_micro": "2020-12-21T09:52:11.272462Z",
                                "minute": "52",
                                "month": "12",
                                "second": "11",
                                "time": "09:52:11",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Monday",
                                "weekday_number": "1",
                                "weeknumber": "51",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 118,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1519,
                                    "used": 2366
                                },
                                "real": {
                                    "free": 118,
                                    "total": 3885,
                                    "used": 3767
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45437695,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370870,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150718,
                                    "inode_total": 25600000,
                                    "inode_used": 449282,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112798720,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437695,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370870,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150718,
                                    "inode_total": 25600000,
                                    "inode_used": 449282,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112798720,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437695,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370870,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150718,
                                    "inode_total": 25600000,
                                    "inode_used": 449282,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112798720,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437696,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370869,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150718,
                                    "inode_total": 25600000,
                                    "inode_used": 449282,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112802816,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34382469,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-9c79-d6b0-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 37,
                "job": 126,
                "modified": "2020-12-21T09:52:17.204053Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-9c79-d6b0-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/37/",
                "uuid": "b7f66d93-42c4-48b9-87fa-a262dc5d2385",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-21T09:52:17.213976Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-9c79-d6b0-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 38,
                "job": 126,
                "modified": "2020-12-21T09:52:17.236338Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/38/",
                "uuid": "0242ac11-0006-9c79-d6b0-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-21T09:52:17.254103Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 1404,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 39,
                "job": 126,
                "modified": "2020-12-21T09:52:17.266470Z",
                "parent": null,
                "parent_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/39/",
                "uuid": "e868c372-e856-44a2-be5e-d72a4de4af57",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-21T09:52:17.245439Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1404,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-9c79-d6b0-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-9c79-d6b0-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 40,
                "job": 126,
                "modified": "2020-12-21T09:52:17.269648Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-9c79-d6b0-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/40/",
                "uuid": "c17d3b2d-bfc6-4fc1-a7c1-485536896a40",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-21T10:04:45.419906Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 1634,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 41,
                "job": 129,
                "modified": "2020-12-21T10:04:45.446762Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/41/",
                "uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-21T10:04:45.477597Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 42,
                "job": 129,
                "modified": "2020-12-21T10:04:45.487364Z",
                "parent": null,
                "parent_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/42/",
                "uuid": "0242ac11-0006-819d-00d7-000000000007",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 3,
                "created": "2020-12-21T10:04:45.493322Z",
                "end_line": 4,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Gathering Facts",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-819d-00d7-00000000000d"
                },
                "event_display": "Task Started (Gathering Facts)",
                "event_level": 2,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 43,
                "job": 129,
                "modified": "2020-12-21T10:04:45.503462Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-819d-00d7-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 2,
                "stdout": "\r\nTASK [Gathering Facts] *********************************************************",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/43/",
                "uuid": "0242ac11-0006-819d-00d7-00000000000d",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 4,
                "created": "2020-12-21T10:04:45.631816Z",
                "end_line": 5,
                "event": "runner_on_unreachable",
                "event_data": {
                    "host": "test-host",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "remote_addr": "test-host",
                    "res": {
                        "changed": false,
                        "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n",
                        "unreachable": true
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-819d-00d7-00000000000d"
                },
                "event_display": "Host Unreachable",
                "event_level": 3,
                "failed": true,
                "host": null,
                "host_name": "test-host",
                "id": 44,
                "job": 129,
                "modified": "2020-12-21T10:04:45.647266Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-819d-00d7-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 4,
                "stdout": "\u001b[1;31mfatal: [test-host]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\\r\\n\", \"unreachable\": true}\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/44/",
                "uuid": "d1a4b700-e388-4cc1-8af9-d8f7ff67f13a",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 5,
                "created": "2020-12-21T10:04:52.450794Z",
                "end_line": 6,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_parsed": true,
                        "_ansible_verbose_override": true,
                        "ansible_facts": {
                            "ansible_all_ipv4_addresses": [
                                "172.17.0.6"
                            ],
                            "ansible_all_ipv6_addresses": [],
                            "ansible_apparmor": {
                                "status": "disabled"
                            },
                            "ansible_architecture": "x86_64",
                            "ansible_bios_date": "10/16/2017",
                            "ansible_bios_version": "1.0",
                            "ansible_cmdline": {
                                "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws",
                                "console": "ttyS0",
                                "nvme.io_timeout": "4294967295",
                                "ro": true,
                                "root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95"
                            },
                            "ansible_date_time": {
                                "date": "2020-12-21",
                                "day": "21",
                                "epoch": "1608545086",
                                "hour": "10",
                                "iso8601": "2020-12-21T10:04:46Z",
                                "iso8601_basic": "20201221T100446498844",
                                "iso8601_basic_short": "20201221T100446",
                                "iso8601_micro": "2020-12-21T10:04:46.498951Z",
                                "minute": "04",
                                "month": "12",
                                "second": "46",
                                "time": "10:04:46",
                                "tz": "UTC",
                                "tz_offset": "+0000",
                                "weekday": "Monday",
                                "weekday_number": "1",
                                "weeknumber": "51",
                                "year": "2020"
                            },
                            "ansible_default_ipv4": {
                                "address": "172.17.0.6",
                                "alias": "eth0",
                                "broadcast": "172.17.255.255",
                                "gateway": "172.17.0.1",
                                "interface": "eth0",
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "netmask": "255.255.0.0",
                                "network": "172.17.0.0",
                                "type": "ether"
                            },
                            "ansible_default_ipv6": {},
                            "ansible_device_links": {
                                "ids": {},
                                "labels": {},
                                "masters": {},
                                "uuids": {}
                            },
                            "ansible_devices": {
                                "loop0": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "66200",
                                    "sectorsize": "512",
                                    "size": "32.32 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop2": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "200416",
                                    "sectorsize": "512",
                                    "size": "97.86 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop3": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113384",
                                    "sectorsize": "512",
                                    "size": "55.36 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop4": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "113424",
                                    "sectorsize": "512",
                                    "size": "55.38 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop5": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "57544",
                                    "sectorsize": "512",
                                    "size": "28.10 MB",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop6": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "4096",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "loop7": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": null,
                                    "partitions": {},
                                    "removable": "0",
                                    "rotational": "1",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "0",
                                    "sectorsize": "512",
                                    "size": "0.00 Bytes",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                },
                                "nvme0n1": {
                                    "holders": [],
                                    "host": "",
                                    "links": {
                                        "ids": [],
                                        "labels": [],
                                        "masters": [],
                                        "uuids": []
                                    },
                                    "model": "Amazon Elastic Block Store",
                                    "partitions": {
                                        "nvme0n1p1": {
                                            "holders": [],
                                            "links": {
                                                "ids": [],
                                                "labels": [],
                                                "masters": [],
                                                "uuids": []
                                            },
                                            "sectors": "419428319",
                                            "sectorsize": 512,
                                            "size": "200.00 GB",
                                            "start": "2048",
                                            "uuid": null
                                        }
                                    },
                                    "removable": "0",
                                    "rotational": "0",
                                    "sas_address": null,
                                    "sas_device_handle": null,
                                    "scheduler_mode": "none",
                                    "sectors": "419430400",
                                    "sectorsize": "512",
                                    "size": "200.00 GB",
                                    "support_discard": "0",
                                    "vendor": null,
                                    "virtual": 1
                                }
                            },
                            "ansible_distribution": "CentOS",
                            "ansible_distribution_file_parsed": true,
                            "ansible_distribution_file_path": "/etc/redhat-release",
                            "ansible_distribution_file_variety": "RedHat",
                            "ansible_distribution_major_version": "7",
                            "ansible_distribution_release": "Core",
                            "ansible_distribution_version": "7.5.1804",
                            "ansible_dns": {
                                "nameservers": [
                                    "172.31.0.2"
                                ],
                                "search": [
                                    "eu-central-1.compute.internal"
                                ]
                            },
                            "ansible_domain": "",
                            "ansible_effective_group_id": 0,
                            "ansible_effective_user_id": 0,
                            "ansible_eth0": {
                                "active": true,
                                "device": "eth0",
                                "ipv4": {
                                    "address": "172.17.0.6",
                                    "broadcast": "172.17.255.255",
                                    "netmask": "255.255.0.0",
                                    "network": "172.17.0.0"
                                },
                                "macaddress": "02:42:ac:11:00:06",
                                "mtu": 1500,
                                "promisc": false,
                                "speed": 10000,
                                "type": "ether"
                            },
                            "ansible_fips": false,
                            "ansible_form_factor": "Other",
                            "ansible_fqdn": "awx",
                            "ansible_hostname": "awx",
                            "ansible_interfaces": [
                                "lo",
                                "eth0"
                            ],
                            "ansible_is_chroot": false,
                            "ansible_iscsi_iqn": "",
                            "ansible_kernel": "4.15.0-1054-aws",
                            "ansible_lo": {
                                "active": true,
                                "device": "lo",
                                "ipv4": {
                                    "address": "127.0.0.1",
                                    "broadcast": "host",
                                    "netmask": "255.0.0.0",
                                    "network": "127.0.0.0"
                                },
                                "mtu": 65536,
                                "promisc": false,
                                "type": "loopback"
                            },
                            "ansible_local": {},
                            "ansible_lsb": {},
                            "ansible_machine": "x86_64",
                            "ansible_memfree_mb": 116,
                            "ansible_memory_mb": {
                                "nocache": {
                                    "free": 1515,
                                    "used": 2370
                                },
                                "real": {
                                    "free": 116,
                                    "total": 3885,
                                    "used": 3769
                                },
                                "swap": {
                                    "cached": 0,
                                    "free": 0,
                                    "total": 0,
                                    "used": 0
                                }
                            },
                            "ansible_memtotal_mb": 3885,
                            "ansible_mounts": [
                                {
                                    "block_available": 45437588,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370977,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150715,
                                    "inode_total": 25600000,
                                    "inode_used": 449285,
                                    "mount": "/etc/resolv.conf",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112360448,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437588,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370977,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150715,
                                    "inode_total": 25600000,
                                    "inode_used": 449285,
                                    "mount": "/etc/hostname",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112360448,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437588,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370977,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150715,
                                    "inode_total": 25600000,
                                    "inode_used": 449285,
                                    "mount": "/etc/hosts",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112360448,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                },
                                {
                                    "block_available": 45437588,
                                    "block_size": 4096,
                                    "block_total": 50808565,
                                    "block_used": 5370977,
                                    "device": "/dev/nvme0n1p1",
                                    "fstype": "ext4",
                                    "inode_available": 25150715,
                                    "inode_total": 25600000,
                                    "inode_used": 449285,
                                    "mount": "/var/lib/nginx",
                                    "options": "rw,relatime,discard,data=ordered,bind",
                                    "size_available": 186112360448,
                                    "size_total": 208111882240,
                                    "uuid": "N/A"
                                }
                            ],
                            "ansible_nodename": "awx",
                            "ansible_os_family": "RedHat",
                            "ansible_pkg_mgr": "yum",
                            "ansible_processor": [
                                "0",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz",
                                "1",
                                "GenuineIntel",
                                "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
                            ],
                            "ansible_processor_cores": 1,
                            "ansible_processor_count": 1,
                            "ansible_processor_threads_per_core": 2,
                            "ansible_processor_vcpus": 2,
                            "ansible_product_name": "t3.medium",
                            "ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859",
                            "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859",
                            "ansible_product_version": "NA",
                            "ansible_python": {
                                "executable": "/usr/bin/python",
                                "has_sslcontext": true,
                                "type": "CPython",
                                "version": {
                                    "major": 2,
                                    "micro": 5,
                                    "minor": 7,
                                    "releaselevel": "final",
                                    "serial": 0
                                },
                                "version_info": [
                                    2,
                                    7,
                                    5,
                                    "final",
                                    0
                                ]
                            },
                            "ansible_python_version": "2.7.5",
                            "ansible_real_group_id": 0,
                            "ansible_real_user_id": 0,
                            "ansible_selinux": {
                                "status": "disabled"
                            },
                            "ansible_selinux_python_present": true,
                            "ansible_service_mgr": "tini",
                            "ansible_swapfree_mb": 0,
                            "ansible_swaptotal_mb": 0,
                            "ansible_system": "Linux",
                            "ansible_system_capabilities": [
                                "cap_chown",
                                "cap_dac_override",
                                "cap_fowner",
                                "cap_fsetid",
                                "cap_kill",
                                "cap_setgid",
                                "cap_setuid",
                                "cap_setpcap",
                                "cap_net_bind_service",
                                "cap_net_raw",
                                "cap_sys_chroot",
                                "cap_mknod",
                                "cap_audit_write",
                                "cap_setfcap+eip"
                            ],
                            "ansible_system_capabilities_enforced": "True",
                            "ansible_system_vendor": "Amazon EC2",
                            "ansible_uptime_seconds": 34383224,
                            "ansible_user_dir": "/root",
                            "ansible_user_gecos": "root",
                            "ansible_user_gid": 0,
                            "ansible_user_id": "root",
                            "ansible_user_shell": "/bin/bash",
                            "ansible_user_uid": 0,
                            "ansible_userspace_architecture": "x86_64",
                            "ansible_userspace_bits": "64",
                            "ansible_virtualization_role": "guest",
                            "ansible_virtualization_type": "docker",
                            "gather_subset": [
                                "all"
                            ],
                            "module_setup": true
                        },
                        "changed": false,
                        "invocation": {
                            "module_args": {
                                "fact_path": "/etc/ansible/facts.d",
                                "filter": "*",
                                "gather_subset": [
                                    "all"
                                ],
                                "gather_timeout": 10
                            }
                        }
                    },
                    "task": "Gathering Facts",
                    "task_action": "setup",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:1",
                    "task_uuid": "0242ac11-0006-819d-00d7-00000000000d"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 45,
                "job": 129,
                "modified": "2020-12-21T10:04:52.481737Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-819d-00d7-00000000000d",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 5,
                "stdout": "\u001b[0;32mok: [localhost]\u001b[0m",
                "task": "Gathering Facts",
                "type": "job_event",
                "url": "/api/v2/job_events/45/",
                "uuid": "1109f095-ede0-4162-88ab-bffea8382f8e",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 6,
                "created": "2020-12-21T10:04:52.484118Z",
                "end_line": 8,
                "event": "playbook_on_task_start",
                "event_data": {
                    "is_conditional": false,
                    "name": "Hello Message",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-819d-00d7-000000000009"
                },
                "event_display": "Task Started (Hello Message)",
                "event_level": 2,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 46,
                "job": 129,
                "modified": "2020-12-21T10:04:52.494760Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-819d-00d7-000000000007",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 6,
                "stdout": "\r\nTASK [Hello Message] ***********************************************************",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/46/",
                "uuid": "0242ac11-0006-819d-00d7-000000000009",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 7,
                "created": "2020-12-21T10:04:52.518281Z",
                "end_line": 11,
                "event": "runner_on_ok",
                "event_data": {
                    "event_loop": null,
                    "host": "localhost",
                    "pid": 1634,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-819d-00d7-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "remote_addr": "localhost",
                    "res": {
                        "_ansible_no_log": false,
                        "_ansible_verbose_always": true,
                        "changed": false,
                        "msg": "Hello World!"
                    },
                    "task": "Hello Message",
                    "task_action": "debug",
                    "task_args": "",
                    "task_path": "/var/lib/awx/projects/_4__demo_project/hello_world.yml:4",
                    "task_uuid": "0242ac11-0006-819d-00d7-000000000009"
                },
                "event_display": "Host OK",
                "event_level": 3,
                "failed": false,
                "host": 1,
                "host_name": "localhost",
                "id": 47,
                "job": 129,
                "modified": "2020-12-21T10:04:52.539012Z",
                "parent": null,
                "parent_uuid": "0242ac11-0006-819d-00d7-000000000009",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 8,
                "stdout": "\u001b[0;32mok: [localhost] => {\u001b[0m\r\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\r\n\u001b[0;32m}\u001b[0m",
                "task": "Hello Message",
                "type": "job_event",
                "url": "/api/v2/job_events/47/",
                "uuid": "32e073d0-325c-44b0-b17f-401304d4d60f",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 8,
                "created": "2020-12-21T10:04:52.525838Z",
                "end_line": 16,
                "event": "playbook_on_stats",
                "event_data": {
                    "changed": {},
                    "dark": {
                        "test-host": 1
                    },
                    "failures": {},
                    "ok": {
                        "localhost": 2
                    },
                    "pid": 1634,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                    "processed": {
                        "localhost": 1,
                        "test-host": 1
                    },
                    "skipped": {}
                },
                "event_display": "Playbook Complete",
                "event_level": 1,
                "failed": true,
                "host": null,
                "host_name": "",
                "id": 48,
                "job": 129,
                "modified": "2020-12-21T10:04:52.551570Z",
                "parent": null,
                "parent_uuid": "c969af97-43b7-4d2a-915a-0c7548281637",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 11,
                "stdout": "\r\nPLAY RECAP *********************************************************************\r\n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \r\n\u001b[0;31mtest-host\u001b[0m                  : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \r\n",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/48/",
                "uuid": "9365dfd3-d7a0-47cf-9134-b2c86ab9dda5",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-21T11:34:38.780915Z",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_data": {
                    "pid": 1864,
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "ada585de-f207-445d-b0d4-1d4d81364f0e"
                },
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 49,
                "job": 132,
                "modified": "2020-12-21T11:34:38.811671Z",
                "parent": null,
                "parent_uuid": "",
                "play": "",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/49/",
                "uuid": "ada585de-f207-445d-b0d4-1d4d81364f0e",
                "verbosity": 0
            },
            {
                "changed": false,
                "counter": 2,
                "created": "2020-12-21T11:34:38.836729Z",
                "end_line": 2,
                "event": "playbook_on_play_start",
                "event_data": {
                    "name": "Hello World Sample",
                    "pattern": "all",
                    "pid": 1864,
                    "play": "Hello World Sample",
                    "play_pattern": "all",
                    "play_uuid": "0242ac11-0006-c6bb-f8cd-000000000007",
                    "playbook": "hello_world.yml",
                    "playbook_uuid": "ada585de-f207-445d-b0d4-1d4d81364f0e"
                },
                "event_display": "Play Started (Hello World Sample)",
                "event_level": 1,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 50,
                "job": 132,
                "modified": "2020-12-21T11:34:38.851842Z",
                "parent": null,
                "parent_uuid": "ada585de-f207-445d-b0d4-1d4d81364f0e",
                "play": "Hello World Sample",
                "playbook": "hello_world.yml",
                "role": "",
                "start_line": 0,
                "stdout": "\r\nPLAY [Hello World Sample] ******************************************************",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/50/",
                "uuid": "0242ac11-0006-c6bb-f8cd-000000000007",
                "verbosity": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|changed|counter|created|end_line|event|event_data|event_display|event_level|failed|host|host_name|id|job|modified|parent_uuid|play|playbook|start_line|stdout|task|type|url|uuid|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 1 | 2020-12-20T15:27:19.104059Z | 0 | playbook_on_start | pid: 484<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 1 | 114 | 2020-12-20T15:27:19.137215Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/1/ | 331e9ca5-56e2-4c2e-b77c-40fef9b95502 | 0 |
>| false | 2 | 2020-12-20T15:27:19.165403Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 2 | 114 | 2020-12-20T15:27:19.184199Z | 331e9ca5-56e2-4c2e-b77c-40fef9b95502 | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/2/ | 0242ac11-0006-dfb8-315d-000000000007 | 0 |
>| false | 3 | 2020-12-20T15:27:19.179387Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-dfb8-315d-00000000000d<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 3 | 114 | 2020-12-20T15:27:19.193831Z | 0242ac11-0006-dfb8-315d-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/3/ | 0242ac11-0006-dfb8-315d-00000000000d | 0 |
>| false | 4 | 2020-12-20T15:27:19.468399Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>task_uuid: 0242ac11-0006-dfb8-315d-00000000000d<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 4 | 114 | 2020-12-20T15:27:19.485575Z | 0242ac11-0006-dfb8-315d-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/4/ | 82f2796c-a1e8-495c-a10f-76ca5bfcbbaf | 0 |
>| false | 5 | 2020-12-20T15:27:26.242320Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 174, "used": 3711}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2119, "free": 1766}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "0", "iso8601_basic_short": "20201220T152720", "tz": "UTC", "weeknumber": "50", "hour": "15", "year": "2020", "minute": "27", "tz_offset": "+0000", "month": "12", "second": "20", "iso8601_micro": "2020-12-20T15:27:20.280545Z", "weekday": "Sunday", "time": "15:27:20", "date": "2020-12-20", "epoch": "1608478040", "iso8601": "2020-12-20T15:27:20Z", "day": "20", "iso8601_basic": "20201220T152720280472"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 174, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34316178, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5365267, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45443298, "size_available": 186135748608, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150734, "device": "/dev/nvme0n1p1", "inode_used": 449266, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365267, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45443298, "size_available": 186135748608, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150734, "device": "/dev/nvme0n1p1", "inode_used": 449266, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365267, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45443298, "size_available": 186135748608, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150734, "device": "/dev/nvme0n1p1", "inode_used": 449266, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365255, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45443310, "size_available": 186135797760, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150734, "device": "/dev/nvme0n1p1", "inode_used": 449266, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>task_uuid: 0242ac11-0006-dfb8-315d-00000000000d<br/>event_loop: null<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 5 | 114 | 2020-12-20T15:27:26.267039Z | 0242ac11-0006-dfb8-315d-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/5/ | c2211a59-9eb9-4db5-80c0-d59ddbaf8a15 | 0 |
>| false | 6 | 2020-12-20T15:27:26.275328Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-dfb8-315d-000000000009<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 6 | 114 | 2020-12-20T15:27:26.302687Z | 0242ac11-0006-dfb8-315d-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/6/ | 0242ac11-0006-dfb8-315d-000000000009 | 0 |
>| false | 7 | 2020-12-20T15:27:26.304700Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 484<br/>play_uuid: 0242ac11-0006-dfb8-315d-000000000007<br/>task_uuid: 0242ac11-0006-dfb8-315d-000000000009<br/>event_loop: null<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 7 | 114 | 2020-12-20T15:27:26.338249Z | 0242ac11-0006-dfb8-315d-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/7/ | bcddde61-4b53-4b6c-b149-04f0ff38fff8 | 0 |
>| false | 8 | 2020-12-20T15:27:26.318986Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 484<br/>dark: {"test-host": 1}<br/>playbook_uuid: 331e9ca5-56e2-4c2e-b77c-40fef9b95502<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 8 | 114 | 2020-12-20T15:27:26.370682Z | 331e9ca5-56e2-4c2e-b77c-40fef9b95502 |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/8/ | 8509f423-4156-4c78-8828-c2d650a0e2a8 | 0 |
>| false | 1 | 2020-12-20T15:39:09.664293Z | 0 | playbook_on_start | pid: 714<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 9 | 117 | 2020-12-20T15:39:09.694985Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/9/ | b1d04184-4686-4a6f-8953-74cef891f4e3 | 0 |
>| false | 2 | 2020-12-20T15:39:09.726361Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 10 | 117 | 2020-12-20T15:39:09.739767Z | b1d04184-4686-4a6f-8953-74cef891f4e3 | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/10/ | 0242ac11-0006-52a6-60e5-000000000007 | 0 |
>| false | 3 | 2020-12-20T15:39:09.743578Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-52a6-60e5-00000000000d<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 11 | 117 | 2020-12-20T15:39:09.754049Z | 0242ac11-0006-52a6-60e5-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/11/ | 0242ac11-0006-52a6-60e5-00000000000d | 0 |
>| false | 4 | 2020-12-20T15:39:09.885094Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>task_uuid: 0242ac11-0006-52a6-60e5-00000000000d<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 12 | 117 | 2020-12-20T15:39:09.900657Z | 0242ac11-0006-52a6-60e5-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/12/ | 1eb38b2b-2435-4e2b-8070-ca21dbf01b35 | 0 |
>| false | 5 | 2020-12-20T15:39:16.714529Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 117, "used": 3768}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2172, "free": 1713}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "0", "iso8601_basic_short": "20201220T153910", "tz": "UTC", "weeknumber": "50", "hour": "15", "year": "2020", "minute": "39", "tz_offset": "+0000", "month": "12", "second": "10", "iso8601_micro": "2020-12-20T15:39:10.763889Z", "weekday": "Sunday", "time": "15:39:10", "date": "2020-12-20", "epoch": "1608478750", "iso8601": "2020-12-20T15:39:10Z", "day": "20", "iso8601_basic": "20201220T153910763816"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 117, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34316889, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5365378, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45443187, "size_available": 186135293952, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150729, "device": "/dev/nvme0n1p1", "inode_used": 449271, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365378, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45443187, "size_available": 186135293952, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150729, "device": "/dev/nvme0n1p1", "inode_used": 449271, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365378, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45443187, "size_available": 186135293952, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150729, "device": "/dev/nvme0n1p1", "inode_used": 449271, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365378, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45443187, "size_available": 186135293952, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150729, "device": "/dev/nvme0n1p1", "inode_used": 449271, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>task_uuid: 0242ac11-0006-52a6-60e5-00000000000d<br/>event_loop: null<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 13 | 117 | 2020-12-20T15:39:16.736918Z | 0242ac11-0006-52a6-60e5-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/13/ | b1e61a5b-8fd5-499d-869c-8303c081d9ad | 0 |
>| false | 6 | 2020-12-20T15:39:16.751042Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-52a6-60e5-000000000009<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 14 | 117 | 2020-12-20T15:39:16.770665Z | 0242ac11-0006-52a6-60e5-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/14/ | 0242ac11-0006-52a6-60e5-000000000009 | 0 |
>| false | 7 | 2020-12-20T15:39:16.779042Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 714<br/>play_uuid: 0242ac11-0006-52a6-60e5-000000000007<br/>task_uuid: 0242ac11-0006-52a6-60e5-000000000009<br/>event_loop: null<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 15 | 117 | 2020-12-20T15:39:16.797575Z | 0242ac11-0006-52a6-60e5-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/15/ | 417ce730-7992-45bc-8887-a6abbf2c1b2e | 0 |
>| false | 8 | 2020-12-20T15:39:16.799913Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 714<br/>dark: {"test-host": 1}<br/>playbook_uuid: b1d04184-4686-4a6f-8953-74cef891f4e3<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 16 | 117 | 2020-12-20T15:39:16.811357Z | b1d04184-4686-4a6f-8953-74cef891f4e3 |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/16/ | 123fb7ed-6878-4fd0-84c7-a03c92852b8c | 0 |
>| false | 1 | 2020-12-20T15:40:26.636051Z | 0 | playbook_on_start | pid: 944<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 17 | 120 | 2020-12-20T15:40:26.665310Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/17/ | 21742f14-1e3b-4705-9cd3-f476f98afca9 | 0 |
>| false | 2 | 2020-12-20T15:40:26.693355Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 18 | 120 | 2020-12-20T15:40:26.703016Z | 21742f14-1e3b-4705-9cd3-f476f98afca9 | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/18/ | 0242ac11-0006-d2c4-69c4-000000000007 | 0 |
>| false | 3 | 2020-12-20T15:40:26.708715Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-d2c4-69c4-00000000000d<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 19 | 120 | 2020-12-20T15:40:26.722194Z | 0242ac11-0006-d2c4-69c4-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/19/ | 0242ac11-0006-d2c4-69c4-00000000000d | 0 |
>| false | 4 | 2020-12-20T15:40:26.836604Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>task_uuid: 0242ac11-0006-d2c4-69c4-00000000000d<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 20 | 120 | 2020-12-20T15:40:26.856232Z | 0242ac11-0006-d2c4-69c4-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/20/ | 2f2d330b-38f6-4995-b5f1-b5c794a80526 | 0 |
>| false | 5 | 2020-12-20T15:40:33.588831Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 104, "used": 3781}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2293, "free": 1592}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "0", "iso8601_basic_short": "20201220T154027", "tz": "UTC", "weeknumber": "50", "hour": "15", "year": "2020", "minute": "40", "tz_offset": "+0000", "month": "12", "second": "27", "iso8601_micro": "2020-12-20T15:40:27.737695Z", "weekday": "Sunday", "time": "15:40:27", "date": "2020-12-20", "epoch": "1608478827", "iso8601": "2020-12-20T15:40:27Z", "day": "20", "iso8601_basic": "20201220T154027737635"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 104, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34316966, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5365420, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45443145, "size_available": 186135121920, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150726, "device": "/dev/nvme0n1p1", "inode_used": 449274, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365420, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45443145, "size_available": 186135121920, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150726, "device": "/dev/nvme0n1p1", "inode_used": 449274, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365420, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45443145, "size_available": 186135121920, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150726, "device": "/dev/nvme0n1p1", "inode_used": 449274, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365420, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45443145, "size_available": 186135121920, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150726, "device": "/dev/nvme0n1p1", "inode_used": 449274, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>task_uuid: 0242ac11-0006-d2c4-69c4-00000000000d<br/>event_loop: null<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 21 | 120 | 2020-12-20T15:40:33.612836Z | 0242ac11-0006-d2c4-69c4-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/21/ | d28efbc3-b702-4a58-a374-978fb2939b95 | 0 |
>| false | 6 | 2020-12-20T15:40:33.620349Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-d2c4-69c4-000000000009<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 22 | 120 | 2020-12-20T15:40:33.647506Z | 0242ac11-0006-d2c4-69c4-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/22/ | 0242ac11-0006-d2c4-69c4-000000000009 | 0 |
>| false | 8 | 2020-12-20T15:40:33.660864Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 944<br/>dark: {"test-host": 1}<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 23 | 120 | 2020-12-20T15:40:33.678193Z | 21742f14-1e3b-4705-9cd3-f476f98afca9 |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/23/ | 17888938-953b-4d5a-bd5f-481af006603e | 0 |
>| false | 7 | 2020-12-20T15:40:33.650819Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 944<br/>play_uuid: 0242ac11-0006-d2c4-69c4-000000000007<br/>task_uuid: 0242ac11-0006-d2c4-69c4-000000000009<br/>event_loop: null<br/>playbook_uuid: 21742f14-1e3b-4705-9cd3-f476f98afca9<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 24 | 120 | 2020-12-20T15:40:33.689699Z | 0242ac11-0006-d2c4-69c4-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/24/ | e96e217d-4829-4c07-999f-84a78fb5bfe3 | 0 |
>| false | 1 | 2020-12-20T15:45:01.072980Z | 0 | playbook_on_start | pid: 1174<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 25 | 123 | 2020-12-20T15:45:01.105605Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/25/ | 332f1315-4fa6-47ec-8282-66c6c224c26e | 0 |
>| false | 2 | 2020-12-20T15:45:01.132351Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 26 | 123 | 2020-12-20T15:45:01.142434Z | 332f1315-4fa6-47ec-8282-66c6c224c26e | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/26/ | 0242ac11-0006-8dae-a802-000000000007 | 0 |
>| false | 3 | 2020-12-20T15:45:01.148593Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-8dae-a802-00000000000d<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 27 | 123 | 2020-12-20T15:45:01.161198Z | 0242ac11-0006-8dae-a802-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/27/ | 0242ac11-0006-8dae-a802-00000000000d | 0 |
>| false | 4 | 2020-12-20T15:45:01.324692Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>task_uuid: 0242ac11-0006-8dae-a802-00000000000d<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 28 | 123 | 2020-12-20T15:45:01.343824Z | 0242ac11-0006-8dae-a802-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/28/ | 4177b88c-1016-421e-ac85-55d37d67befb | 0 |
>| false | 5 | 2020-12-20T15:45:08.028043Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 118, "used": 3767}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2301, "free": 1584}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "0", "iso8601_basic_short": "20201220T154502", "tz": "UTC", "weeknumber": "50", "hour": "15", "year": "2020", "minute": "45", "tz_offset": "+0000", "month": "12", "second": "02", "iso8601_micro": "2020-12-20T15:45:02.175922Z", "weekday": "Sunday", "time": "15:45:02", "date": "2020-12-20", "epoch": "1608479102", "iso8601": "2020-12-20T15:45:02Z", "day": "20", "iso8601_basic": "20201220T154502175834"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 118, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34317240, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5365480, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45443085, "size_available": 186134876160, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150722, "device": "/dev/nvme0n1p1", "inode_used": 449278, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365480, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45443085, "size_available": 186134876160, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150722, "device": "/dev/nvme0n1p1", "inode_used": 449278, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365480, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45443085, "size_available": 186134876160, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150722, "device": "/dev/nvme0n1p1", "inode_used": 449278, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5365480, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45443085, "size_available": 186134876160, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150722, "device": "/dev/nvme0n1p1", "inode_used": 449278, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>task_uuid: 0242ac11-0006-8dae-a802-00000000000d<br/>event_loop: null<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 29 | 123 | 2020-12-20T15:45:08.051138Z | 0242ac11-0006-8dae-a802-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/29/ | 53c38d4b-06f9-477d-b911-fe6b27f7509d | 0 |
>| false | 6 | 2020-12-20T15:45:08.065324Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-8dae-a802-000000000009<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 30 | 123 | 2020-12-20T15:45:08.080849Z | 0242ac11-0006-8dae-a802-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/30/ | 0242ac11-0006-8dae-a802-000000000009 | 0 |
>| false | 8 | 2020-12-20T15:45:08.105432Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 1174<br/>dark: {"test-host": 1}<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 31 | 123 | 2020-12-20T15:45:08.115925Z | 332f1315-4fa6-47ec-8282-66c6c224c26e |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/31/ | 5fe1c5f7-04db-4888-9a51-b5251bf0bbfe | 0 |
>| false | 7 | 2020-12-20T15:45:08.097415Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 1174<br/>play_uuid: 0242ac11-0006-8dae-a802-000000000007<br/>task_uuid: 0242ac11-0006-8dae-a802-000000000009<br/>event_loop: null<br/>playbook_uuid: 332f1315-4fa6-47ec-8282-66c6c224c26e<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 32 | 123 | 2020-12-20T15:45:08.126780Z | 0242ac11-0006-8dae-a802-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/32/ | 6e306fb5-547a-4b6d-9566-10912d7f6401 | 0 |
>| false | 1 | 2020-12-21T09:52:10.157175Z | 0 | playbook_on_start | pid: 1404<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 33 | 126 | 2020-12-21T09:52:10.184226Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/33/ | a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5 | 0 |
>| false | 2 | 2020-12-21T09:52:10.214671Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 34 | 126 | 2020-12-21T09:52:10.224963Z | a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5 | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/34/ | 0242ac11-0006-9c79-d6b0-000000000007 | 0 |
>| false | 3 | 2020-12-21T09:52:10.228399Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-9c79-d6b0-00000000000d<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 35 | 126 | 2020-12-21T09:52:10.243743Z | 0242ac11-0006-9c79-d6b0-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/35/ | 0242ac11-0006-9c79-d6b0-00000000000d | 0 |
>| false | 4 | 2020-12-21T09:52:10.395481Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>task_uuid: 0242ac11-0006-9c79-d6b0-00000000000d<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 36 | 126 | 2020-12-21T09:52:10.410222Z | 0242ac11-0006-9c79-d6b0-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/36/ | 9d7a21c9-8cc9-429a-bc0f-0426563dda83 | 0 |
>| false | 5 | 2020-12-21T09:52:17.179687Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 118, "used": 3767}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2366, "free": 1519}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "1", "iso8601_basic_short": "20201221T095211", "tz": "UTC", "weeknumber": "51", "hour": "09", "year": "2020", "minute": "52", "tz_offset": "+0000", "month": "12", "second": "11", "iso8601_micro": "2020-12-21T09:52:11.272462Z", "weekday": "Monday", "time": "09:52:11", "date": "2020-12-21", "epoch": "1608544331", "iso8601": "2020-12-21T09:52:11Z", "day": "21", "iso8601_basic": "20201221T095211272402"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 118, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34382469, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5370870, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45437695, "size_available": 186112798720, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150718, "device": "/dev/nvme0n1p1", "inode_used": 449282, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370870, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45437695, "size_available": 186112798720, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150718, "device": "/dev/nvme0n1p1", "inode_used": 449282, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370870, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45437695, "size_available": 186112798720, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150718, "device": "/dev/nvme0n1p1", "inode_used": 449282, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370869, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45437696, "size_available": 186112802816, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150718, "device": "/dev/nvme0n1p1", "inode_used": 449282, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>task_uuid: 0242ac11-0006-9c79-d6b0-00000000000d<br/>event_loop: null<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 37 | 126 | 2020-12-21T09:52:17.204053Z | 0242ac11-0006-9c79-d6b0-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/37/ | b7f66d93-42c4-48b9-87fa-a262dc5d2385 | 0 |
>| false | 6 | 2020-12-21T09:52:17.213976Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-9c79-d6b0-000000000009<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 38 | 126 | 2020-12-21T09:52:17.236338Z | 0242ac11-0006-9c79-d6b0-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/38/ | 0242ac11-0006-9c79-d6b0-000000000009 | 0 |
>| false | 8 | 2020-12-21T09:52:17.254103Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 1404<br/>dark: {"test-host": 1}<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 39 | 126 | 2020-12-21T09:52:17.266470Z | a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5 |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/39/ | e868c372-e856-44a2-be5e-d72a4de4af57 | 0 |
>| false | 7 | 2020-12-21T09:52:17.245439Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 1404<br/>play_uuid: 0242ac11-0006-9c79-d6b0-000000000007<br/>task_uuid: 0242ac11-0006-9c79-d6b0-000000000009<br/>event_loop: null<br/>playbook_uuid: a0283f39-46e0-43e1-ae5e-22ae9d7a8fc5<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 40 | 126 | 2020-12-21T09:52:17.269648Z | 0242ac11-0006-9c79-d6b0-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/40/ | c17d3b2d-bfc6-4fc1-a7c1-485536896a40 | 0 |
>| false | 1 | 2020-12-21T10:04:45.419906Z | 0 | playbook_on_start | pid: 1634<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 41 | 129 | 2020-12-21T10:04:45.446762Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/41/ | c969af97-43b7-4d2a-915a-0c7548281637 | 0 |
>| false | 2 | 2020-12-21T10:04:45.477597Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 42 | 129 | 2020-12-21T10:04:45.487364Z | c969af97-43b7-4d2a-915a-0c7548281637 | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/42/ | 0242ac11-0006-819d-00d7-000000000007 | 0 |
>| false | 3 | 2020-12-21T10:04:45.493322Z | 4 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>name: Gathering Facts<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-819d-00d7-00000000000d<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>task_action: setup<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Task Started (Gathering Facts) | 2 | true |  |  | 43 | 129 | 2020-12-21T10:04:45.503462Z | 0242ac11-0006-819d-00d7-000000000007 | Hello World Sample | hello_world.yml | 2 | <br/>TASK [Gathering Facts] ********************************************************* | Gathering Facts | job_event | /api/v2/job_events/43/ | 0242ac11-0006-819d-00d7-00000000000d | 0 |
>| false | 4 | 2020-12-21T10:04:45.631816Z | 5 | runner_on_unreachable | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: test-host<br/>res: {"msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true, "changed": false}<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>task_uuid: 0242ac11-0006-819d-00d7-00000000000d<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: test-host<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host Unreachable | 3 | true |  | test-host | 44 | 129 | 2020-12-21T10:04:45.647266Z | 0242ac11-0006-819d-00d7-00000000000d | Hello World Sample | hello_world.yml | 4 | [1;31mfatal: [test-host]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname test-host: Name or service not known\r\n", "unreachable": true}[0m | Gathering Facts | job_event | /api/v2/job_events/44/ | d1a4b700-e388-4cc1-8af9-d8f7ff67f13a | 0 |
>| false | 5 | 2020-12-21T10:04:52.450794Z | 6 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Gathering Facts<br/>task_args: <br/>remote_addr: localhost<br/>res: {"_ansible_parsed": true, "_ansible_no_log": false, "changed": false, "_ansible_verbose_override": true, "invocation": {"module_args": {"filter": "*", "gather_subset": ["all"], "fact_path": "/etc/ansible/facts.d", "gather_timeout": 10}}, "ansible_facts": {"ansible_product_serial": "ec2217e9-f4b7-739e-b41b-22859157f859", "ansible_form_factor": "Other", "ansible_product_version": "NA", "ansible_fips": false, "ansible_service_mgr": "tini", "ansible_memory_mb": {"real": {"total": 3885, "free": 116, "used": 3769}, "swap": {"cached": 0, "total": 0, "used": 0, "free": 0}, "nocache": {"used": 2370, "free": 1515}}, "module_setup": true, "ansible_memtotal_mb": 3885, "gather_subset": ["all"], "ansible_system_capabilities_enforced": "True", "ansible_domain": "", "ansible_distribution_version": "7.5.1804", "ansible_local": {}, "ansible_distribution_file_path": "/etc/redhat-release", "ansible_virtualization_type": "docker", "ansible_real_user_id": 0, "ansible_processor_cores": 1, "ansible_virtualization_role": "guest", "ansible_distribution_file_variety": "RedHat", "ansible_dns": {"nameservers": ["172.31.0.2"], "search": ["eu-central-1.compute.internal"]}, "ansible_effective_group_id": 0, "ansible_is_chroot": false, "ansible_bios_version": "1.0", "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz", "1", "GenuineIntel", "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"], "ansible_date_time": {"weekday_number": "1", "iso8601_basic_short": "20201221T100446", "tz": "UTC", "weeknumber": "51", "hour": "10", "year": "2020", "minute": "04", "tz_offset": "+0000", "month": "12", "second": "46", "iso8601_micro": "2020-12-21T10:04:46.498951Z", "weekday": "Monday", "time": "10:04:46", "date": "2020-12-21", "epoch": "1608545086", "iso8601": "2020-12-21T10:04:46Z", "day": "21", "iso8601_basic": "20201221T100446498844"}, "ansible_lo": {"mtu": 65536, "active": true, "promisc": false, "ipv4": {"broadcast": "host", "netmask": "255.0.0.0", "network": "127.0.0.0", "address": "127.0.0.1"}, "device": "lo", "type": "loopback"}, "ansible_userspace_bits": "64", "ansible_architecture": "x86_64", "ansible_device_links": {"masters": {}, "labels": {}, "ids": {}, "uuids": {}}, "ansible_default_ipv4": {"macaddress": "02:42:ac:11:00:06", "network": "172.17.0.0", "mtu": 1500, "broadcast": "172.17.255.255", "alias": "eth0", "netmask": "255.255.0.0", "address": "172.17.0.6", "interface": "eth0", "type": "ether", "gateway": "172.17.0.1"}, "ansible_swapfree_mb": 0, "ansible_default_ipv6": {}, "ansible_distribution_release": "Core", "ansible_system_vendor": "Amazon EC2", "ansible_apparmor": {"status": "disabled"}, "ansible_cmdline": {"root": "UUID=bbf64c6d-bc15-4ae0-aa4c-608fd9820d95", "nvme.io_timeout": "4294967295", "ro": true, "BOOT_IMAGE": "/boot/vmlinuz-4.15.0-1054-aws", "console": "ttyS0"}, "ansible_effective_user_id": 0, "ansible_user_gid": 0, "ansible_selinux": {"status": "disabled"}, "ansible_distribution_file_parsed": true, "ansible_os_family": "RedHat", "ansible_userspace_architecture": "x86_64", "ansible_product_uuid": "EC2217E9-F4B7-739E-B41B-22859157F859", "ansible_product_name": "t3.medium", "ansible_pkg_mgr": "yum", "ansible_memfree_mb": 116, "ansible_devices": {"nvme0n1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "419430400", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "0", "removable": "0", "support_discard": "0", "holders": [], "partitions": {"nvme0n1p1": {"sectorsize": 512, "uuid": null, "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sectors": "419428319", "start": "2048", "holders": [], "size": "200.00 GB"}}, "model": "Amazon Elastic Block Store", "size": "200.00 GB"}, "loop3": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113384", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.36 MB"}, "loop2": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop1": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "200416", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "97.86 MB"}, "loop0": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "66200", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "32.32 MB"}, "loop7": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "0", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop6": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "0", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "0.00 Bytes"}, "loop5": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "57544", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "28.10 MB"}, "loop4": {"scheduler_mode": "none", "sectorsize": "512", "vendor": null, "sectors": "113424", "links": {"masters": [], "labels": [], "ids": [], "uuids": []}, "sas_device_handle": null, "sas_address": null, "virtual": 1, "host": "", "rotational": "1", "removable": "0", "support_discard": "4096", "holders": [], "partitions": {}, "model": null, "size": "55.38 MB"}}, "ansible_user_uid": 0, "ansible_user_id": "root", "ansible_distribution": "CentOS", "ansible_user_dir": "/root", "ansible_distribution_major_version": "7", "ansible_selinux_python_present": true, "ansible_iscsi_iqn": "", "ansible_hostname": "awx", "ansible_processor_vcpus": 2, "ansible_processor_count": 1, "ansible_swaptotal_mb": 0, "ansible_lsb": {}, "ansible_real_group_id": 0, "ansible_bios_date": "10/16/2017", "ansible_all_ipv6_addresses": [], "ansible_interfaces": ["lo", "eth0"], "ansible_uptime_seconds": 34383224, "ansible_machine": "x86_64", "ansible_kernel": "4.15.0-1054-aws", "ansible_user_gecos": "root", "ansible_system_capabilities": ["cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot", "cap_mknod", "cap_audit_write", "cap_setfcap+eip"], "ansible_python": {"executable": "/usr/bin/python", "version": {"micro": 5, "major": 2, "releaselevel": "final", "serial": 0, "minor": 7}, "type": "CPython", "has_sslcontext": true, "version_info": [2, 7, 5, "final", 0]}, "ansible_processor_threads_per_core": 2, "ansible_fqdn": "awx", "ansible_mounts": [{"block_used": 5370977, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/resolv.conf", "block_available": 45437588, "size_available": 186112360448, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150715, "device": "/dev/nvme0n1p1", "inode_used": 449285, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370977, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hostname", "block_available": 45437588, "size_available": 186112360448, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150715, "device": "/dev/nvme0n1p1", "inode_used": 449285, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370977, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/etc/hosts", "block_available": 45437588, "size_available": 186112360448, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150715, "device": "/dev/nvme0n1p1", "inode_used": 449285, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}, {"block_used": 5370977, "uuid": "N/A", "size_total": 208111882240, "block_total": 50808565, "mount": "/var/lib/nginx", "block_available": 45437588, "size_available": 186112360448, "fstype": "ext4", "inode_total": 25600000, "inode_available": 25150715, "device": "/dev/nvme0n1p1", "inode_used": 449285, "block_size": 4096, "options": "rw,relatime,discard,data=ordered,bind"}], "ansible_eth0": {"macaddress": "02:42:ac:11:00:06", "speed": 10000, "mtu": 1500, "active": true, "promisc": false, "ipv4": {"broadcast": "172.17.255.255", "netmask": "255.255.0.0", "network": "172.17.0.0", "address": "172.17.0.6"}, "device": "eth0", "type": "ether"}, "ansible_nodename": "awx", "ansible_system": "Linux", "ansible_user_shell": "/bin/bash", "ansible_all_ipv4_addresses": ["172.17.0.6"], "ansible_python_version": "2.7.5"}}<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>task_uuid: 0242ac11-0006-819d-00d7-00000000000d<br/>event_loop: null<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>task_action: setup<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:1 | Host OK | 3 | false | 1 | localhost | 45 | 129 | 2020-12-21T10:04:52.481737Z | 0242ac11-0006-819d-00d7-00000000000d | Hello World Sample | hello_world.yml | 5 | [0;32mok: [localhost][0m | Gathering Facts | job_event | /api/v2/job_events/45/ | 1109f095-ede0-4162-88ab-bffea8382f8e | 0 |
>| false | 6 | 2020-12-21T10:04:52.484118Z | 8 | playbook_on_task_start | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>name: Hello Message<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>is_conditional: false<br/>task_uuid: 0242ac11-0006-819d-00d7-000000000009<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>task_action: debug<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Task Started (Hello Message) | 2 | false |  |  | 46 | 129 | 2020-12-21T10:04:52.494760Z | 0242ac11-0006-819d-00d7-000000000007 | Hello World Sample | hello_world.yml | 6 | <br/>TASK [Hello Message] *********************************************************** | Hello Message | job_event | /api/v2/job_events/46/ | 0242ac11-0006-819d-00d7-000000000009 | 0 |
>| false | 7 | 2020-12-21T10:04:52.518281Z | 11 | runner_on_ok | play_pattern: all<br/>play: Hello World Sample<br/>task: Hello Message<br/>task_args: <br/>remote_addr: localhost<br/>res: {"msg": "Hello World!", "changed": false, "_ansible_verbose_always": true, "_ansible_no_log": false}<br/>pid: 1634<br/>play_uuid: 0242ac11-0006-819d-00d7-000000000007<br/>task_uuid: 0242ac11-0006-819d-00d7-000000000009<br/>event_loop: null<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>task_action: debug<br/>host: localhost<br/>task_path: /var/lib/awx/projects/_4__demo_project/hello_world.yml:4 | Host OK | 3 | false | 1 | localhost | 47 | 129 | 2020-12-21T10:04:52.539012Z | 0242ac11-0006-819d-00d7-000000000009 | Hello World Sample | hello_world.yml | 8 | [0;32mok: [localhost] => {[0m<br/>[0;32m    "msg": "Hello World!"[0m<br/>[0;32m}[0m | Hello Message | job_event | /api/v2/job_events/47/ | 32e073d0-325c-44b0-b17f-401304d4d60f | 0 |
>| false | 8 | 2020-12-21T10:04:52.525838Z | 16 | playbook_on_stats | skipped: {}<br/>ok: {"localhost": 2}<br/>changed: {}<br/>pid: 1634<br/>dark: {"test-host": 1}<br/>playbook_uuid: c969af97-43b7-4d2a-915a-0c7548281637<br/>playbook: hello_world.yml<br/>failures: {}<br/>processed: {"localhost": 1, "test-host": 1} | Playbook Complete | 1 | true |  |  | 48 | 129 | 2020-12-21T10:04:52.551570Z | c969af97-43b7-4d2a-915a-0c7548281637 |  | hello_world.yml | 11 | <br/>PLAY RECAP *********************************************************************<br/>[0;32mlocalhost[0m                  : [0;32mok=2   [0m changed=0    unreachable=0    failed=0   <br/>[0;31mtest-host[0m                  : ok=0    changed=0    [1;31munreachable=1   [0m failed=0   <br/> |  | job_event | /api/v2/job_events/48/ | 9365dfd3-d7a0-47cf-9134-b2c86ab9dda5 | 0 |
>| false | 1 | 2020-12-21T11:34:38.780915Z | 0 | playbook_on_start | pid: 1864<br/>playbook_uuid: ada585de-f207-445d-b0d4-1d4d81364f0e<br/>playbook: hello_world.yml | Playbook Started | 0 | false |  |  | 49 | 132 | 2020-12-21T11:34:38.811671Z |  |  | hello_world.yml | 0 |  |  | job_event | /api/v2/job_events/49/ | ada585de-f207-445d-b0d4-1d4d81364f0e | 0 |
>| false | 2 | 2020-12-21T11:34:38.836729Z | 2 | playbook_on_play_start | play_pattern: all<br/>play: Hello World Sample<br/>name: Hello World Sample<br/>pattern: all<br/>pid: 1864<br/>play_uuid: 0242ac11-0006-c6bb-f8cd-000000000007<br/>playbook_uuid: ada585de-f207-445d-b0d4-1d4d81364f0e<br/>playbook: hello_world.yml | Play Started (Hello World Sample) | 1 | false |  |  | 50 | 132 | 2020-12-21T11:34:38.851842Z | ada585de-f207-445d-b0d4-1d4d81364f0e | Hello World Sample | hello_world.yml | 0 | <br/>PLAY [Hello World Sample] ****************************************************** |  | job_event | /api/v2/job_events/50/ | 0242ac11-0006-c6bb-f8cd-000000000007 | 0 |


### ansible-tower-adhoc-command-launch
***
Create new ad hoc command


#### Base Command

`ansible-tower-adhoc-command-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | inventory id. | Required | 
| credential_id | credential id. | Required | 
| module_name | Modules are discrete units of code that can be used from the command line or in a playbook task. Ansible ships with a number of modules that can be executed directly on remote hosts or through Playbooks. Possible values are: command, shell, yum, apt, apt_key, apt_repository, apt_rpm, service, group, user, mount, ping, selinux, setup, win_ping, win_service, win_updates, win_group, win_user. | Required | 
| module_args | Module arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommand.id | Unknown | Ad hoc command id | 
| AnsibleAWX.AdhocCommand.status | Unknown | Ad hoc command status  | 


#### Command Example
```!ansible-tower-adhoc-command-launch credential_id=1 inventory_id=1 module_name=ping```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "become_enabled": false,
            "controller_node": "",
            "created": "2021-01-04T16:15:05.071429Z",
            "credential": 1,
            "diff_mode": false,
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "",
            "failed": false,
            "finished": null,
            "forks": 0,
            "id": 388,
            "inventory": 1,
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-04T16:15:05.103033Z",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "started": null,
            "status": "new",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/388/",
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 388 status - new
>|become_enabled|created|credential|diff_mode|elapsed|failed|forks|id|inventory|job_type|launch_type|modified|module_name|name|status|type|url|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-01-04T16:15:05.071429Z | 1 | false | 0.0 | false | 0 | 388 | 1 | run | manual | 2021-01-04T16:15:05.103033Z | ping | ping | new | ad_hoc_command | /api/v2/ad_hoc_commands/388/ | 0 |


### ansible-tower-adhoc-command-relaunch
***
Launch a new job to run the ad hoc command


#### Base Command

`ansible-tower-adhoc-command-relaunch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | command id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-adhoc-command-relaunch command_id=236```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "ad_hoc_command": 389,
            "become_enabled": false,
            "controller_node": "",
            "created": "2021-01-04T16:15:07.243871Z",
            "credential": 1,
            "diff_mode": false,
            "elapsed": 0,
            "event_processing_finished": false,
            "execution_node": "",
            "extra_vars": "",
            "failed": false,
            "finished": null,
            "forks": 0,
            "id": 389,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_env": {},
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-04T16:15:07.302523Z",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "result_traceback": "",
            "started": null,
            "status": "pending",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/389/",
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 389 status - pending
>|ad_hoc_command|become_enabled|created|credential|diff_mode|elapsed|event_processing_finished|failed|forks|id|inventory|job_type|launch_type|modified|module_name|name|status|type|url|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 389 | false | 2021-01-04T16:15:07.243871Z | 1 | false | 0.0 | false | false | 0 | 389 | 1 | run | manual | 2021-01-04T16:15:07.302523Z | ping | ping | pending | ad_hoc_command | /api/v2/ad_hoc_commands/389/ | 0 |


### ansible-tower-adhoc-command-cancel
***
Cancel a job of the given ad hoc command


#### Base Command

`ansible-tower-adhoc-command-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | command id to cancel. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### ansible-tower-adhoc-command-stdout
***
Retrieve the stdout from running this ad hoc command.


#### Base Command

`ansible-tower-adhoc-command-stdout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | command id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-adhoc-command-stdout command_id=236```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommandStdout": {
            "command_id": "236",
            "range": {
                "absolute_end": 10,
                "end": 10,
                "start": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command 236 output ### 
>
>[1;31mteat_demo | UNREACHABLE! => {[0m
>[1;31m    "changed": false, [0m
>[1;31m    "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname teat_demo: Name or service not known\\r\\n", [0m
>[1;31m    "unreachable": true[0m
>[1;31m}[0m
>[0;32mlocalhost | SUCCESS => {[0m
>[0;32m    "changed": false, [0m
>[0;32m    "ping": "pong"[0m
>[0;32m}[0m
>
>


### ansible-tower-adhoc-command-status
***
Retrieve a single ad hoc command status


#### Base Command

`ansible-tower-adhoc-command-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | Command id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ansible-tower-adhoc-command-status command_id=236```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "become_enabled": false,
            "controller_node": "",
            "created": "2020-12-29T13:28:21.538400Z",
            "credential": 1,
            "diff_mode": false,
            "elapsed": 2.2,
            "event_processing_finished": true,
            "execution_node": "awx",
            "extra_vars": "",
            "failed": true,
            "finished": "2020-12-29T13:28:24.029843Z",
            "forks": 0,
            "host_status_counts": {
                "dark": 1,
                "ok": 1
            },
            "id": 236,
            "inventory": 1,
            "job_args": "[\"ansible\", \"-i\", \"/tmp/awx_236_NewoHR/tmppT3kU8\", \"-u\", \"admin\", \"-e\", \"@/tmp/awx_236_NewoHR/tmp0jjAjr\", \"-m\", \"ping\", \"-a\", \"\", \"all\"]",
            "job_cwd": "/tmp/awx_236_NewoHR",
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2020-12-29T13:28:21.763189Z",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "result_traceback": "",
            "started": "2020-12-29T13:28:21.829663Z",
            "status": "failed",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/236/",
            "verbosity": 0
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 236 status - failed
>|become_enabled|created|credential|diff_mode|elapsed|event_processing_finished|execution_node|failed|finished|forks|host_status_counts|id|inventory|job_args|job_cwd|job_type|launch_type|modified|module_name|name|started|status|type|url|verbosity|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2020-12-29T13:28:21.538400Z | 1 | false | 2.2 | true | awx | true | 2020-12-29T13:28:24.029843Z | 0 | dark: 1<br/>ok: 1 | 236 | 1 | ["ansible", "-i", "/tmp/awx_236_NewoHR/tmppT3kU8", "-u", "admin", "-e", "@/tmp/awx_236_NewoHR/tmp0jjAjr", "-m", "ping", "-a", "", "all"] | /tmp/awx_236_NewoHR | run | manual | 2020-12-29T13:28:21.763189Z | ping | ping | 2020-12-29T13:28:21.829663Z | failed | ad_hoc_command | /api/v2/ad_hoc_commands/236/ | 0 |

