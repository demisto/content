Scale IT automation, manage complex deployments, and speed productivity.
This integration was integrated and tested with version v3.8.0 of Ansible Automation Platform and with API version v2.
## Configure Ansible Automation Platform in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ansible-tower-inventories-list
***
Retrieves the list of inventories.


#### Base Command

`ansible-tower-inventories-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The inventory ID for which to retrieve the specific inventory. | Optional | 
| page_number | Page number to retrieve. Default is 1. | Optional | 
| page_size | Page size. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Inventory.id | Number | Database ID for this inventory. | 
| AnsibleAWX.Inventory.type | String | Data type for this inventory. | 
| AnsibleAWX.Inventory.url | String | URL for this inventory. | 
| AnsibleAWX.Inventory.created | Date | Timestamp indicating when this inventory was created. | 
| AnsibleAWX.Inventory.modified | Date | Timestamp indicating when this inventory was last modified. | 
| AnsibleAWX.Inventory.name | String | Name of this inventory. | 
| AnsibleAWX.Inventory.description | String | Optional description of this inventory. | 
| AnsibleAWX.Inventory.organization | Number | ID of the organization containing this inventory. | 
| AnsibleAWX.Inventory.kind | String | Type of inventory being represented. | 
| AnsibleAWX.Inventory.host_filter | String | Filter that is applied to the hosts of this inventory. | 
| AnsibleAWX.Inventory.variables | String | Inventory variables in JSON or YAML format. | 
| AnsibleAWX.Inventory.total_inventory_sources | Number | Total number of external inventory sources configured within this inventory. | 
| AnsibleAWX.Inventory.inventory_sources_with_failures | Number | Number of external inventory sources in this inventory with failures. | 
| AnsibleAWX.Inventory.insights_credential | Number | Credentials to be used by hosts belonging to this inventory when accessing Red Hat Insights API. | 
| AnsibleAWX.Inventory.pending_deletion | Boolean | Flag indicating the inventory is being deleted. | 


#### Command Example
```!ansible-tower-inventories-list page_number=1 page_size=50```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Inventory": {
            "created": "2019-11-19 11:53:43.325946",
            "description": "",
            "groups_with_active_failures": 0,
            "host_filter": null,
            "id": 1,
            "insights_credential": null,
            "inventory_sources_with_failures": 0,
            "kind": "",
            "modified": "2021-01-11 10:41:31.234370",
            "name": "Example Inventory",
            "organization": 1,
            "pending_deletion": false,
            "total_inventory_sources": 0,
            "type": "inventory",
            "url": "/api/v2/inventories/1/",
            "variables": ""
        }
    }
}
```

#### Human Readable Output

>### Inventories List
>|name|id|type|url|created|modified|organization|groups_with_active_failures|total_inventory_sources|inventory_sources_with_failures|pending_deletion|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Example Inventory | 1 | inventory | /api/v2/inventories/1/ | 2019-11-19 11:53:43.325946 | 2021-01-11 10:41:31.234370 | 1 | 0 | 0 | 0 | false |


### ansible-tower-hosts-list
***
Retrieves the list of hosts. If an inventory ID is specified, retrieve the host located under the specific inventory.


#### Base Command

`ansible-tower-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | ID of the host to retrieve. | Optional | 
| inventory_id | ID of the inventory to retrieve. | Optional | 
| page | Page number to retrieve. Default is 1. | Optional | 
| page_size | Page size. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Host.id | Number | Database ID for this host. | 
| AnsibleAWX.Host.type | String | Data type for this host. | 
| AnsibleAWX.Host.url | String | URL for this host. | 
| AnsibleAWX.Host.created | Date | Timestamp indicating when this host was created. | 
| AnsibleAWX.Host.modified | Date | Timestamp indicating when this host was last modified. | 
| AnsibleAWX.Host.name | String | Name of this host. | 
| AnsibleAWX.Host.description | String | Optional description of this host. | 
| AnsibleAWX.Host.inventory | Number | Inventory ID. | 
| AnsibleAWX.Host.enabled | Boolean | Whether this host is online and available for running jobs. | 
| AnsibleAWX.Host.instance_id | String | The value used by the remote inventory source to uniquely identify the host. | 
| AnsibleAWX.Host.variables | String | Host variables in JSON or YAML format. | 
| AnsibleAWX.Host.last_job | Number | ID of the last job that was run on the host. | 
| AnsibleAWX.Host.insights_system_id | String | Red Hat Insights host unique identifier. | 
| AnsibleAWX.Host.ansible_facts_modified | Date | The date and time ansible_facts was last modified. | 


#### Command Example
```!ansible-tower-hosts-list inventory_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Host": [
            {
                "ansible_facts_modified": null,
                "created": "2021-01-07 11:42:29.655768",
                "description": "",
                "enabled": true,
                "id": 1,
                "insights_system_id": null,
                "instance_id": "",
                "inventory": 1,
                "last_job": 700,
                "modified": "2021-01-13 07:46:49.267924",
                "name": "test",
                "type": "host",
                "url": "/api/v2/hosts/1/",
                "variables": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Hosts List
>|name|id|type|url|created|modified|inventory|enabled|variables|last_job|
>|---|---|---|---|---|---|---|---|---|---|
>| test | 1 | host | /api/v2/hosts/1/ | 2021-01-07 11:42:29.655768 | 2021-01-13 07:46:49.267924 | 1 | true |  | 700 |


### ansible-tower-host-create
***
Creates a host under the specified inventory ID and with the specified name.


#### Base Command

`ansible-tower-host-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | The ID of the inventory under which to create the host. | Required | 
| host_name | Unique name for the host. | Required | 
| description | Optional description of this host. | Optional | 
| enabled | Whether this host will be online and available for running jobs. Default is "True". Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Host.id | Number | Database ID for this host. | 
| AnsibleAWX.Host.type | String | Data type for this host. | 
| AnsibleAWX.Host.url | String | URL for this host. | 
| AnsibleAWX.Host.created | Date | Timestamp indicating when this host was created. | 
| AnsibleAWX.Host.modified | Date | Timestamp indicating when this host was last modified. | 
| AnsibleAWX.Host.name | String | Name of this host. | 
| AnsibleAWX.Host.description | String | Optional description of this host. | 
| AnsibleAWX.Host.inventory | Number | Inventory ID. | 
| AnsibleAWX.Host.enabled | Boolean | Whether this host is online and available for running jobs. | 
| AnsibleAWX.Host.instance_id | String | The value used by the remote inventory source to uniquely identify the host. | 
| AnsibleAWX.Host.variables | String | Host variables in JSON or YAML format. | 
| AnsibleAWX.Host.has_active_failures | Boolean | Whether host has active failures. | 
| AnsibleAWX.Host.last_job | Number | The ID of the last job. | 
| AnsibleAWX.Host.insights_system_id | String | Red Hat Insights host unique identifier. | 
| AnsibleAWX.Host.ansible_facts_modified | Date | The date and time ansible_facts was last modified. | 


#### Command Example
```!ansible-tower-host-create host_name=example inventory_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Host": {
            "ansible_facts_modified": null,
            "created": "2021-01-14 09:22:01.427258",
            "description": "",
            "enabled": true,
            "id": 3,
            "insights_system_id": null,
            "instance_id": "",
            "inventory": 1,
            "last_job": null,
            "modified": "2021-01-14 09:22:01.427272",
            "name": "example",
            "type": "host",
            "url": "/api/v2/hosts/3/",
            "variables": ""
        }
    }
}
```

#### Human Readable Output

>### Created Host
>|name|id|enabled|inventory|modified|created|type|url|
>|---|---|---|---|---|---|---|---|
>| example | 3 | true |  1 | 2021-01-14 09:22:01.427272 | 2021-01-14 09:22:01.427258 | host | /api/v2/hosts/3/ |


### ansible-tower-host-delete
***
Deletes the specified host.


#### Base Command

`ansible-tower-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The ID of the host to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Host.id | Number | Database ID for this host. | 
| AnsibleAWX.Host.Deleted | Boolean | Whether this host was deleted. | 


#### Command Example
``` !ansible-tower-host-delete host_id=30 ```

#### Human Readable Output

Removed host id: 30


### ansible-tower-job-templates-list
***
Retrieves the list of job templates.


#### Base Command

`ansible-tower-job-templates-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | Inventory ID of the jobs that are managed with hosts under this inventory. | Optional | 
| page | Page number to retrieve. Default is 1. | Optional | 
| page_size | Page size. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 
| id | The ID of the job template. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.JobTemplate.id | Number | Database ID for this job template. | 
| AnsibleAWX.JobTemplate.type | String | Data type for this job template. | 
| AnsibleAWX.JobTemplate.url | String | URL for this job template. | 
| AnsibleAWX.JobTemplate.created | Date | Timestamp indicating when this job template was created. | 
| AnsibleAWX.JobTemplate.modified | Date | Timestamp indicating when this job template was last modified. | 
| AnsibleAWX.JobTemplate.name | String | Name of this job template. | 
| AnsibleAWX.JobTemplate.description | String | Optional description of this job template. | 
| AnsibleAWX.JobTemplate.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.JobTemplate.inventory | Number | Inventory ID. | 
| AnsibleAWX.JobTemplate.project | Number | Project ID. | 
| AnsibleAWX.JobTemplate.playbook | String | Playbook name. | 
| AnsibleAWX.JobTemplate.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.JobTemplate.extra_vars | String | Extra command line variables that were passed to the playbook. | 
| AnsibleAWX.JobTemplate.job_tags | String | Job tags. These tags are useful when you have a large playbook and you want to run a specific part of a playbook or task. | 
| AnsibleAWX.JobTemplate.skip_tags | String | Skip tags. These tags are useful when you have a large playbook and you want to skip a specific part of a playbook or task. | 
| AnsibleAWX.JobTemplate.timeout | Number | The number of seconds to wait before the task is canceled. | 
| AnsibleAWX.JobTemplate.last_job_run | Date | Timestamp indicating when the last job ran. | 
| AnsibleAWX.JobTemplate.last_job_failed | Boolean | Whether the last job failed. | 
| AnsibleAWX.JobTemplate.next_job_run | Date | Timestamp of the next job run. | 
| AnsibleAWX.JobTemplate.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.JobTemplate.host_config_key | String | The host config key that ran the job. | 
| AnsibleAWX.JobTemplate.survey_enabled | Boolean | Whether the job template survey was enabled. | 
| AnsibleAWX.JobTemplate.become_enabled | Boolean | Whether the job template was enabled. | 
| AnsibleAWX.JobTemplate.custom_virtualenv | String | Local absolute file path containing a custom Python virtualenv to use. | 
| AnsibleAWX.JobTemplate.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 


#### Command Example
```!ansible-tower-job-templates-list```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobTemplate": {
            "become_enabled": false,
            "created": "2019-11-19 11:53:43.446968",
            "credential": 1,
            "custom_virtualenv": null,
            "description": "",
            "extra_vars": "",
            "host_config_key": "",
            "id": 5,
            "inventory": 1,
            "job_tags": "",
            "job_type": "run",
            "last_job_failed": true,
            "last_job_run": "2021-01-13T07:46:49.418371Z",
            "limit": "",
            "modified": "2021-01-13 07:46:49.462160",
            "name": "Demo Job Template",
            "next_job_run": null,
            "playbook": "hello_world.yml",
            "project": 4,
            "skip_tags": "",
            "status": "failed",
            "survey_enabled": false,
            "timeout": 0,
            "type": "job_template",
            "url": "/api/v2/job_templates/5/",
            "vault_credential": null
        }
    }
}
```

#### Human Readable Output

>### Job Templates List
>|name|id|type|url|created|modified|inventory|project|playbook|timeout|last_job_run|last_job_failed|status|survey_enabled|become_enabled|credential|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Demo Job Template | 5 | job_template | /api/v2/job_templates/5/ | 2019-11-19 11:53:43.446968 | 2021-01-13 07:46:49.462160 | run | 1 | 4 | hello_world.yml | 0 | 2021-01-13T07:46:49.418371Z | true | failed | false | false |  | 1 |  |


### ansible-tower-credentials-list
***
Retrieves the list of credentials. If an ID is specified, retrieve the specific credential.


#### Base Command

`ansible-tower-credentials-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific credential. | Optional | 
| page | Page number to retrieve. Default is 1. | Optional | 
| page_size | Page size. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Credential.id | Number | Database ID for this credential. | 
| AnsibleAWX.Credential.type | String | Data type for this credential. | 
| AnsibleAWX.Credential.url | String | URL for this credential. | 
| AnsibleAWX.Credential.created | Date | Timestamp indicating when this credential was created. | 
| AnsibleAWX.Credential.modified | Date | Timestamp indicating when this credential was last modified. | 
| AnsibleAWX.Credential.name | String | Name of this credential. | 
| AnsibleAWX.Credential.description | String | Optional description of this credential. | 
| AnsibleAWX.Credential.organization | Number | Organization ID. Inherits permissions from organization roles. | 
| AnsibleAWX.Credential.credential_type | Number | The type of credential to create. | 
| AnsibleAWX.Credential.inputs.username | String | Username. | 


#### Command Example
```!ansible-tower-credentials-list```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Credential": {
            "created": "2019-11-19 11:53:43.220855",
            "credential_type": 1,
            "description": "",
            "id": 1,
            "inputs": {
                "username": "admin"
            },
            "modified": "2019-11-19 11:53:43.289192",
            "name": "Demo Credential",
            "organization": null,
            "type": "credential",
            "url": "/api/v2/credentials/1/"
        }
    }
}
```

#### Human Readable Output

>### Credentials List
>|name|id|type|url|created|modified|credential_type|inputs|
>|---|---|---|---|---|---|---|---|
>| Demo Credential | 1 | credential | /api/v2/credentials/1/ | 2019-11-19 11:53:43.220855 | 2019-11-19 11:53:43.289192 | 1 | username: admin |


### ansible-tower-job-launch
***
Launches the job template.


#### Base Command

`ansible-tower-job-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_template_id | ID of the job template to launch. | Required | 
| inventory_id | The ID of the inventory that contains the host you want this job to manage if the job template does not have an inventory to start. | Optional | 
| credentials_id | The ID of the credentials that allow Tower to access the node this job will be run against. | Optional | 
| extra_variables | Command line variables to pass to the playbook in JSON format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Number | Database ID for this job. | 
| AnsibleAWX.Job.type | String | Data type for this job. | 
| AnsibleAWX.Job.url | String | URL for this job. | 
| AnsibleAWX.Job.created | Date | Timestamp indicating when this job was created. | 
| AnsibleAWX.Job.modified | Date | Timestamp indicating when this job was last modified. | 
| AnsibleAWX.Job.name | String | Name of this job. | 
| AnsibleAWX.Job.description | String | Optional description of this job. | 
| AnsibleAWX.Job.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.Job.inventory | Number | Inventory ID. | 
| AnsibleAWX.Job.project | Number | Project ID. | 
| AnsibleAWX.Job.playbook | String | Playbook name. | 
| AnsibleAWX.Job.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.Job.extra_vars | String | Extra command line variables that were passed to the playbook. | 
| AnsibleAWX.Job.job_tags | String | Job tags. These tags are useful when you have a large playbook and you want to run a specific part of a playbook or task. | 
| AnsibleAWX.Job.skip_tags | String | Skip tags. These tags are useful when you have a large playbook and you want to skip a specific part of a playbook or task. | 
| AnsibleAWX.Job.timeout | Number | The number of seconds to wait before the task is canceled. | 
| AnsibleAWX.Job.launch_type | String | Launch type of the job. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.Job.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.Job.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.Job.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.Job.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.Job.job_args | String | Job arguments. | 
| AnsibleAWX.Job.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.Job.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.Job.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output | 
| AnsibleAWX.Job.execution_node | String | The node the job executed on. | 
| AnsibleAWX.Job.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.Job.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.Job.job_template | Number | The ID of the job template for this job. | 
| AnsibleAWX.Job.scm_revision | String | The source control management revision of the project used for this job, if available. | 
| AnsibleAWX.Job.instance_group | Number | The instance group the job was run under. | 
| AnsibleAWX.Job.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 


#### Command Example
```!ansible-tower-job-launch job_template_id=5```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "artifacts": {},
            "controller_node": "",
            "created": "2021-01-14 09:22:07.965061",
            "credential": 1,
            "description": "",
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": false,
            "finished": null,
            "id": 1,
            "ignored_fields": {},
            "instance_group": null,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-14 09:22:08.080092",
            "name": "Example Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "started": null,
            "status": "pending",
            "timeout": 0,
            "type": "job",
            "url": "/api/v2/jobs/1/",
            "vault_credential": null
        }
    }
}
```

#### Human Readable Output

>### Job: 1 status is: pending
>|name|id|type|url|created|modified|job_type|inventory|project|playbook|extra_vars|timeout|launch_type|status|failed|elapsed|job_template|credential|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Example Job Template | 1 | job | /api/v2/jobs/1/ | 2021-01-14 09:22:07.965061 | 2021-01-14 09:22:08.080092 | run | 1 | 4 | hello_world.yml | {} | 0 | manual | pending | false | 0.0 | 5 | 1 |


### ansible-tower-job-relaunch
***
Relaunch a job.


#### Base Command

`ansible-tower-job-relaunch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | ID of the job to relaunch. | Required | 
| relaunch_hosts | The hosts to relaunch the job. Can be all the hosts or only the ones where the job failed. Possible values are: "all" and "failed". Default is "all". Possible values are: all, failed. Default is all. | Optional | 
| credentials_id | Credential ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Number | Database ID for this job. | 
| AnsibleAWX.Job.type | String | Data type for this job. | 
| AnsibleAWX.Job.url | String | URL for this job. | 
| AnsibleAWX.Job.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.Job.created | Date | Timestamp indicating when this job was created. | 
| AnsibleAWX.Job.modified | Date | Timestamp indicating when this job was last modified. | 
| AnsibleAWX.Job.name | String | Name of this job. | 
| AnsibleAWX.Job.description | String | Optional description of this job. | 
| AnsibleAWX.Job.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.Job.inventory | Number | Inventory ID. | 
| AnsibleAWX.Job.project | Number | Project ID | 
| AnsibleAWX.Job.playbook | String | Playbook name | 
| AnsibleAWX.Job.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.Job.extra_vars | String | Extra command line variables that were passed to the playbook. | 
| AnsibleAWX.Job.job_tags | String | Job tags. These tags are useful when you have a large playbook and you want to run a specific part of a playbook or task. | 
| AnsibleAWX.Job.skip_tags | String | Skip tags. These tags are useful when you have a large playbook and you want to skip a specific part of a playbook or task. | 
| AnsibleAWX.Job.timeout | Number | The number of seconds to wait before the task is canceled. | 
| AnsibleAWX.Job.launch_type | String | Launch type of the job. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.Job.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.Job.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.Job.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.Job.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.Job.job_args | String | Job arguments. | 
| AnsibleAWX.Job.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.Job.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output | 
| AnsibleAWX.Job.execution_node | String | The node the job executed on. | 
| AnsibleAWX.Job.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.Job.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.Job.job_template | Number | The ID of the job template of this job. | 
| AnsibleAWX.Job.scm_revision | String | The source control management revision of the project used for this job, if available. | 
| AnsibleAWX.Job.instance_group | Number | The instance group the job was run under. | 
| AnsibleAWX.Job.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 


#### Command Example
```!ansible-tower-job-relaunch job_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "artifacts": {},
            "controller_node": "",
            "created": "2021-01-14 09:22:09.688907",
            "credential": 1,
            "description": "",
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": false,
            "finished": null,
            "id": 2,
            "instance_group": null,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "relaunch",
            "limit": "",
            "modified": "2021-01-14 09:22:09.841300",
            "name": "Example Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "started": null,
            "status": "pending",
            "timeout": 0,
            "type": "job",
            "url": "/api/v2/jobs/2/",
            "vault_credential": null
        }
    }
}
```

#### Human Readable Output



### ansible-tower-job-cancel
***
Cancels a pending or running job.


#### Base Command

`ansible-tower-job-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job to cancel. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Number | Database ID for this job. | 
| AnsibleAWX.Job.type | String | Data type for this job. | 
| AnsibleAWX.Job.url | String | URL for this job. | 
| AnsibleAWX.Job.created | Date | Timestamp indicating when this job was created. | 
| AnsibleAWX.Job.modified | Date | Timestamp indicating when this job was last modified. | 
| AnsibleAWX.Job.name | String | Name of this job. | 
| AnsibleAWX.Job.description | String | Optional description of this job. | 
| AnsibleAWX.Job.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.Job.inventory | Number | Inventory ID. | 
| AnsibleAWX.Job.project | Number | Project ID. | 
| AnsibleAWX.Job.playbook | String | Playbook name. | 
| AnsibleAWX.Job.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.Job.extra_vars | String | Extra command line variables that were passed to the playbook. | 
| AnsibleAWX.Job.job_tags | String | Job tags. These tags are useful when you have a large playbook and you want to run a specific part of a playbook or task. | 
| AnsibleAWX.Job.skip_tags | String | Skip tags. These tags are useful when you have a large playbook and you want to skip a specific part of a playbook or task. | 
| AnsibleAWX.Job.timeout | Number | The number of seconds to wait before the task is canceled. | 
| AnsibleAWX.Job.launch_type | String | Launch type of the job. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.Job.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.Job.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.Job.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.Job.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.Job.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.Job.job_args | String | Job arguments. | 
| AnsibleAWX.Job.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.Job.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.Job.execution_node | String | The node the job executed on. | 
| AnsibleAWX.Job.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.Job.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.Job.job_template | Number | The ID of the job template of this job. | 
| AnsibleAWX.Job.scm_revision | String | The source control management revision of the project used for this job, if available. | 
| AnsibleAWX.Job.instance_group | Number | The instance group the job was run under. | 
| AnsibleAWX.Job.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 


#### Command Example
```!ansible-tower-job-cancel job_id=2```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "artifacts": {},
            "controller_node": "",
            "created": "2021-01-14 12:11:11.430693",
            "credential": 1,
            "description": "",
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": true,
            "finished": "2021-01-14T12:11:17.297156Z",
            "id": 2,
            "instance_group": null,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-14 12:11:17.297511",
            "name": "Example Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "started": null,
            "status": "canceled",
            "timeout": 0,
            "type": "job",
            "url": "/api/v2/jobs/2/",
            "vault_credential": null
        }
    }
}
```

#### Human Readable Output

>### Job 2 status canceled
>|name|id|type|url|created|modified|job_type|inventory|project|playbook|extra_vars|timeout|launch_type|status|failed|finished|elapsed|job_template|credential|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Example Job Template | 2 | job | /api/v2/jobs/2/ | 2021-01-14 12:11:11.430693 | 2021-01-14 12:11:17.297511 | run | 1 | 4 | hello_world.yml | {} | 0 | manual | canceled | true | 2021-01-14T12:11:17.297156Z | 0.0 | 5 | 1 |





### ansible-tower-job-stdout
***
Retrieves the standard output by running the provided job.


#### Base Command

`ansible-tower-job-stdout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job. | Required | 
| print_output | Whether to print the output. Possible values are: "True" and "False". Default is "True". Possible values are: True, False. Default is True. | Optional | 
| text_filter | The string by which to filter lines in the standard output. For example, enter 'success' to filter the standard output lines containing this word. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.JobStdout.job_id | Number | The ID of the job. | 
| AnsibleAWX.JobStdout.content | String | The standard output content. | 


#### Command Example
```!ansible-tower-job-stdout job_id=3```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobStdout": {
            "content": "\n\nPLAY [Hello World Sample] ******************************************************\n\nTASK [Gathering Facts] *********************************************************\n\u001b[1;31mfatal: [check8]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname check8: Name or service not known\\\\r\\\\n\", \"unreachable\": true}\u001b[0m\n\u001b[0;32mok: [localhost]\u001b[0m\n\nTASK [Hello Message] ***********************************************************\n\u001b[0;32mok: [localhost] => {\u001b[0m\n\u001b[0;32m    \"msg\": \"Hello World!\"\u001b[0m\n\u001b[0;32m}\u001b[0m\n\nPLAY RECAP *********************************************************************\n\u001b[0;31mcheck8\u001b[0m                     : ok=0    changed=0    \u001b[1;31munreachable=1   \u001b[0m failed=0   \n\u001b[0;32mlocalhost\u001b[0m                  : \u001b[0;32mok=2   \u001b[0m changed=0    unreachable=0    failed=0   \n\n",
            "job_id": "3"
        }
    }
}
```

#### Human Readable Output

>### Job 3 output ### 
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
Retrieves the job status.


#### Base Command

`ansible-tower-job-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job. | Required | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Number | Database ID for this job. | 
| AnsibleAWX.Job.type | String | Data type for this job. | 
| AnsibleAWX.Job.url | String | URL for this job. | 
| AnsibleAWX.Job.created | Date | Timestamp indicating when this job was created. | 
| AnsibleAWX.Job.modified | Date | Timestamp indicating when this job was last modified. | 
| AnsibleAWX.Job.name | String | Name of this job. | 
| AnsibleAWX.Job.description | String | Optional description of this job. | 
| AnsibleAWX.Job.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.Job.inventory | Number | Inventory ID. | 
| AnsibleAWX.Job.project | Number | Project ID. | 
| AnsibleAWX.Job.playbook | String | Playbook name. | 
| AnsibleAWX.Job.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.Job.extra_vars | String | Extra command line variables that were passed to the playbook. | 
| AnsibleAWX.Job.job_tags | String | Job tags. These tags are useful when you have a large playbook and you want to run a specific part of a playbook or task. | 
| AnsibleAWX.Job.skip_tags | String | Skip tags. These tags are useful when you have a large playbook and you want to skip a specific part of a playbook or task. | 
| AnsibleAWX.Job.timeout | Number | The number of seconds to wait before the task is canceled. | 
| AnsibleAWX.Job.launch_type | String | Launch type of the job. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.Job.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.Job.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.Job.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.Job.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.Job.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.Job.job_args | String | Job arguments. | 
| AnsibleAWX.Job.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.Job.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.Job.execution_node | String | The node the job executed on. | 
| AnsibleAWX.Job.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.Job.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.Job.job_template | Number | The ID of the job template of this job. | 
| AnsibleAWX.Job.scm_revision | String | The source control management revision of the project used for this job, if available. | 
| AnsibleAWX.Job.instance_group | Number | The instance group the job was run under. | 
| AnsibleAWX.Job.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 


#### Command Example
```!ansible-tower-job-status job_id=2```

#### Context Example
```json
{
    "AnsibleAWX": {
        "Job": {
            "artifacts": {},
            "controller_node": "",
            "created": "2020-12-30 16:12:05.529479",
            "credential": 1,
            "description": "",
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "{}",
            "failed": true,
            "finished": "2020-12-30T16:12:08.434925Z",
            "id": 2,
            "instance_group": null,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_tags": "",
            "job_template": 5,
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2020-12-30 16:12:08.435262",
            "name": "Demo Job Template",
            "passwords_needed_to_start": [],
            "playbook": "hello_world.yml",
            "project": 4,
            "result_traceback": "",
            "scm_revision": "",
            "skip_tags": "",
            "started": null,
            "status": "canceled",
            "timeout": 0,
            "type": "job",
            "url": "/api/v2/jobs/2/",
            "vault_credential": null
        }
    }
}
```

#### Human Readable Output

>### Job 2 status failed
>|name|id|type|url|created|modified|job_type|inventory|project|playbook|extra_vars|timeout|launch_type|status|failed|finished|elapsed|job_template|credential|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Demo Job Template | 2 | job | /api/v2/jobs/2/ | 2020-12-30 16:12:05.529479 | 2020-12-30 16:12:08.435262 | run | 1 | 4 | hello_world.yml | {} | 0 | manual | failed | true | 2020-12-30T16:12:08.434925Z | 0.0 | 5 | 1 |


### ansible-tower-job-events-list
***
Retrieves the list of job events.


#### Base Command

`ansible-tower-job-events-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the job event. | Optional | 
| page | The page number to retrieve. Default is 1. | Optional | 
| page_size | Page size. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description**                                                                                           |
| --- | --- |-----------------------------------------------------------------------------------------------------------|
| AnsibleAWX.JobEvents.id | Number | Database ID for this job event.                                                                           | 
| AnsibleAWX.JobEvents.type | String | Data type for this job event.                                                                             | 
| AnsibleAWX.JobEvents.url | String | URL for this job event.                                                                                   | 
| AnsibleAWX.JobEvents.created | Date | Timestamp indicating when this job event was created.                                                     | 
| AnsibleAWX.JobEvents.modified | Date | Timestamp indicating when this job event was last modified.                                               | 
| AnsibleAWX.JobEvents.job | Number | Job ID.                                                                                                   | 
| AnsibleAWX.JobEvents.event | String | The specific event. For example, runner_on_failed \(Host Failed\), runner_on_start \(Host Started\), etc. | 
| AnsibleAWX.JobEvents.counter | Number | Job event counter.                                                                                        | 
| AnsibleAWX.JobEvents.event_display | String | Event display. For example, Playbook Started.                                                             | 
| AnsibleAWX.JobEvents.event_level | Number | The event level.                                                                                          | 
| AnsibleAWX.JobEvents.failed | Boolean | Whether the job failed.                                                                                   | 
| AnsibleAWX.JobEvents.changed | Boolean | Whether the job changed.                                                                                  | 
| AnsibleAWX.JobEvents.uuid | String | UUID of the job event.                                                                                    | 
| AnsibleAWX.JobEvents.parent_uuid | String | Parent UUID.                                                                                              | 
| AnsibleAWX.JobEvents.host | Number | Host ID associated with the event.                                                                        | 
| AnsibleAWX.JobEvents.host_name | String | Host name associated with the event.                                                                      | 
| AnsibleAWX.JobEvents.playbook | String | Playbook name of this job.                                                                                | 
| AnsibleAWX.JobEvents.task | String | Task name.                                                                                                | 
| AnsibleAWX.JobEvents.stdout | String | Standard output of the job.                                                                               | 
| AnsibleAWX.JobEvents.start_line | Number | Starting line number of the execution.                                                                    | 
| AnsibleAWX.JobEvents.end_line | Number | Ending line number of the execution.                                                                      |

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
                "created": "2020-12-20 15:27:19.104059",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 1,
                "modified": "2020-12-20 15:27:19.137215",
                "parent_uuid": "",
                "playbook": "hello_world.yml",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/1/",
                "uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|type|id|url|created|modified|event|counter|event_display|event_level|failed|changed|uuid|parent_uuid|host|host_name|playbook|task|stdout|start_line|end_line|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| job_event | 1 | /api/v2/job_events/1/ | 2020-12-20 15:27:19.104059 | 2020-12-20 15:27:19.137215 | playbook_on_start | 1 | Playbook Started | 0 | false | false | 331e9ca5-56e2-4c2e-b77c-40fef9b95502 |  |  |  | hello_world.yml |  |  | 0 | 0 |

### ansible-tower-adhoc-command-launch
***
Creates new ad hoc commands.


#### Base Command

`ansible-tower-adhoc-command-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inventory_id | ID of the inventory. | Required | 
| credential_id | ID of the credential. | Required | 
| module_name | The name of the module.Modules are discrete units of code that can be used from the command line or in a playbook task. Ansible ships with a number of modules that can be executed directly on remote hosts or through playbooks. Possible values are: command, shell, yum, apt, apt_key, apt_repository, apt_rpm, service, group, user, mount, ping, selinux, setup, win_ping, win_service, win_updates, win_group, win_user. | Required | 
| module_args | Module arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommand.id | Number | Database ID for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.type | String | Data type for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.url | String | URL for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.created | Date | Timestamp indicating when this ad hoc command was created. | 
| AnsibleAWX.AdhocCommand.modified | Date | Timestamp indicating when this ad hoc command was last modified. | 
| AnsibleAWX.AdhocCommand.name | String | Name of this ad hoc command. | 
| AnsibleAWX.AdhocCommand.launch_type | String | Launch type of the job. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.AdhocCommand.status | String | Status of the job. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.AdhocCommand.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.AdhocCommand.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.AdhocCommand.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.AdhocCommand.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.AdhocCommand.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.AdhocCommand.execution_node | String | The node the job executed on. | 
| AnsibleAWX.AdhocCommand.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.AdhocCommand.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.AdhocCommand.inventory | Number | Inventory ID. | 
| AnsibleAWX.AdhocCommand.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.AdhocCommand.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 
| AnsibleAWX.AdhocCommand.module_name | String | Selected module name. | 
| AnsibleAWX.AdhocCommand.module_args | String | Module arguments. | 
| AnsibleAWX.AdhocCommand.extra_vars | String | Extra variables needed for the module running. | 
| AnsibleAWX.AdhocCommand.become_enabled | Boolean | Whether the ad hoc command become enabled. | 


#### Command Example
```!ansible-tower-adhoc-command-launch credential_id=1 inventory_id=1 module_name=ping```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "become_enabled": false,
            "controller_node": "",
            "created": "2021-01-14 09:22:18.554364",
            "credential": 1,
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "",
            "failed": false,
            "finished": null,
            "id": 1,
            "inventory": 1,
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-14 09:22:18.585043",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "started": null,
            "status": "new",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/1/"
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 1 status - new
>|name|id|type|url|created|modified|launch_type|status|failed|elapsed|job_type|inventory|credential|module_name|become_enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ping | 1 | ad_hoc_command | /api/v2/ad_hoc_commands/1/ | 2021-01-14 09:22:18.554364 | 2021-01-14 09:22:18.585043 | manual | new | false | 0.0 | run | 1 | 1 | ping | false |


### ansible-tower-adhoc-command-relaunch
***
Launch a new job to run the ad hoc command.


#### Base Command

`ansible-tower-adhoc-command-relaunch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | The ID of the command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommand.id | Number | Database ID for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.type | String | Data type for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.url | String | URL for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.created | Date | Timestamp indicating when this ad hoc command was created. | 
| AnsibleAWX.AdhocCommand.modified | Date | Timestamp indicating when this ad hoc command was last modified. | 
| AnsibleAWX.AdhocCommand.name | String | Name of this ad hoc command. | 
| AnsibleAWX.AdhocCommand.launch_type | String | Launch type. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.AdhocCommand.status | String | Status. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.AdhocCommand.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.AdhocCommand.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.AdhocCommand.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.AdhocCommand.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.AdhocCommand.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.AdhocCommand.execution_node | String | The node the job executed on | 
| AnsibleAWX.AdhocCommand.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.AdhocCommand.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.AdhocCommand.inventory | Number | Inventory ID. | 
| AnsibleAWX.AdhocCommand.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.AdhocCommand.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 
| AnsibleAWX.AdhocCommand.module_name | String | Selected module name. | 
| AnsibleAWX.AdhocCommand.module_args | String | Module arguments. | 
| AnsibleAWX.AdhocCommand.extra_vars | String | Extra variables needed for that module running. | 
| AnsibleAWX.AdhocCommand.become_enabled | Boolean | Whether the ad hoc command become enabled. | 


#### Command Example
```!ansible-tower-adhoc-command-relaunch command_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "ad_hoc_command": 2,
            "become_enabled": false,
            "controller_node": "",
            "created": "2021-01-14 09:22:20.700721",
            "credential": 1,
            "elapsed": 0,
            "execution_node": "",
            "extra_vars": "",
            "failed": false,
            "finished": null,
            "id": 2,
            "inventory": 1,
            "job_args": "",
            "job_cwd": "",
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-14 09:22:20.748133",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "result_traceback": "",
            "started": null,
            "status": "pending",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/2/"
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 2 status - pending
>|name|id|type|url|created|modified|launch_type|status|failed|elapsed|job_type|inventory|credential|module_name|become_enabled|ad_hoc_command|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ping | 2 | ad_hoc_command | /api/v2/ad_hoc_commands/2/ | 2021-01-14 09:22:20.700721 | 2021-01-14 09:22:20.748133 | manual | pending | false | 0.0 | run | 1 | 1 | ping | false | 2 |


### ansible-tower-adhoc-command-cancel
***
Cancel a job of the specified ad hoc command.


#### Base Command

`ansible-tower-adhoc-command-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | The ID of the command to cancel. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommand.id | Number | Database ID for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.type | String | Data type for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.url | String | URL for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.created | Date | Timestamp indicating when this ad hoc command was created. | 
| AnsibleAWX.AdhocCommand.modified | Date | Timestamp indicating when this ad hoc command was last modified. | 
| AnsibleAWX.AdhocCommand.name | String | Name of this ad hoc command. | 
| AnsibleAWX.AdhocCommand.launch_type | String | Launch type. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.AdhocCommand.status | String | Status. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.AdhocCommand.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.AdhocCommand.started | None | The date and time the job was queued to start. | 
| AnsibleAWX.AdhocCommand.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.AdhocCommand.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.AdhocCommand.job_args | String | Job arguments. | 
| AnsibleAWX.AdhocCommand.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.AdhocCommand.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.AdhocCommand.execution_node | String | The node the job executed on. | 
| AnsibleAWX.AdhocCommand.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.AdhocCommand.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.AdhocCommand.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.AdhocCommand.inventory | Number | Inventory ID. | 
| AnsibleAWX.AdhocCommand.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.AdhocCommand.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 
| AnsibleAWX.AdhocCommand.module_name | String | Selected module name. | 
| AnsibleAWX.AdhocCommand.module_args | String | Module arguments. | 
| AnsibleAWX.AdhocCommand.extra_vars | String | Extra variables needed for that module running. | 
| AnsibleAWX.AdhocCommand.become_enabled | Boolean | Whether the ad hoc command become enabled. | 


#### Command Example
```!ansible-tower-adhoc-command-cancel command_id=2```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "become_enabled": false,
            "controller_node": "",
            "created": "2021-01-14 12:21:28.382292",
            "credential": 1,
            "elapsed": 2.280328,
            "execution_node": "awx",
            "extra_vars": "",
            "failed": true,
            "finished": "2021-01-14 12:21:28.668796",
            "id": 2,
            "inventory": 1,
            "job_args": "[]",
            "job_cwd": "",
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2021-01-14 12:21:30.557684",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "result_traceback": "",
            "started": "2021-01-14T12:21:28.668796Z",
            "status": "canceled",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/2/"
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 2 status - canceled
>|name|id|type|url|created|modified|launch_type|status|failed|started|elapsed|job_args|job_cwd|execution_node|job_type|inventory|credential|module_name|become_enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ping | 2 | ad_hoc_command | /api/v2/ad_hoc_commands/2/ | 2021-01-14 12:21:28.382292 | 2021-01-14 12:21:30.557684 | manual | canceled | false | 2021-01-14T12:21:28.668796Z | 2.280328 | [] |  | awx | run | 1 | 1 | ping | false |




### ansible-tower-adhoc-command-stdout
***
Retrieves the standard output from running this ad hoc command.


#### Base Command

`ansible-tower-adhoc-command-stdout`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | The ID of the command to run. | Required | 
| print_output | Prints the ad hoc command output. Possible values are: "True" and "False". Default is "True". Possible values are: True, False. Default is True. | Optional | 
| text_filter | The string by which to filter lines in the standard output. For example, enter 'success' to filter the standard output lines containing this word. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommandStdout.content | String | Standard output content. | 


#### Command Example
```!ansible-tower-adhoc-command-stdout command_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommandStdout": {
            "command_id": "1",
            "content": "\u001b[1;31mteat_demo | UNREACHABLE! => {\u001b[0m\n\u001b[1;31m    \"changed\": false, \u001b[0m\n\u001b[1;31m    \"msg\": \"Failed to connect to the host via ssh: ssh: Could not resolve hostname teat_demo: Name or service not known\\\\r\\\\n\", \u001b[0m\n\u001b[1;31m    \"unreachable\": true\u001b[0m\n\u001b[1;31m}\u001b[0m\n\u001b[0;32mlocalhost | SUCCESS => {\u001b[0m\n\u001b[0;32m    \"changed\": false, \u001b[0m\n\u001b[0;32m    \"ping\": \"pong\"\u001b[0m\n\u001b[0;32m}\u001b[0m\n\n"
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command 1 output ### 
>
>[1;31m test_demo | UNREACHABLE! => {[0m
>[1;31m    "changed": false, [0m
>[1;31m    "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname teat_demo: Name or service not known", [0m 
>[1;31m    "unreachable": true[0m
>[1;31m}[0m
>
>


### ansible-tower-adhoc-command-status
***
Retrieves a single ad hoc command status.


#### Base Command

`ansible-tower-adhoc-command-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | The ID of the command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.AdhocCommand.id | Number | Database ID for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.type | String | Data type for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.url | String | URL for this ad hoc command. | 
| AnsibleAWX.AdhocCommand.created | Date | Timestamp indicating when this ad hoc command was created. | 
| AnsibleAWX.AdhocCommand.modified | Date | Timestamp indicating when this ad hoc command was last modified. | 
| AnsibleAWX.AdhocCommand.name | String | Name of this ad hoc command. | 
| AnsibleAWX.AdhocCommand.launch_type | String | Launch type. Can be manual, relaunch, callback, scheduled, dependency, workflow, webhook, sync, or scm. | 
| AnsibleAWX.AdhocCommand.status | String | Status. Can be new, pending, waiting, running, successful, failed, error, canceled, or never updated. | 
| AnsibleAWX.AdhocCommand.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.AdhocCommand.started | Date | The date and time the job was queued to start. | 
| AnsibleAWX.AdhocCommand.finished | Date | The date and time the job finished execution. | 
| AnsibleAWX.AdhocCommand.elapsed | Number | The amount of time in seconds that it took the job to run. | 
| AnsibleAWX.AdhocCommand.job_args | String | Job arguments. | 
| AnsibleAWX.AdhocCommand.job_cwd | String | Current working directory \(CWD\) of the job. | 
| AnsibleAWX.AdhocCommand.job_explanation | String | Indicates the state of the job if it was not able to run and capture the standard output. | 
| AnsibleAWX.AdhocCommand.execution_node | String | The node the job executed on. | 
| AnsibleAWX.AdhocCommand.controller_node | String | The instance that managed the isolated execution environment. | 
| AnsibleAWX.AdhocCommand.result_traceback | String | The traceback of the result. | 
| AnsibleAWX.AdhocCommand.job_type | String | Job type. Possible values are "run" and "check". | 
| AnsibleAWX.AdhocCommand.inventory | Number | Inventory ID. | 
| AnsibleAWX.AdhocCommand.limit | String | The host pattern that will limit the list of hosts that will be managed or affected by the playbook. | 
| AnsibleAWX.AdhocCommand.credential | Number | Credential ID that allowed Tower to access the node this job was run against. | 
| AnsibleAWX.AdhocCommand.module_name | String | Selected module name. | 
| AnsibleAWX.AdhocCommand.module_args | String | Module arguments. | 
| AnsibleAWX.AdhocCommand.extra_vars | String | Extra variables needed for that module running. | 
| AnsibleAWX.AdhocCommand.become_enabled | Boolean | Whether the ad hoc command become enabled. | 


#### Command Example
```!ansible-tower-adhoc-command-status command_id=1```

#### Context Example
```json
{
    "AnsibleAWX": {
        "AdhocCommand": {
            "become_enabled": false,
            "controller_node": "",
            "created": "2020-12-29 13:28:21.538400",
            "credential": 1,
            "elapsed": 2.2,
            "execution_node": "awx",
            "extra_vars": "",
            "failed": true,
            "finished": "2020-12-29T13:28:24.029843Z",
            "id": 1,
            "inventory": 1,
            "job_args": "[]",
            "job_cwd": "",
            "job_explanation": "",
            "job_type": "run",
            "launch_type": "manual",
            "limit": "",
            "modified": "2020-12-29 13:28:21.763189",
            "module_args": "",
            "module_name": "ping",
            "name": "ping",
            "result_traceback": "",
            "started": "2020-12-29T13:28:21.829663Z",
            "status": "failed",
            "type": "ad_hoc_command",
            "url": "/api/v2/ad_hoc_commands/1/"
        }
    }
}
```

#### Human Readable Output

>### Ad hoc command - 1 status - failed
>|name|id|type|url|created|modified|launch_type|status|failed|started|finished|elapsed|job_args|job_cwd|execution_node|job_type|inventory|credential|module_name|become_enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ping | 1 | ad_hoc_command | /api/v2/ad_hoc_commands/1/ | 2020-12-29 13:28:21.538400 | 2020-12-29 13:28:21.763189 | manual | failed | true | 2020-12-29T13:28:21.829663Z | 2020-12-29T13:28:24.029843Z | 2.2 | [] |  | awx | run | 1 | 1 | ping | false |

### ansible-tower-job-events-list-by-id
***
Retrieves the list of job events of specific job.


#### Base Command

`ansible-tower-job-events-list-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job event. | Required | 
| page | The page number to retrieve. Default is 1. Default is 1. | Optional | 
| page_size | Page size. Default is 50. Default is 50. | Optional | 
| search | The search query string used to perform a case-insensitive search within all designated text fields of a model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnsibleAWX.JobEvents.id | Number | Database ID for this job event. | 
| AnsibleAWX.JobEvents.type | String | Data type for this job event. | 
| AnsibleAWX.JobEvents.url | String | URL for this job event. | 
| AnsibleAWX.JobEvents.created | Date | Timestamp indicating when this job event was created. | 
| AnsibleAWX.JobEvents.modified | Date | Timestamp indicating when this job event was last modified. | 
| AnsibleAWX.JobEvents.job | Number | Job ID. | 
| AnsibleAWX.JobEvents.event | String | The specific event. For example, runner_on_failed \(Host Failed\), runner_on_start \(Host Started\), etc. | 
| AnsibleAWX.JobEvents.counter | Number | Job event counter. | 
| AnsibleAWX.JobEvents.event_display | String | Event display. For example, Playbook Started. | 
| AnsibleAWX.JobEvents.event_level | Number | The event level. | 
| AnsibleAWX.JobEvents.failed | Boolean | Whether the job failed. | 
| AnsibleAWX.JobEvents.changed | Boolean | Whether the job changed. | 
| AnsibleAWX.JobEvents.uuid | String | UUID of the job event. | 
| AnsibleAWX.JobEvents.parent_uuid | String | Parent UUID. | 
| AnsibleAWX.JobEvents.host | Number | Host ID associated with the event. | 
| AnsibleAWX.JobEvents.host_name | String | Host name associated with the event. | 
| AnsibleAWX.JobEvents.playbook | String | Playbook name of this job. | 
| AnsibleAWX.JobEvents.task | String | Task name. | 
| AnsibleAWX.JobEvents.stdout | String | Standard output of the job. | 
| AnsibleAWX.JobEvents.start_line | Number | Starting line number of the execution. | 
| AnsibleAWX.JobEvents.end_line | Number | Ending line number of the execution. | 
| AnsibleAWX.JobEvents.event_data | String | Job's raw event data.                                                                                     | 

#### Command Example
```!ansible-tower-job-events-list-by-id job_id=69```

#### Context Example
```json
{
    "AnsibleAWX": {
        "JobEvents": [
            {
                "changed": false,
                "counter": 1,
                "created": "2020-12-20 15:27:19.104059",
                "end_line": 0,
                "event": "playbook_on_start",
                "event_display": "Playbook Started",
                "event_level": 0,
                "failed": false,
                "host": null,
                "host_name": "",
                "id": 1,
                "modified": "2020-12-20 15:27:19.137215",
                "parent_uuid": "",
                "playbook": "hello_world.yml",
                "start_line": 0,
                "stdout": "",
                "task": "",
                "type": "job_event",
                "url": "/api/v2/job_events/1/",
                "event_data": {},
                "uuid": "331e9ca5-56e2-4c2e-b77c-40fef9b95502"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|type|id|url|created|modified|event|counter|event_display|event_level|failed|changed|uuid|parent_uuid|host|host_name|playbook|task|stdout|start_line|end_line|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| job_event | 1 | /api/v2/job_events/1/ | 2020-12-20 15:27:19.104059 | 2020-12-20 15:27:19.137215 | playbook_on_start | 1 | Playbook Started | 0 | false | false | 331e9ca5-56e2-4c2e-b77c-40fef9b95502 |  |  |  | hello_world.yml |  |  | 0 | 0 |