# Databricks Integration

Comprehensive integration with Databricks workspace APIs for managing clusters, jobs, SQL, pipelines, Unity Catalog, MLflow, IAM, and more.

This integration was integrated and tested with the Databricks REST API.

## Configure Databricks on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Databricks**.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Databricks Workspace URL | e.g., https://dbc-xxxxx.cloud.databricks.com | True |
| Personal Access Token |  | True |
| Trust any certificate (not secure) | Default: false. | False |
| Use system proxy settings | Default: false. | False |
| Fetch incidents | Default: false. | False |
| Incident type |  | False |
| Fetch types | Types of events to fetch as incidents. | False |
| Maximum incidents per fetch | Default: 50. | False |
| First fetch time | e.g., 3 days, 1 week Default: 3 days. | False |
| Incidents Fetch Interval | Default: 1. | False |

4. Click **Test** to validate the connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message is shown in the War Room with the command details.

### Total Commands: 193

### databricks-cluster-get

***

Retrieves information about a cluster by its ID.

#### Base Command

`databricks-cluster-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Cluster.cluster_id | String | The unique identifier of the cluster. |
| Databricks.Cluster.cluster_name | String | The name of the cluster. |
| Databricks.Cluster.state | String | The current state of the cluster. |
| Databricks.Cluster.creator_user_name | String | The user who created the cluster. |
| Databricks.Cluster.spark_version | String | The Spark version of the cluster. |
| Databricks.Cluster.node_type_id | String | The node type of the cluster workers. |
| Databricks.Cluster.num_workers | Number | The number of workers in the cluster. |
| Databricks.Cluster.autotermination_minutes | Number | Auto-termination time in minutes. |
| Databricks.Cluster.start_time | Date | The time the cluster was started. |
| Databricks.Cluster.cluster_source | String | The source that created the cluster. |

#### Command Example

```!databricks-cluster-get cluster_id=0831-000000-abcdefgh```

### databricks-cluster-list

***

Lists all clusters in the workspace.

#### Base Command

`databricks-cluster-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Cluster.cluster_id | String | The unique identifier of the cluster. |
| Databricks.Cluster.cluster_name | String | The name of the cluster. |
| Databricks.Cluster.state | String | The current state of the cluster. |
| Databricks.Cluster.creator_user_name | String | The user who created the cluster. |
| Databricks.Cluster.spark_version | String | The Spark version of the cluster. |
| Databricks.Cluster.node_type_id | String | The node type of the cluster workers. |
| Databricks.Cluster.num_workers | Number | The number of workers in the cluster. |
| Databricks.Cluster.autotermination_minutes | Number | Auto-termination time in minutes. |
| Databricks.Cluster.start_time | Date | The time the cluster was started. |
| Databricks.Cluster.cluster_source | String | The source that created the cluster. |

#### Command Example

```!databricks-cluster-list```

### databricks-cluster-create

***

Creates a new Databricks cluster.

#### Base Command

`databricks-cluster-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name for the new cluster. | Required |
| spark_version | The Spark version for the cluster. | Required |
| node_type_id | The node type ID for cluster workers. | Required |
| num_workers | The number of workers for the cluster. | Optional |
| autotermination_minutes | Auto-termination time in minutes. | Optional |
| custom_tags | Custom tags as a JSON string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Cluster.cluster_id | String | The ID of the newly created cluster. |

#### Command Example

```!databricks-cluster-create cluster_name="test-cluster" spark_version="14.3.x-scala2.12" node_type_id="i3.xlarge" num_workers="2"```

### databricks-cluster-edit

***

Edits the configuration of an existing cluster.

#### Base Command

`databricks-cluster-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to edit. | Required |
| cluster_name | New name for the cluster. | Optional |
| spark_version | New Spark version for the cluster. | Optional |
| node_type_id | New node type ID for cluster workers. | Optional |
| num_workers | New number of workers. | Optional |
| autotermination_minutes | New auto-termination time in minutes. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-edit```

### databricks-cluster-delete

***

Terminates a cluster.

#### Base Command

`databricks-cluster-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to terminate. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-delete cluster_id=0831-000000-abcdefgh```

### databricks-cluster-permanent-delete

***

Permanently deletes a cluster.

#### Base Command

`databricks-cluster-permanent-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to permanently delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-permanent-delete```

### databricks-cluster-start

***

Starts a previously terminated cluster.

#### Base Command

`databricks-cluster-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to start. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-start cluster_id=0831-000000-abcdefgh```

### databricks-cluster-restart

***

Restarts a running cluster.

#### Base Command

`databricks-cluster-restart`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to restart. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-restart cluster_id=0831-000000-abcdefgh```

### databricks-cluster-resize

***

Resizes a cluster by changing the number of workers.

#### Base Command

`databricks-cluster-resize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to resize. | Required |
| num_workers | The new number of workers. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-resize```

### databricks-cluster-pin

***

Pins a cluster to keep it visible in the cluster list.

#### Base Command

`databricks-cluster-pin`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to pin. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-pin cluster_id=0831-000000-abcdefgh```

### databricks-cluster-unpin

***

Unpins a cluster.

#### Base Command

`databricks-cluster-unpin`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to unpin. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-unpin cluster_id=0831-000000-abcdefgh```

### databricks-cluster-change-owner

***

Changes the owner of a cluster.

#### Base Command

`databricks-cluster-change-owner`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| owner_username | The username of the new owner. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-change-owner```

### databricks-cluster-list-zones

***

Lists available availability zones for cluster deployment.

#### Base Command

`databricks-cluster-list-zones`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Zone.zones | Unknown | List of available zones. |

#### Command Example

```!databricks-cluster-list-zones```

### databricks-cluster-update

***

Updates specific properties of a cluster.

#### Base Command

`databricks-cluster-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster to update. | Required |
| cluster_name | New name for the cluster. | Optional |
| spark_version | New Spark version for the cluster. | Optional |
| node_type_id | New node type ID for cluster workers. | Optional |
| num_workers | New number of workers. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-update```

### databricks-cluster-policy-get

***

Retrieves a cluster policy by its ID.

#### Base Command

`databricks-cluster-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the cluster policy to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ClusterPolicy.policy_id | String | The unique identifier of the policy. |
| Databricks.ClusterPolicy.name | String | The name of the policy. |
| Databricks.ClusterPolicy.definition | String | The policy definition as a JSON string. |
| Databricks.ClusterPolicy.creator_user_name | String | The user who created the policy. |
| Databricks.ClusterPolicy.created_at_timestamp | Date | When the policy was created. |

#### Command Example

```!databricks-cluster-policy-get policy_id=ABC123```

### databricks-cluster-policy-list

***

Lists all cluster policies in the workspace.

#### Base Command

`databricks-cluster-policy-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ClusterPolicy.policy_id | String | The unique identifier of the policy. |
| Databricks.ClusterPolicy.name | String | The name of the policy. |
| Databricks.ClusterPolicy.definition | String | The policy definition as a JSON string. |
| Databricks.ClusterPolicy.creator_user_name | String | The user who created the policy. |
| Databricks.ClusterPolicy.created_at_timestamp | Date | When the policy was created. |

#### Command Example

```!databricks-cluster-policy-list```

### databricks-cluster-policy-create

***

Creates a new cluster policy.

#### Base Command

`databricks-cluster-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the cluster policy. | Required |
| definition | The policy definition as a JSON string. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ClusterPolicy.policy_id | String | The ID of the newly created policy. |

#### Command Example

```!databricks-cluster-policy-create```

### databricks-cluster-policy-edit

***

Edits an existing cluster policy.

#### Base Command

`databricks-cluster-policy-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy to edit. | Required |
| name | New name for the policy. | Optional |
| definition | New policy definition as a JSON string. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-policy-edit```

### databricks-cluster-policy-delete

***

Deletes a cluster policy.

#### Base Command

`databricks-cluster-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-cluster-policy-delete```

### databricks-instance-pool-get

***

Retrieves information about an instance pool.

#### Base Command

`databricks-instance-pool-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_pool_id | The ID of the instance pool. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.InstancePool.instance_pool_id | String | The unique identifier of the pool. |
| Databricks.InstancePool.instance_pool_name | String | The name of the pool. |
| Databricks.InstancePool.node_type_id | String | The node type ID used by the pool. |
| Databricks.InstancePool.min_idle_instances | Number | Minimum number of idle instances maintained. |
| Databricks.InstancePool.max_capacity | Number | Maximum number of instances in the pool. |
| Databricks.InstancePool.state | String | The current state of the pool. |

#### Command Example

```!databricks-instance-pool-get instance_pool_id=0831-pool-1```

### databricks-instance-pool-list

***

Lists all instance pools in the workspace.

#### Base Command

`databricks-instance-pool-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.InstancePool.instance_pool_id | String | The unique identifier of the pool. |
| Databricks.InstancePool.instance_pool_name | String | The name of the pool. |
| Databricks.InstancePool.node_type_id | String | The node type ID used by the pool. |
| Databricks.InstancePool.min_idle_instances | Number | Minimum number of idle instances maintained. |
| Databricks.InstancePool.max_capacity | Number | Maximum number of instances in the pool. |
| Databricks.InstancePool.state | String | The current state of the pool. |

#### Command Example

```!databricks-instance-pool-list```

### databricks-instance-pool-create

***

Creates a new instance pool.

#### Base Command

`databricks-instance-pool-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_pool_name | The name of the instance pool. | Required |
| node_type_id | The node type ID for the pool. | Required |
| min_idle_instances | Minimum number of idle instances. | Optional |
| max_capacity | Maximum number of instances in the pool. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.InstancePool.instance_pool_id | String | The ID of the newly created pool. |

#### Command Example

```!databricks-instance-pool-create```

### databricks-instance-pool-edit

***

Edits an existing instance pool.

#### Base Command

`databricks-instance-pool-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_pool_id | The ID of the pool to edit. | Required |
| instance_pool_name | New name for the pool. | Optional |
| node_type_id | New node type ID. | Optional |
| min_idle_instances | New minimum number of idle instances. | Optional |
| max_capacity | New maximum capacity. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-instance-pool-edit```

### databricks-instance-pool-delete

***

Deletes an instance pool.

#### Base Command

`databricks-instance-pool-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_pool_id | The ID of the pool to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-instance-pool-delete```

### databricks-library-cluster-status

***

Retrieves the status of libraries on a specific cluster.

#### Base Command

`databricks-library-cluster-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.LibraryStatus.library | Unknown | The library specification. |
| Databricks.LibraryStatus.status | String | The installation status of the library. |
| Databricks.LibraryStatus.is_library_for_all_clusters | Boolean | Whether the library is installed on all clusters. |

#### Command Example

```!databricks-library-cluster-status cluster_id=0831-000000-abcdefgh```

### databricks-library-all-cluster-statuses

***

Retrieves library statuses for all clusters.

#### Base Command

`databricks-library-all-cluster-statuses`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.LibraryClusterStatus.cluster_id | String | The cluster ID. |
| Databricks.LibraryClusterStatus.library_statuses | Unknown | The library statuses for this cluster. |

#### Command Example

```!databricks-library-all-cluster-statuses```

### databricks-library-install

***

Installs libraries on a cluster.

#### Base Command

`databricks-library-install`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| libraries | JSON array of library specifications to install. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-library-install```

### databricks-library-uninstall

***

Uninstalls libraries from a cluster.

#### Base Command

`databricks-library-uninstall`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| libraries | JSON array of library specifications to uninstall. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-library-uninstall```

### databricks-context-create

***

Creates an execution context on a cluster.

#### Base Command

`databricks-context-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| language | The programming language for the context. Possible values are: python, scala, sql, r. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Context.id | String | The ID of the created execution context. |

#### Command Example

```!databricks-context-create```

### databricks-context-destroy

***

Destroys an execution context.

#### Base Command

`databricks-context-destroy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| context_id | The ID of the context to destroy. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-context-destroy```

### databricks-context-status

***

Gets the status of an execution context.

#### Base Command

`databricks-context-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| context_id | The ID of the context. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Context.id | String | The ID of the context. |
| Databricks.Context.status | String | The status of the context. |

#### Command Example

```!databricks-context-status```

### databricks-command-execute

***

Executes a command in an execution context.

#### Base Command

`databricks-command-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| context_id | The ID of the execution context. | Required |
| language | The programming language. Possible values are: python, scala, sql, r. | Required |
| command | The command text to execute. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Command.id | String | The ID of the command. |
| Databricks.Command.status | String | The execution status of the command. |

#### Command Example

```!databricks-command-execute```

### databricks-command-status

***

Gets the status and results of a command.

#### Base Command

`databricks-command-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| command_id | The ID of the command. | Required |
| context_id | The ID of the execution context. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Command.id | String | The ID of the command. |
| Databricks.Command.status | String | The execution status of the command. |
| Databricks.Command.results | Unknown | The results of the command execution. |

#### Command Example

```!databricks-command-status```

### databricks-command-cancel

***

Cancels a running command.

#### Base Command

`databricks-command-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The ID of the cluster. | Required |
| command_id | The ID of the command to cancel. | Required |
| context_id | The ID of the execution context. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-command-cancel```

### databricks-job-get

***

Retrieves details about a specific job.

#### Base Command

`databricks-job-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Job.job_id | Number | The unique identifier of the job. |
| Databricks.Job.settings | Unknown | The settings of the job. |
| Databricks.Job.creator_user_name | String | The user who created the job. |
| Databricks.Job.created_time | Date | When the job was created. |

#### Command Example

```!databricks-job-get job_id=12345```

### databricks-job-list

***

Lists all jobs in the workspace.

#### Base Command

`databricks-job-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of jobs to return. Default is 20. | Optional |
| offset | Offset for pagination. | Optional |
| name | Filter jobs by name. | Optional |
| expand_tasks | Whether to include task details. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Job.job_id | Number | The unique identifier of the job. |
| Databricks.Job.settings | Unknown | The settings of the job. |
| Databricks.Job.creator_user_name | String | The user who created the job. |
| Databricks.Job.created_time | Date | When the job was created. |

#### Command Example

```!databricks-job-list```

### databricks-job-create

***

Creates a new job.

#### Base Command

`databricks-job-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the job. | Required |
| tasks | JSON string defining the job tasks. | Required |
| schedule | JSON string defining the schedule. | Optional |
| max_concurrent_runs | Maximum number of concurrent runs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Job.job_id | Number | The ID of the newly created job. |

#### Command Example

```!databricks-job-create name="my-job" tasks='[{"task_key":"t1","notebook_task":{"notebook_path":"/test"}}]'```

### databricks-job-reset

***

Overwrites all settings of an existing job.

#### Base Command

`databricks-job-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job to reset. | Required |
| new_settings | JSON string with the new job settings. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-job-reset```

### databricks-job-update

***

Partially updates a job.

#### Base Command

`databricks-job-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job to update. | Required |
| fields_to_update | JSON string with the fields to update. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-job-update```

### databricks-job-delete

***

Deletes a job.

#### Base Command

`databricks-job-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-job-delete job_id=12345```

### databricks-job-run-now

***

Triggers an immediate run of a job.

#### Base Command

`databricks-job-run-now`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The ID of the job to run. | Required |
| notebook_params | JSON string of notebook parameters. | Optional |
| python_params | JSON string of Python parameters. | Optional |
| jar_params | JSON string of JAR parameters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.JobRun.run_id | Number | The ID of the triggered run. |
| Databricks.JobRun.number_in_job | Number | The run number within the job. |

#### Command Example

```!databricks-job-run-now job_id=12345```

### databricks-pipeline-get

***

Retrieves details about a pipeline.

#### Base Command

`databricks-pipeline-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Pipeline.pipeline_id | String | The unique identifier of the pipeline. |
| Databricks.Pipeline.name | String | The name of the pipeline. |
| Databricks.Pipeline.state | String | The current state of the pipeline. |
| Databricks.Pipeline.creator_user_name | String | The user who created the pipeline. |
| Databricks.Pipeline.cluster_id | String | The cluster ID associated with the pipeline. |

#### Command Example

```!databricks-pipeline-get pipeline_id=abc-123-def```

### databricks-pipeline-list

***

Lists pipelines in the workspace.

#### Base Command

`databricks-pipeline-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum number of pipelines to return. | Optional |
| filter | Filter string for pipelines. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Pipeline.pipeline_id | String | The unique identifier of the pipeline. |
| Databricks.Pipeline.name | String | The name of the pipeline. |
| Databricks.Pipeline.state | String | The current state of the pipeline. |
| Databricks.Pipeline.creator_user_name | String | The user who created the pipeline. |

#### Command Example

```!databricks-pipeline-list```

### databricks-pipeline-create

***

Creates a new pipeline.

#### Base Command

`databricks-pipeline-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the pipeline. | Required |
| configuration | Pipeline configuration as a JSON string. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Pipeline.pipeline_id | String | The ID of the newly created pipeline. |

#### Command Example

```!databricks-pipeline-create```

### databricks-pipeline-update

***

Updates an existing pipeline.

#### Base Command

`databricks-pipeline-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline to update. | Required |
| configuration | New pipeline configuration as a JSON string. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-pipeline-update```

### databricks-pipeline-delete

***

Deletes a pipeline.

#### Base Command

`databricks-pipeline-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-pipeline-delete```

### databricks-pipeline-clone

***

Clones an existing pipeline.

#### Base Command

`databricks-pipeline-clone`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline to clone. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Pipeline.pipeline_id | String | The ID of the cloned pipeline. |

#### Command Example

```!databricks-pipeline-clone```

### databricks-pipeline-start

***

Starts a pipeline update.

#### Base Command

`databricks-pipeline-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline to start. | Required |
| full_refresh | Whether to do a full refresh. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.PipelineUpdate.update_id | String | The ID of the triggered update. |

#### Command Example

```!databricks-pipeline-start```

### databricks-pipeline-stop

***

Stops a running pipeline.

#### Base Command

`databricks-pipeline-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline to stop. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-pipeline-stop```

### databricks-pipeline-events

***

Retrieves events for a pipeline.

#### Base Command

`databricks-pipeline-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline. | Required |
| max_results | Maximum number of events to return. | Optional |
| filter | Filter string for events. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.PipelineEvent.id | String | The unique identifier of the event. |
| Databricks.PipelineEvent.timestamp | Date | When the event occurred. |
| Databricks.PipelineEvent.event_type | String | The type of event. |
| Databricks.PipelineEvent.message | String | The event message. |
| Databricks.PipelineEvent.level | String | The severity level of the event. |

#### Command Example

```!databricks-pipeline-events```

### databricks-pipeline-list-updates

***

Lists updates for a pipeline.

#### Base Command

`databricks-pipeline-list-updates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline. | Required |
| max_results | Maximum number of updates to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.PipelineUpdate.update_id | String | The unique identifier of the update. |
| Databricks.PipelineUpdate.state | String | The state of the update. |
| Databricks.PipelineUpdate.creation_time | Date | When the update was created. |

#### Command Example

```!databricks-pipeline-list-updates```

### databricks-pipeline-get-update

***

Retrieves a specific pipeline update.

#### Base Command

`databricks-pipeline-get-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline. | Required |
| update_id | The ID of the update. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.PipelineUpdate.update_id | String | The unique identifier of the update. |
| Databricks.PipelineUpdate.state | String | The state of the update. |
| Databricks.PipelineUpdate.creation_time | Date | When the update was created. |
| Databricks.PipelineUpdate.config | Unknown | The update configuration. |

#### Command Example

```!databricks-pipeline-get-update```

### databricks-pipeline-apply-environment

***

Applies environment settings to a pipeline.

#### Base Command

`databricks-pipeline-apply-environment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pipeline_id | The ID of the pipeline. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-pipeline-apply-environment```

### databricks-dbfs-get-status

***

Gets the status of a file or directory in DBFS.

#### Base Command

`databricks-dbfs-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS path. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.DBFS.path | String | The DBFS path. |
| Databricks.DBFS.is_dir | Boolean | Whether the path is a directory. |
| Databricks.DBFS.file_size | Number | The file size in bytes. |
| Databricks.DBFS.modification_time | Date | Last modification time. |

#### Command Example

```!databricks-dbfs-get-status path=/tmp```

### databricks-dbfs-list

***

Lists the contents of a DBFS directory.

#### Base Command

`databricks-dbfs-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS directory path. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.DBFS.path | String | The DBFS path. |
| Databricks.DBFS.is_dir | Boolean | Whether the path is a directory. |
| Databricks.DBFS.file_size | Number | The file size in bytes. |
| Databricks.DBFS.modification_time | Date | Last modification time. |

#### Command Example

```!databricks-dbfs-list path=/```

### databricks-dbfs-read

***

Reads the contents of a file in DBFS.

#### Base Command

`databricks-dbfs-read`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS file path. | Required |
| offset | The byte offset to start reading from. | Optional |
| length | The number of bytes to read. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.DBFSFile.bytes_read | Number | The number of bytes read. |
| Databricks.DBFSFile.data | String | The base64-encoded file content. |

#### Command Example

```!databricks-dbfs-read```

### databricks-dbfs-create

***

Opens a stream to write a file in DBFS.

#### Base Command

`databricks-dbfs-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS file path. | Required |
| overwrite | Whether to overwrite existing file. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.DBFSStream.handle | Number | The handle for the write stream. |

#### Command Example

```!databricks-dbfs-create```

### databricks-dbfs-add-block

***

Appends a block of data to a DBFS write stream.

#### Base Command

`databricks-dbfs-add-block`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| handle | The handle of the write stream. | Required |
| data | Base64-encoded data block to append. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-add-block```

### databricks-dbfs-close

***

Closes a DBFS write stream.

#### Base Command

`databricks-dbfs-close`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| handle | The handle of the write stream to close. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-close```

### databricks-dbfs-put

***

Uploads a file to DBFS.

#### Base Command

`databricks-dbfs-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS file path. | Required |
| contents | Base64-encoded file contents. | Optional |
| overwrite | Whether to overwrite existing file. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-put```

### databricks-dbfs-delete

***

Deletes a file or directory in DBFS.

#### Base Command

`databricks-dbfs-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS path to delete. | Required |
| recursive | Whether to delete recursively. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-delete```

### databricks-dbfs-mkdirs

***

Creates a directory in DBFS.

#### Base Command

`databricks-dbfs-mkdirs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The DBFS directory path to create. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-mkdirs path=/tmp/test```

### databricks-dbfs-move

***

Moves a file or directory in DBFS.

#### Base Command

`databricks-dbfs-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_path | The source DBFS path. | Required |
| destination_path | The destination DBFS path. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dbfs-move```

### databricks-workspace-get-status

***

Gets the status of a workspace object.

#### Base Command

`databricks-workspace-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace path. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.WorkspaceObject.object_type | String | The type of workspace object. |
| Databricks.WorkspaceObject.path | String | The workspace path. |
| Databricks.WorkspaceObject.object_id | Number | The unique identifier of the object. |
| Databricks.WorkspaceObject.language | String | The language of the notebook. |

#### Command Example

```!databricks-workspace-get-status path=/Shared```

### databricks-workspace-list

***

Lists the contents of a workspace directory.

#### Base Command

`databricks-workspace-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace directory path. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.WorkspaceObject.object_type | String | The type of workspace object. |
| Databricks.WorkspaceObject.path | String | The workspace path. |
| Databricks.WorkspaceObject.object_id | Number | The unique identifier of the object. |
| Databricks.WorkspaceObject.language | String | The language of the notebook. |

#### Command Example

```!databricks-workspace-list path=/```

### databricks-workspace-export

***

Exports a workspace object.

#### Base Command

`databricks-workspace-export`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace path to export. | Required |
| format | The export format. Possible values are: SOURCE, HTML, JUPYTER, DBC. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.WorkspaceExport.content | String | The base64-encoded exported content. |

#### Command Example

```!databricks-workspace-export path=/Shared/notebook format=SOURCE```

### databricks-workspace-import

***

Imports a workspace object.

#### Base Command

`databricks-workspace-import`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace destination path. | Required |
| content | Base64-encoded content to import. | Required |
| format | The import format. Possible values are: SOURCE, HTML, JUPYTER, DBC. | Optional |
| language | The language for the notebook. Possible values are: PYTHON, SCALA, SQL, R. | Optional |
| overwrite | Whether to overwrite existing object. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-workspace-import```

### databricks-workspace-delete

***

Deletes a workspace object.

#### Base Command

`databricks-workspace-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace path to delete. | Required |
| recursive | Whether to delete recursively. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-workspace-delete```

### databricks-workspace-mkdirs

***

Creates a directory in the workspace.

#### Base Command

`databricks-workspace-mkdirs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The workspace directory path to create. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-workspace-mkdirs```

### databricks-git-credential-get

***

Retrieves a Git credential.

#### Base Command

`databricks-git-credential-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| credential_id | The ID of the Git credential. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GitCredential.credential_id | Number | The ID of the credential. |
| Databricks.GitCredential.git_username | String | The Git username. |
| Databricks.GitCredential.git_provider | String | The Git provider. |

#### Command Example

```!databricks-git-credential-get```

### databricks-git-credential-list

***

Lists all Git credentials.

#### Base Command

`databricks-git-credential-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GitCredential.credential_id | Number | The ID of the credential. |
| Databricks.GitCredential.git_username | String | The Git username. |
| Databricks.GitCredential.git_provider | String | The Git provider. |

#### Command Example

```!databricks-git-credential-list```

### databricks-git-credential-create

***

Creates a new Git credential.

#### Base Command

`databricks-git-credential-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| git_provider | The Git provider name. | Required |
| git_username | The Git username. | Required |
| personal_access_token | The personal access token for Git. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GitCredential.credential_id | Number | The ID of the newly created credential. |

#### Command Example

```!databricks-git-credential-create```

### databricks-git-credential-update

***

Updates a Git credential.

#### Base Command

`databricks-git-credential-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| credential_id | The ID of the credential to update. | Required |
| git_provider | The new Git provider. | Optional |
| git_username | The new Git username. | Optional |
| personal_access_token | The new personal access token. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-git-credential-update```

### databricks-git-credential-delete

***

Deletes a Git credential.

#### Base Command

`databricks-git-credential-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| credential_id | The ID of the credential to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-git-credential-delete```

### databricks-repo-get

***

Retrieves a repo by its ID.

#### Base Command

`databricks-repo-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo_id | The ID of the repo. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Repo.id | Number | The unique identifier of the repo. |
| Databricks.Repo.url | String | The URL of the remote repository. |
| Databricks.Repo.provider | String | The Git provider. |
| Databricks.Repo.path | String | The workspace path of the repo. |
| Databricks.Repo.branch | String | The current branch. |
| Databricks.Repo.head_commit_id | String | The HEAD commit ID. |

#### Command Example

```!databricks-repo-get```

### databricks-repo-list

***

Lists repos in the workspace.

#### Base Command

`databricks-repo-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path_prefix | Filter repos by path prefix. | Optional |
| next_page_token | Pagination token for the next page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Repo.id | Number | The unique identifier of the repo. |
| Databricks.Repo.url | String | The URL of the remote repository. |
| Databricks.Repo.provider | String | The Git provider. |
| Databricks.Repo.path | String | The workspace path of the repo. |
| Databricks.Repo.branch | String | The current branch. |
| Databricks.Repo.head_commit_id | String | The HEAD commit ID. |

#### Command Example

```!databricks-repo-list```

### databricks-repo-create

***

Creates a new repo.

#### Base Command

`databricks-repo-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL of the remote repository. | Required |
| provider | The Git provider. | Required |
| path | The desired workspace path. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Repo.id | Number | The ID of the newly created repo. |

#### Command Example

```!databricks-repo-create```

### databricks-repo-update

***

Updates a repo branch or tag.

#### Base Command

`databricks-repo-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo_id | The ID of the repo to update. | Required |
| branch | The branch to checkout. | Optional |
| tag | The tag to checkout. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-repo-update```

### databricks-warehouse-get

***

Retrieves information about a SQL warehouse.

#### Base Command

`databricks-warehouse-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the SQL warehouse. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Warehouse.id | String | The unique identifier of the warehouse. |
| Databricks.Warehouse.name | String | The name of the warehouse. |
| Databricks.Warehouse.cluster_size | String | The cluster size. |
| Databricks.Warehouse.state | String | The current state of the warehouse. |
| Databricks.Warehouse.num_clusters | Number | The number of clusters. |
| Databricks.Warehouse.creator_name | String | The creator of the warehouse. |
| Databricks.Warehouse.num_active_sessions | Number | Number of active sessions. |

#### Command Example

```!databricks-warehouse-get warehouse_id=abc123```

### databricks-warehouse-list

***

Lists all SQL warehouses.

#### Base Command

`databricks-warehouse-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Warehouse.id | String | The unique identifier of the warehouse. |
| Databricks.Warehouse.name | String | The name of the warehouse. |
| Databricks.Warehouse.cluster_size | String | The cluster size. |
| Databricks.Warehouse.state | String | The current state of the warehouse. |
| Databricks.Warehouse.num_clusters | Number | The number of clusters. |
| Databricks.Warehouse.creator_name | String | The creator of the warehouse. |

#### Command Example

```!databricks-warehouse-list```

### databricks-warehouse-create

***

Creates a new SQL warehouse.

#### Base Command

`databricks-warehouse-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the warehouse. | Required |
| cluster_size | The cluster size. | Required |
| max_num_clusters | Maximum number of clusters. | Optional |
| auto_stop_mins | Auto-stop time in minutes. | Optional |
| enable_serverless_compute | Whether to enable serverless compute. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Warehouse.id | String | The ID of the newly created warehouse. |

#### Command Example

```!databricks-warehouse-create```

### databricks-warehouse-edit

***

Edits a SQL warehouse configuration.

#### Base Command

`databricks-warehouse-edit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the warehouse to edit. | Required |
| name | New name for the warehouse. | Optional |
| cluster_size | New cluster size. | Optional |
| max_num_clusters | New maximum number of clusters. | Optional |
| auto_stop_mins | New auto-stop time in minutes. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-warehouse-edit```

### databricks-warehouse-delete

***

Deletes a SQL warehouse.

#### Base Command

`databricks-warehouse-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the warehouse to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-warehouse-delete```

### databricks-warehouse-start

***

Starts a SQL warehouse.

#### Base Command

`databricks-warehouse-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the warehouse to start. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-warehouse-start warehouse_id=abc123```

### databricks-warehouse-stop

***

Stops a SQL warehouse.

#### Base Command

`databricks-warehouse-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the warehouse to stop. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-warehouse-stop warehouse_id=abc123```

### databricks-warehouse-get-config

***

Gets the workspace warehouse configuration.

#### Base Command

`databricks-warehouse-get-config`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.WarehouseConfig.data_access_config | Unknown | The data access configuration. |
| Databricks.WarehouseConfig.sql_configuration_parameters | Unknown | The SQL configuration parameters. |

#### Command Example

```!databricks-warehouse-get-config```

### databricks-warehouse-set-config

***

Sets the workspace warehouse configuration.

#### Base Command

`databricks-warehouse-set-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config | JSON string with the warehouse configuration. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-warehouse-set-config```

### databricks-sql-statement-execute

***

Executes a SQL statement against a warehouse.

#### Base Command

`databricks-sql-statement-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| warehouse_id | The ID of the SQL warehouse. | Required |
| statement | The SQL statement to execute. | Required |
| catalog | The catalog to use. | Optional |
| schema | The schema to use. | Optional |
| wait_timeout | Timeout in seconds to wait for results. | Optional |
| disposition | The result disposition. Possible values are: INLINE, EXTERNAL_LINKS. | Optional |
| row_limit | Maximum number of rows to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLStatement.statement_id | String | The ID of the statement execution. |
| Databricks.SQLStatement.status | Unknown | The status of the statement. |
| Databricks.SQLStatement.manifest | Unknown | The result manifest. |
| Databricks.SQLStatement.result | Unknown | The result data. |

#### Command Example

```!databricks-sql-statement-execute warehouse_id=abc123 statement="SELECT 1"```

### databricks-sql-statement-get-status

***

Gets the status and results of a SQL statement.

#### Base Command

`databricks-sql-statement-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| statement_id | The ID of the statement. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLStatement.statement_id | String | The ID of the statement. |
| Databricks.SQLStatement.status | Unknown | The status of the statement. |
| Databricks.SQLStatement.manifest | Unknown | The result manifest. |
| Databricks.SQLStatement.result | Unknown | The result data. |

#### Command Example

```!databricks-sql-statement-get-status```

### databricks-sql-statement-get-result-chunk

***

Gets a result chunk of a SQL statement.

#### Base Command

`databricks-sql-statement-get-result-chunk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| statement_id | The ID of the statement. | Required |
| chunk_index | The index of the result chunk. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLResultChunk.chunk_index | Number | The chunk index. |
| Databricks.SQLResultChunk.row_offset | Number | The row offset of this chunk. |
| Databricks.SQLResultChunk.row_count | Number | The number of rows in this chunk. |
| Databricks.SQLResultChunk.data_array | Unknown | The data array. |

#### Command Example

```!databricks-sql-statement-get-result-chunk```

### databricks-sql-statement-cancel

***

Cancels a running SQL statement.

#### Base Command

`databricks-sql-statement-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| statement_id | The ID of the statement to cancel. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-sql-statement-cancel```

### databricks-sql-query-get

***

Retrieves a saved SQL query.

#### Base Command

`databricks-sql-query-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The ID of the query. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLQuery.id | String | The unique identifier of the query. |
| Databricks.SQLQuery.name | String | The name of the query. |
| Databricks.SQLQuery.query | String | The SQL text of the query. |
| Databricks.SQLQuery.description | String | The description of the query. |
| Databricks.SQLQuery.warehouse_id | String | The warehouse ID for the query. |
| Databricks.SQLQuery.parent_path | String | The parent path of the query. |

#### Command Example

```!databricks-sql-query-get query_id=abc-123```

### databricks-sql-query-list

***

Lists saved SQL queries.

#### Base Command

`databricks-sql-query-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of queries per page. | Optional |
| page_token | Pagination token for the next page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLQuery.id | String | The unique identifier of the query. |
| Databricks.SQLQuery.name | String | The name of the query. |
| Databricks.SQLQuery.query | String | The SQL text of the query. |
| Databricks.SQLQuery.description | String | The description of the query. |
| Databricks.SQLQuery.warehouse_id | String | The warehouse ID for the query. |

#### Command Example

```!databricks-sql-query-list```

### databricks-sql-query-create

***

Creates a new saved SQL query.

#### Base Command

`databricks-sql-query-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the query. | Required |
| query | The SQL text. | Required |
| warehouse_id | The warehouse to use. | Required |
| description | The description of the query. | Optional |
| parent_path | The parent path for the query. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLQuery.id | String | The ID of the newly created query. |

#### Command Example

```!databricks-sql-query-create```

### databricks-sql-query-update

***

Updates a saved SQL query.

#### Base Command

`databricks-sql-query-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The ID of the query to update. | Required |
| name | New name for the query. | Optional |
| query | New SQL text. | Optional |
| description | New description. | Optional |
| warehouse_id | New warehouse ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLQuery.id | String | The ID of the updated query. |

#### Command Example

```!databricks-sql-query-update```

### databricks-sql-query-delete

***

Deletes a saved SQL query.

#### Base Command

`databricks-sql-query-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The ID of the query to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-sql-query-delete```

### databricks-sql-alert-list

***

Lists all SQL alerts.

#### Base Command

`databricks-sql-alert-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLAlert.id | String | The unique identifier of the alert. |
| Databricks.SQLAlert.display_name | String | The display name of the alert. |
| Databricks.SQLAlert.query_id | String | The query ID associated with the alert. |
| Databricks.SQLAlert.state | String | The current state of the alert. |
| Databricks.SQLAlert.lifecycle_state | String | The lifecycle state of the alert. |
| Databricks.SQLAlert.owner_user_name | String | The owner of the alert. |
| Databricks.SQLAlert.create_time | Date | When the alert was created. |
| Databricks.SQLAlert.update_time | Date | When the alert was last updated. |

#### Command Example

```!databricks-sql-alert-list```

### databricks-sql-alert-get

***

Retrieves a SQL alert.

#### Base Command

`databricks-sql-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLAlert.id | String | The unique identifier of the alert. |
| Databricks.SQLAlert.display_name | String | The display name of the alert. |
| Databricks.SQLAlert.query_id | String | The query ID associated with the alert. |
| Databricks.SQLAlert.condition | Unknown | The alert condition. |
| Databricks.SQLAlert.state | String | The current state of the alert. |
| Databricks.SQLAlert.lifecycle_state | String | The lifecycle state of the alert. |
| Databricks.SQLAlert.owner_user_name | String | The owner of the alert. |
| Databricks.SQLAlert.create_time | Date | When the alert was created. |
| Databricks.SQLAlert.update_time | Date | When the alert was last updated. |

#### Command Example

```!databricks-sql-alert-get alert_id=abc-123```

### databricks-sql-alert-create

***

Creates a new SQL alert.

#### Base Command

`databricks-sql-alert-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name of the alert. | Required |
| query_id | The query ID to monitor. | Required |
| condition | The alert condition as a JSON string. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLAlert.id | String | The ID of the newly created alert. |

#### Command Example

```!databricks-sql-alert-create```

### databricks-sql-alert-update

***

Updates a SQL alert.

#### Base Command

`databricks-sql-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to update. | Required |
| display_name | New display name for the alert. | Optional |
| query_id | New query ID. | Optional |
| condition | New condition as a JSON string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLAlert.id | String | The ID of the updated alert. |

#### Command Example

```!databricks-sql-alert-update```

### databricks-sql-alert-delete

***

Deletes a SQL alert.

#### Base Command

`databricks-sql-alert-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-sql-alert-delete```

### databricks-sql-query-history-list

***

Lists SQL query execution history.

#### Base Command

`databricks-sql-query-history-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum number of results to return. | Optional |
| start_time_ms | Start time in milliseconds since epoch. | Optional |
| end_time_ms | End time in milliseconds since epoch. | Optional |
| statuses | Filter by statuses. Possible values are: QUEUED, RUNNING, CANCELED, FAILED, FINISHED. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SQLQueryHistory.query_id | String | The query execution ID. |
| Databricks.SQLQueryHistory.query_text | String | The SQL text that was executed. |
| Databricks.SQLQueryHistory.status | String | The execution status. |
| Databricks.SQLQueryHistory.user_name | String | The user who ran the query. |
| Databricks.SQLQueryHistory.warehouse_id | String | The warehouse used for execution. |
| Databricks.SQLQueryHistory.duration | Number | The execution duration in milliseconds. |

#### Command Example

```!databricks-sql-query-history-list```

### databricks-serving-endpoint-list

***

Lists all serving endpoints.

#### Base Command

`databricks-serving-endpoint-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpoint.name | String | The name of the endpoint. |
| Databricks.ServingEndpoint.creator | String | The creator of the endpoint. |
| Databricks.ServingEndpoint.creation_timestamp | Date | When the endpoint was created. |
| Databricks.ServingEndpoint.state | Unknown | The state of the endpoint. |
| Databricks.ServingEndpoint.config | Unknown | The endpoint configuration. |

#### Command Example

```!databricks-serving-endpoint-list```

### databricks-serving-endpoint-get

***

Retrieves a serving endpoint.

#### Base Command

`databricks-serving-endpoint-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpoint.name | String | The name of the endpoint. |
| Databricks.ServingEndpoint.creator | String | The creator of the endpoint. |
| Databricks.ServingEndpoint.creation_timestamp | Date | When the endpoint was created. |
| Databricks.ServingEndpoint.state | Unknown | The state of the endpoint. |
| Databricks.ServingEndpoint.config | Unknown | The endpoint configuration. |

#### Command Example

```!databricks-serving-endpoint-get name=my-endpoint```

### databricks-serving-endpoint-create

***

Creates a new serving endpoint.

#### Base Command

`databricks-serving-endpoint-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |
| config | The endpoint configuration as a JSON string. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpoint.name | String | The name of the created endpoint. |

#### Command Example

```!databricks-serving-endpoint-create```

### databricks-serving-endpoint-update-config

***

Updates the configuration of a serving endpoint.

#### Base Command

`databricks-serving-endpoint-update-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |
| served_entities | JSON string of served entity configurations. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpoint.name | String | The name of the updated endpoint. |

#### Command Example

```!databricks-serving-endpoint-update-config```

### databricks-serving-endpoint-delete

***

Deletes a serving endpoint.

#### Base Command

`databricks-serving-endpoint-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-serving-endpoint-delete```

### databricks-serving-endpoint-query

***

Queries a serving endpoint for predictions.

#### Base Command

`databricks-serving-endpoint-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |
| inputs | JSON string of input data. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpointResponse.predictions | Unknown | The prediction results. |

#### Command Example

```!databricks-serving-endpoint-query```

### databricks-serving-endpoint-get-logs

***

Retrieves logs for a served model.

#### Base Command

`databricks-serving-endpoint-get-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the serving endpoint. | Required |
| served_model_name | The name of the served model. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServingEndpointLogs.logs | String | The model logs. |

#### Command Example

```!databricks-serving-endpoint-get-logs```

### databricks-vector-search-endpoint-list

***

Lists all vector search endpoints.

#### Base Command

`databricks-vector-search-endpoint-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.VectorSearchEndpoint.name | String | The name of the endpoint. |
| Databricks.VectorSearchEndpoint.endpoint_type | String | The type of the endpoint. |
| Databricks.VectorSearchEndpoint.state | String | The state of the endpoint. |

#### Command Example

```!databricks-vector-search-endpoint-list```

### databricks-vector-search-endpoint-get

***

Retrieves a vector search endpoint.

#### Base Command

`databricks-vector-search-endpoint-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.VectorSearchEndpoint.name | String | The name of the endpoint. |
| Databricks.VectorSearchEndpoint.endpoint_type | String | The type of the endpoint. |
| Databricks.VectorSearchEndpoint.state | String | The state of the endpoint. |
| Databricks.VectorSearchEndpoint.num_indexes | Number | The number of indexes. |
| Databricks.VectorSearchEndpoint.creator | String | The creator of the endpoint. |

#### Command Example

```!databricks-vector-search-endpoint-get endpoint_name=my-vs-endpoint```

### databricks-vector-search-endpoint-create

***

Creates a new vector search endpoint.

#### Base Command

`databricks-vector-search-endpoint-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |
| endpoint_type | The type of the endpoint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.VectorSearchEndpoint.name | String | The name of the created endpoint. |

#### Command Example

```!databricks-vector-search-endpoint-create```

### databricks-vector-search-endpoint-delete

***

Deletes a vector search endpoint.

#### Base Command

`databricks-vector-search-endpoint-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-vector-search-endpoint-delete```

### databricks-vector-search-endpoint-get-metrics

***

Retrieves metrics for a vector search endpoint.

#### Base Command

`databricks-vector-search-endpoint-get-metrics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the endpoint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.VectorSearchMetrics.metrics | Unknown | The endpoint metrics. |

#### Command Example

```!databricks-vector-search-endpoint-get-metrics```

### databricks-mlflow-metric-history

***

Gets the history of a metric for a run.

#### Base Command

`databricks-mlflow-metric-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| run_id | The ID of the MLflow run. | Required |
| metric_key | The metric key to retrieve history for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowMetric.key | String | The metric key. |
| Databricks.MLflowMetric.value | Number | The metric value. |
| Databricks.MLflowMetric.timestamp | Date | When the metric was logged. |
| Databricks.MLflowMetric.step | Number | The step number. |

#### Command Example

```!databricks-mlflow-metric-history```

### databricks-mlflow-model-list

***

Lists registered MLflow models.

#### Base Command

`databricks-mlflow-model-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum number of models to return. | Optional |
| page_token | Pagination token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModel.name | String | The name of the model. |
| Databricks.MLflowModel.creation_timestamp | Date | When the model was created. |
| Databricks.MLflowModel.last_updated_timestamp | Date | When the model was last updated. |
| Databricks.MLflowModel.user_id | String | The user who created the model. |
| Databricks.MLflowModel.description | String | The model description. |

#### Command Example

```!databricks-mlflow-model-list```

### databricks-mlflow-model-get

***

Retrieves a registered MLflow model.

#### Base Command

`databricks-mlflow-model-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the model. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModel.name | String | The name of the model. |
| Databricks.MLflowModel.creation_timestamp | Date | When the model was created. |
| Databricks.MLflowModel.last_updated_timestamp | Date | When the model was last updated. |
| Databricks.MLflowModel.user_id | String | The user who created the model. |
| Databricks.MLflowModel.description | String | The model description. |
| Databricks.MLflowModel.latest_versions | Unknown | The latest versions of the model. |

#### Command Example

```!databricks-mlflow-model-get name=my-model```

### databricks-mlflow-model-version-create

***

Creates a new model version.

#### Base Command

`databricks-mlflow-model-version-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the registered model. | Required |
| source | The source path for the model artifacts. | Required |
| run_id | The MLflow run ID. | Optional |
| description | Description for the model version. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModelVersion.name | String | The model name. |
| Databricks.MLflowModelVersion.version | String | The version number. |
| Databricks.MLflowModelVersion.creation_timestamp | Date | When the version was created. |
| Databricks.MLflowModelVersion.current_stage | String | The current stage. |
| Databricks.MLflowModelVersion.source | String | The source path. |
| Databricks.MLflowModelVersion.run_id | String | The associated run ID. |
| Databricks.MLflowModelVersion.status | String | The version status. |

#### Command Example

```!databricks-mlflow-model-version-create```

### databricks-mlflow-model-version-get

***

Retrieves a specific model version.

#### Base Command

`databricks-mlflow-model-version-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the registered model. | Required |
| version | The version number. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModelVersion.name | String | The model name. |
| Databricks.MLflowModelVersion.version | String | The version number. |
| Databricks.MLflowModelVersion.creation_timestamp | Date | When the version was created. |
| Databricks.MLflowModelVersion.current_stage | String | The current stage. |
| Databricks.MLflowModelVersion.source | String | The source path. |
| Databricks.MLflowModelVersion.run_id | String | The associated run ID. |
| Databricks.MLflowModelVersion.status | String | The version status. |

#### Command Example

```!databricks-mlflow-model-version-get```

### databricks-mlflow-model-version-search

***

Searches model versions.

#### Base Command

`databricks-mlflow-model-version-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Filter string for searching versions. | Optional |
| max_results | Maximum number of results. | Optional |
| order_by | Ordering specification. | Optional |
| page_token | Pagination token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModelVersion.name | String | The model name. |
| Databricks.MLflowModelVersion.version | String | The version number. |
| Databricks.MLflowModelVersion.creation_timestamp | Date | When the version was created. |
| Databricks.MLflowModelVersion.current_stage | String | The current stage. |
| Databricks.MLflowModelVersion.source | String | The source path. |
| Databricks.MLflowModelVersion.run_id | String | The associated run ID. |
| Databricks.MLflowModelVersion.status | String | The version status. |

#### Command Example

```!databricks-mlflow-model-version-search```

### databricks-mlflow-model-version-delete

***

Deletes a model version.

#### Base Command

`databricks-mlflow-model-version-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the registered model. | Required |
| version | The version number to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-mlflow-model-version-delete```

### databricks-mlflow-model-version-transition-stage

***

Transitions a model version to a new stage.

#### Base Command

`databricks-mlflow-model-version-transition-stage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the registered model. | Required |
| version | The version number. | Required |
| stage | The target stage. Possible values are: None, Staging, Production, Archived. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.MLflowModelVersion.name | String | The model name. |
| Databricks.MLflowModelVersion.version | String | The version number. |
| Databricks.MLflowModelVersion.current_stage | String | The new current stage. |

#### Command Example

```!databricks-mlflow-model-version-transition-stage```

### databricks-catalog-get

***

Retrieves a Unity Catalog catalog.

#### Base Command

`databricks-catalog-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the catalog. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Catalog.name | String | The name of the catalog. |
| Databricks.Catalog.owner | String | The owner of the catalog. |
| Databricks.Catalog.comment | String | The catalog comment. |
| Databricks.Catalog.metastore_id | String | The metastore ID. |
| Databricks.Catalog.created_at | Date | When the catalog was created. |
| Databricks.Catalog.created_by | String | Who created the catalog. |

#### Command Example

```!databricks-catalog-get name=main```

### databricks-catalog-list

***

Lists all Unity Catalog catalogs.

#### Base Command

`databricks-catalog-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Catalog.name | String | The name of the catalog. |
| Databricks.Catalog.owner | String | The owner of the catalog. |
| Databricks.Catalog.comment | String | The catalog comment. |
| Databricks.Catalog.metastore_id | String | The metastore ID. |
| Databricks.Catalog.created_at | Date | When the catalog was created. |
| Databricks.Catalog.created_by | String | Who created the catalog. |

#### Command Example

```!databricks-catalog-list```

### databricks-catalog-create

***

Creates a new Unity Catalog catalog.

#### Base Command

`databricks-catalog-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the catalog. | Required |
| comment | A comment for the catalog. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Catalog.name | String | The name of the created catalog. |

#### Command Example

```!databricks-catalog-create```

### databricks-catalog-update

***

Updates a Unity Catalog catalog.

#### Base Command

`databricks-catalog-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the catalog to update. | Required |
| new_name | New name for the catalog. | Optional |
| comment | New comment. | Optional |
| owner | New owner. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Catalog.name | String | The updated catalog name. |

#### Command Example

```!databricks-catalog-update```

### databricks-catalog-delete

***

Deletes a Unity Catalog catalog.

#### Base Command

`databricks-catalog-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the catalog to delete. | Required |
| force | Whether to force delete. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-catalog-delete```

### databricks-schema-get

***

Retrieves a Unity Catalog schema.

#### Base Command

`databricks-schema-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the schema (catalog.schema). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Schema.name | String | The name of the schema. |
| Databricks.Schema.catalog_name | String | The parent catalog name. |
| Databricks.Schema.owner | String | The owner of the schema. |
| Databricks.Schema.comment | String | The schema comment. |
| Databricks.Schema.full_name | String | The full name of the schema. |
| Databricks.Schema.created_at | Date | When the schema was created. |

#### Command Example

```!databricks-schema-get full_name=main.default```

### databricks-schema-list

***

Lists schemas in a catalog.

#### Base Command

`databricks-schema-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The name of the catalog. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Schema.name | String | The name of the schema. |
| Databricks.Schema.catalog_name | String | The parent catalog name. |
| Databricks.Schema.owner | String | The owner of the schema. |
| Databricks.Schema.comment | String | The schema comment. |
| Databricks.Schema.full_name | String | The full name of the schema. |
| Databricks.Schema.created_at | Date | When the schema was created. |

#### Command Example

```!databricks-schema-list catalog_name=main```

### databricks-schema-create

***

Creates a new schema in a catalog.

#### Base Command

`databricks-schema-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the schema. | Required |
| catalog_name | The parent catalog name. | Required |
| comment | A comment for the schema. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Schema.full_name | String | The full name of the created schema. |

#### Command Example

```!databricks-schema-create```

### databricks-schema-update

***

Updates a schema.

#### Base Command

`databricks-schema-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the schema to update. | Required |
| new_name | New name for the schema. | Optional |
| comment | New comment. | Optional |
| owner | New owner. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Schema.full_name | String | The updated schema full name. |

#### Command Example

```!databricks-schema-update```

### databricks-schema-delete

***

Deletes a schema.

#### Base Command

`databricks-schema-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the schema to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-schema-delete```

### databricks-table-get

***

Retrieves a Unity Catalog table.

#### Base Command

`databricks-table-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the table (catalog.schema.table). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Table.name | String | The name of the table. |
| Databricks.Table.catalog_name | String | The parent catalog. |
| Databricks.Table.schema_name | String | The parent schema. |
| Databricks.Table.table_type | String | The type of table. |
| Databricks.Table.data_source_format | String | The data source format. |
| Databricks.Table.owner | String | The owner of the table. |
| Databricks.Table.created_at | Date | When the table was created. |

#### Command Example

```!databricks-table-get full_name=main.default.my_table```

### databricks-table-list

***

Lists tables in a schema.

#### Base Command

`databricks-table-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The catalog name. | Required |
| schema_name | The schema name. | Required |
| max_results | Maximum number of results. | Optional |
| page_token | Pagination token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Table.name | String | The name of the table. |
| Databricks.Table.catalog_name | String | The parent catalog. |
| Databricks.Table.schema_name | String | The parent schema. |
| Databricks.Table.table_type | String | The type of table. |
| Databricks.Table.data_source_format | String | The data source format. |
| Databricks.Table.owner | String | The owner of the table. |
| Databricks.Table.created_at | Date | When the table was created. |

#### Command Example

```!databricks-table-list catalog_name=main schema_name=default```

### databricks-table-delete

***

Deletes a table.

#### Base Command

`databricks-table-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the table to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-table-delete```

### databricks-table-exists

***

Checks if a table exists.

#### Base Command

`databricks-table-exists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the table. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.TableExists.table_exists | Boolean | Whether the table exists. |

#### Command Example

```!databricks-table-exists full_name=main.default.my_table```

### databricks-table-summaries

***

Lists table summaries in a catalog.

#### Base Command

`databricks-table-summaries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The catalog name. | Required |
| schema_name_pattern | Pattern to filter schema names. | Optional |
| table_name_pattern | Pattern to filter table names. | Optional |
| max_results | Maximum number of results. | Optional |
| page_token | Pagination token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.TableSummary.full_name | String | The full name of the table. |
| Databricks.TableSummary.table_type | String | The type of table. |

#### Command Example

```!databricks-table-summaries catalog_name=main```

### databricks-volume-get

***

Retrieves a Unity Catalog volume.

#### Base Command

`databricks-volume-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the volume (catalog.schema.volume). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Volume.name | String | The name of the volume. |
| Databricks.Volume.catalog_name | String | The parent catalog. |
| Databricks.Volume.schema_name | String | The parent schema. |
| Databricks.Volume.volume_type | String | The volume type. |
| Databricks.Volume.storage_location | String | The storage location. |
| Databricks.Volume.owner | String | The owner of the volume. |
| Databricks.Volume.created_at | Date | When the volume was created. |

#### Command Example

```!databricks-volume-get```

### databricks-volume-list

***

Lists volumes in a schema.

#### Base Command

`databricks-volume-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The catalog name. | Required |
| schema_name | The schema name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Volume.name | String | The name of the volume. |
| Databricks.Volume.catalog_name | String | The parent catalog. |
| Databricks.Volume.schema_name | String | The parent schema. |
| Databricks.Volume.volume_type | String | The volume type. |
| Databricks.Volume.storage_location | String | The storage location. |
| Databricks.Volume.owner | String | The owner of the volume. |
| Databricks.Volume.created_at | Date | When the volume was created. |

#### Command Example

```!databricks-volume-list catalog_name=main schema_name=default```

### databricks-volume-create

***

Creates a new Unity Catalog volume.

#### Base Command

`databricks-volume-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the volume. | Required |
| catalog_name | The parent catalog. | Required |
| schema_name | The parent schema. | Required |
| volume_type | The volume type. Possible values are: MANAGED, EXTERNAL. | Required |
| storage_location | The storage location for EXTERNAL volumes. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Volume.name | String | The name of the created volume. |

#### Command Example

```!databricks-volume-create```

### databricks-volume-update

***

Updates a Unity Catalog volume.

#### Base Command

`databricks-volume-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the volume to update. | Required |
| new_name | New name. | Optional |
| comment | New comment. | Optional |
| owner | New owner. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Volume.name | String | The updated volume name. |

#### Command Example

```!databricks-volume-update```

### databricks-volume-delete

***

Deletes a Unity Catalog volume.

#### Base Command

`databricks-volume-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| full_name | The full name of the volume to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-volume-delete```

### databricks-grant-get

***

Gets the permissions on a securable object.

#### Base Command

`databricks-grant-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| securable_type | The type of securable object. | Required |
| full_name | The full name of the securable object. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Grant.principal | String | The principal. |
| Databricks.Grant.privileges | Unknown | The granted privileges. |

#### Command Example

```!databricks-grant-get securable_type=catalog full_name=main```

### databricks-grant-update

***

Updates permissions on a securable object.

#### Base Command

`databricks-grant-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| securable_type | The type of securable object. | Required |
| full_name | The full name of the securable object. | Required |
| changes | JSON string of permission changes. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-grant-update```

### databricks-user-get

***

Retrieves a workspace user.

#### Base Command

`databricks-user-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.User.id | String | The user ID. |
| Databricks.User.userName | String | The username. |
| Databricks.User.displayName | String | The display name. |
| Databricks.User.active | Boolean | Whether the user is active. |

#### Command Example

```!databricks-user-get user_id=12345```

### databricks-user-list

***

Lists workspace users.

#### Base Command

`databricks-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | SCIM filter expression. | Optional |
| count | Maximum number of results. | Optional |
| startIndex | Start index for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.User.id | String | The user ID. |
| Databricks.User.userName | String | The username. |
| Databricks.User.displayName | String | The display name. |
| Databricks.User.active | Boolean | Whether the user is active. |

#### Command Example

```!databricks-user-list```

### databricks-user-create

***

Creates a new workspace user.

#### Base Command

`databricks-user-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | The username (email address). | Required |
| display_name | The display name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.User.id | String | The ID of the created user. |

#### Command Example

```!databricks-user-create```

### databricks-user-update

***

Updates a workspace user.

#### Base Command

`databricks-user-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to update. | Required |
| user_name | New username. | Optional |
| display_name | New display name. | Optional |
| active | Whether the user is active. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-user-update```

### databricks-user-delete

***

Deletes a workspace user.

#### Base Command

`databricks-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-user-delete```

### databricks-group-get

***

Retrieves a workspace group.

#### Base Command

`databricks-group-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Group.id | String | The group ID. |
| Databricks.Group.displayName | String | The display name. |
| Databricks.Group.members | Unknown | The group members. |

#### Command Example

```!databricks-group-get group_id=12345```

### databricks-group-list

***

Lists workspace groups.

#### Base Command

`databricks-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | SCIM filter expression. | Optional |
| count | Maximum number of results. | Optional |
| startIndex | Start index for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Group.id | String | The group ID. |
| Databricks.Group.displayName | String | The display name. |
| Databricks.Group.members | Unknown | The group members. |

#### Command Example

```!databricks-group-list```

### databricks-group-create

***

Creates a new workspace group.

#### Base Command

`databricks-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name for the group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Group.id | String | The ID of the created group. |

#### Command Example

```!databricks-group-create```

### databricks-group-update

***

Updates a workspace group.

#### Base Command

`databricks-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to update. | Required |
| display_name | New display name. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-group-update```

### databricks-group-delete

***

Deletes a workspace group.

#### Base Command

`databricks-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-group-delete```

### databricks-service-principal-get

***

Retrieves a service principal.

#### Base Command

`databricks-service-principal-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sp_id | The ID of the service principal. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServicePrincipal.id | String | The service principal ID. |
| Databricks.ServicePrincipal.applicationId | String | The application ID. |
| Databricks.ServicePrincipal.displayName | String | The display name. |
| Databricks.ServicePrincipal.active | Boolean | Whether the service principal is active. |

#### Command Example

```!databricks-service-principal-get sp_id=12345```

### databricks-service-principal-list

***

Lists service principals.

#### Base Command

`databricks-service-principal-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | SCIM filter expression. | Optional |
| count | Maximum number of results. | Optional |
| startIndex | Start index for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServicePrincipal.id | String | The service principal ID. |
| Databricks.ServicePrincipal.applicationId | String | The application ID. |
| Databricks.ServicePrincipal.displayName | String | The display name. |
| Databricks.ServicePrincipal.active | Boolean | Whether the service principal is active. |

#### Command Example

```!databricks-service-principal-list```

### databricks-service-principal-create

***

Creates a new service principal.

#### Base Command

`databricks-service-principal-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application ID. | Required |
| display_name | The display name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.ServicePrincipal.id | String | The ID of the created service principal. |

#### Command Example

```!databricks-service-principal-create```

### databricks-service-principal-update

***

Updates a service principal.

#### Base Command

`databricks-service-principal-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sp_id | The ID of the service principal to update. | Required |
| display_name | New display name. | Optional |
| active | Whether the service principal is active. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-service-principal-update```

### databricks-service-principal-delete

***

Deletes a service principal.

#### Base Command

`databricks-service-principal-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sp_id | The ID of the service principal to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-service-principal-delete```

### databricks-permissions-get

***

Gets permissions on a workspace object.

#### Base Command

`databricks-permissions-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of object. | Required |
| object_id | The ID of the object. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Permission.object_id | String | The object ID. |
| Databricks.Permission.object_type | String | The object type. |
| Databricks.Permission.access_control_list | Unknown | The access control list. |

#### Command Example

```!databricks-permissions-get object_type=clusters object_id=abc123```

### databricks-permissions-set

***

Replaces permissions on a workspace object.

#### Base Command

`databricks-permissions-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of object. | Required |
| object_id | The ID of the object. | Required |
| access_control_list | JSON string of the access control list. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-permissions-set```

### databricks-permissions-update

***

Partially updates permissions on a workspace object.

#### Base Command

`databricks-permissions-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of object. | Required |
| object_id | The ID of the object. | Required |
| access_control_list | JSON string of the access control list. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-permissions-update```

### databricks-token-list

***

Lists all valid tokens for the user.

#### Base Command

`databricks-token-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Token.token_id | String | The token ID. |
| Databricks.Token.creation_time | Date | When the token was created. |
| Databricks.Token.expiry_time | Date | When the token expires. |
| Databricks.Token.comment | String | The token comment. |

#### Command Example

```!databricks-token-list```

### databricks-token-create

***

Creates a new personal access token.

#### Base Command

`databricks-token-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | A comment for the token. | Optional |
| lifetime_seconds | Lifetime of the token in seconds. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Token.token_id | String | The ID of the new token. |
| Databricks.Token.token_value | String | The value of the new token. |

#### Command Example

```!databricks-token-create comment="test token" lifetime_seconds=86400```

### databricks-token-update

***

Updates a token comment.

#### Base Command

`databricks-token-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token_id | The ID of the token to update. | Required |
| comment | New comment for the token. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-token-update```

### databricks-token-delete

***

Revokes a personal access token.

#### Base Command

`databricks-token-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token_id | The ID of the token to revoke. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-token-delete```

### databricks-secret-put

***

Stores a secret value in a scope.

#### Base Command

`databricks-secret-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |
| key | The secret key name. | Required |
| string_value | The secret value. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-put```

### databricks-secret-delete

***

Deletes a secret from a scope.

#### Base Command

`databricks-secret-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |
| key | The secret key name. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-delete```

### databricks-secret-list

***

Lists secrets in a scope.

#### Base Command

`databricks-secret-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Secret.key | String | The secret key name. |
| Databricks.Secret.last_updated_timestamp | Date | When the secret was last updated. |

#### Command Example

```!databricks-secret-list scope=my-scope```

### databricks-secret-scope-create

***

Creates a new secret scope.

#### Base Command

`databricks-secret-scope-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the scope to create. | Required |
| initial_manage_principal | The initial principal to manage the scope. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-scope-create scope=my-scope```

### databricks-secret-scope-list

***

Lists all secret scopes.

#### Base Command

`databricks-secret-scope-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SecretScope.name | String | The name of the scope. |
| Databricks.SecretScope.backend_type | String | The backend type of the scope. |

#### Command Example

```!databricks-secret-scope-list```

### databricks-secret-scope-delete

***

Deletes a secret scope.

#### Base Command

`databricks-secret-scope-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the scope to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-scope-delete```

### databricks-secret-acl-get

***

Gets the ACL for a principal on a scope.

#### Base Command

`databricks-secret-acl-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |
| principal | The principal name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SecretACL.principal | String | The principal. |
| Databricks.SecretACL.permission | String | The permission level. |

#### Command Example

```!databricks-secret-acl-get```

### databricks-secret-acl-list

***

Lists ACLs on a secret scope.

#### Base Command

`databricks-secret-acl-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.SecretACL.principal | String | The principal. |
| Databricks.SecretACL.permission | String | The permission level. |

#### Command Example

```!databricks-secret-acl-list scope=my-scope```

### databricks-secret-acl-put

***

Creates or updates an ACL on a secret scope.

#### Base Command

`databricks-secret-acl-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |
| principal | The principal name. | Required |
| permission | The permission level. Possible values are: READ, WRITE, MANAGE. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-acl-put```

### databricks-secret-acl-delete

***

Deletes an ACL from a secret scope.

#### Base Command

`databricks-secret-acl-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The name of the secret scope. | Required |
| principal | The principal name. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-secret-acl-delete```

### databricks-dashboard-get

***

Retrieves a Lakeview dashboard.

#### Base Command

`databricks-dashboard-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | The ID of the dashboard. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Dashboard.dashboard_id | String | The unique identifier of the dashboard. |
| Databricks.Dashboard.display_name | String | The display name of the dashboard. |
| Databricks.Dashboard.warehouse_id | String | The associated warehouse. |
| Databricks.Dashboard.path | String | The workspace path. |
| Databricks.Dashboard.create_time | Date | When the dashboard was created. |
| Databricks.Dashboard.update_time | Date | When the dashboard was last updated. |

#### Command Example

```!databricks-dashboard-get dashboard_id=abc123```

### databricks-dashboard-list

***

Lists Lakeview dashboards.

#### Base Command

`databricks-dashboard-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of dashboards per page. | Optional |
| page_token | Pagination token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Dashboard.dashboard_id | String | The unique identifier of the dashboard. |
| Databricks.Dashboard.display_name | String | The display name of the dashboard. |
| Databricks.Dashboard.warehouse_id | String | The associated warehouse. |
| Databricks.Dashboard.path | String | The workspace path. |
| Databricks.Dashboard.create_time | Date | When the dashboard was created. |
| Databricks.Dashboard.update_time | Date | When the dashboard was last updated. |

#### Command Example

```!databricks-dashboard-list```

### databricks-dashboard-create

***

Creates a new Lakeview dashboard.

#### Base Command

`databricks-dashboard-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name of the dashboard. | Required |
| warehouse_id | The warehouse to use. | Required |
| parent_path | The parent workspace path. | Optional |
| serialized_dashboard | The dashboard definition as a JSON string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Dashboard.dashboard_id | String | The ID of the created dashboard. |

#### Command Example

```!databricks-dashboard-create```

### databricks-dashboard-update

***

Updates a Lakeview dashboard.

#### Base Command

`databricks-dashboard-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | The ID of the dashboard to update. | Required |
| display_name | New display name. | Optional |
| warehouse_id | New warehouse ID. | Optional |
| serialized_dashboard | New dashboard definition as a JSON string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Dashboard.dashboard_id | String | The updated dashboard ID. |

#### Command Example

```!databricks-dashboard-update```

### databricks-dashboard-delete

***

Trashes a Lakeview dashboard.

#### Base Command

`databricks-dashboard-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | The ID of the dashboard to trash. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dashboard-delete```

### databricks-dashboard-migrate

***

Migrates a classic SQL dashboard to Lakeview.

#### Base Command

`databricks-dashboard-migrate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_dashboard_id | The ID of the classic dashboard to migrate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.Dashboard.dashboard_id | String | The ID of the migrated dashboard. |

#### Command Example

```!databricks-dashboard-migrate```

### databricks-dashboard-publish

***

Publishes a draft Lakeview dashboard.

#### Base Command

`databricks-dashboard-publish`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | The ID of the dashboard to publish. | Required |
| warehouse_id | The warehouse to use for the published dashboard. | Optional |
| embed_credentials | Whether to embed credentials. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-dashboard-publish```

### databricks-global-init-script-get

***

Retrieves a global init script.

#### Base Command

`databricks-global-init-script-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The ID of the init script. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GlobalInitScript.script_id | String | The unique identifier of the script. |
| Databricks.GlobalInitScript.name | String | The name of the script. |
| Databricks.GlobalInitScript.position | Number | The position in the execution order. |
| Databricks.GlobalInitScript.enabled | Boolean | Whether the script is enabled. |
| Databricks.GlobalInitScript.created_at | Date | When the script was created. |
| Databricks.GlobalInitScript.created_by | String | Who created the script. |
| Databricks.GlobalInitScript.script | String | The base64-encoded script content. |

#### Command Example

```!databricks-global-init-script-get script_id=abc123```

### databricks-global-init-script-list

***

Lists all global init scripts.

#### Base Command

`databricks-global-init-script-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GlobalInitScript.script_id | String | The unique identifier of the script. |
| Databricks.GlobalInitScript.name | String | The name of the script. |
| Databricks.GlobalInitScript.position | Number | The position in the execution order. |
| Databricks.GlobalInitScript.enabled | Boolean | Whether the script is enabled. |
| Databricks.GlobalInitScript.created_at | Date | When the script was created. |
| Databricks.GlobalInitScript.created_by | String | Who created the script. |

#### Command Example

```!databricks-global-init-script-list```

### databricks-global-init-script-create

***

Creates a new global init script.

#### Base Command

`databricks-global-init-script-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the script. | Required |
| script | Base64-encoded script content. | Required |
| position | Position in the execution order. | Optional |
| enabled | Whether the script is enabled. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.GlobalInitScript.script_id | String | The ID of the created script. |

#### Command Example

```!databricks-global-init-script-create```

### databricks-global-init-script-update

***

Updates a global init script.

#### Base Command

`databricks-global-init-script-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The ID of the script to update. | Required |
| name | New name for the script. | Optional |
| script | New base64-encoded script content. | Optional |
| position | New position. | Optional |
| enabled | Whether the script is enabled. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-global-init-script-update```

### databricks-global-init-script-delete

***

Deletes a global init script.

#### Base Command

`databricks-global-init-script-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The ID of the script to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-global-init-script-delete```

### databricks-ip-access-list-get

***

Retrieves an IP access list.

#### Base Command

`databricks-ip-access-list-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_access_list_id | The ID of the IP access list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.IPAccessList.list_id | String | The unique identifier of the list. |
| Databricks.IPAccessList.label | String | The label of the list. |
| Databricks.IPAccessList.list_type | String | The list type (ALLOW or BLOCK). |
| Databricks.IPAccessList.ip_addresses | Unknown | The IP addresses in the list. |
| Databricks.IPAccessList.address_count | Number | Number of addresses in the list. |
| Databricks.IPAccessList.created_at | Date | When the list was created. |
| Databricks.IPAccessList.enabled | Boolean | Whether the list is enabled. |

#### Command Example

```!databricks-ip-access-list-get```

### databricks-ip-access-list-list

***

Lists all IP access lists.

#### Base Command

`databricks-ip-access-list-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.IPAccessList.list_id | String | The unique identifier of the list. |
| Databricks.IPAccessList.label | String | The label of the list. |
| Databricks.IPAccessList.list_type | String | The list type (ALLOW or BLOCK). |
| Databricks.IPAccessList.ip_addresses | Unknown | The IP addresses in the list. |
| Databricks.IPAccessList.address_count | Number | Number of addresses in the list. |
| Databricks.IPAccessList.created_at | Date | When the list was created. |
| Databricks.IPAccessList.enabled | Boolean | Whether the list is enabled. |

#### Command Example

```!databricks-ip-access-list-list```

### databricks-ip-access-list-create

***

Creates a new IP access list.

#### Base Command

`databricks-ip-access-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The label for the list. | Required |
| list_type | The list type. Possible values are: ALLOW, BLOCK. | Required |
| ip_addresses | IP addresses or CIDR ranges. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Databricks.IPAccessList.list_id | String | The ID of the created list. |

#### Command Example

```!databricks-ip-access-list-create```

### databricks-ip-access-list-update

***

Updates an IP access list.

#### Base Command

`databricks-ip-access-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_access_list_id | The ID of the list to update. | Required |
| label | New label. | Optional |
| list_type | New list type. Possible values are: ALLOW, BLOCK. | Optional |
| ip_addresses | New IP addresses or CIDR ranges. | Optional |
| enabled | Whether the list is enabled. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-ip-access-list-update```

### databricks-ip-access-list-delete

***

Deletes an IP access list.

#### Base Command

`databricks-ip-access-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_access_list_id | The ID of the list to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!databricks-ip-access-list-delete```
