This is an integration that will use Sysdig agent to respond to malicious activity by triggering different actions at the host or container level like killing a container, quarantine a file or perform a system capture
This integration was integrated and tested with Host shield `13.9.1` of the Sysdig Agent and ResponseActions version `0.1.0`

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Sysdig Response Actions in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Your server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Classifier | False |
| Incident type (if classifier doesn't exist) | False |
| Mapper (incoming) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### execute-response-action

***
Executes response actions through the Sysdig API. Each action type requires a specific set of parameters.

#### Base Command

`execute-response-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actionType | The action type to perform. Required parameters per action:<br/>- KILL_PROCESS: host_id, process_id (startTime defaults to -1)<br/>- KILL_CONTAINER: host_id, container_id<br/>- STOP_CONTAINER: host_id, container_id<br/>- PAUSE_CONTAINER: host_id, container_id<br/>- UNPAUSE_CONTAINER: host_id, container_id<br/>- START_CONTAINER: host_id, container_id<br/>- FILE_QUARANTINE: host_id, path_absolute (optional: container_id)<br/>- FILE_ACQUIRE: host_id, path_absolute (optional: container_id)<br/>- FILE_UNQUARANTINE: host_id, path_absolute, quarantined_file_path (optional: container_id)<br/>- DELETE_POD: k8s_cluster_name, k8s_namespace_name, k8s_pod_name<br/>- ROLLOUT_RESTART: k8s_cluster_name, k8s_namespace_name, k8s_workload_type, k8s_workload_name<br/>- ISOLATE_NETWORK: k8s_cluster_name, k8s_namespace_name, k8s_workload_type, k8s_workload_name (optional: network_protocol, network_port, network_cidr, network_direction)<br/>- DELETE_NETWORK_POLICY: k8s_cluster_name, k8s_namespace_name, network_policy_name<br/>- GET_LOGS: k8s_cluster_name, k8s_namespace_name (optional: k8s_workload_type, k8s_workload_name, k8s_pod_name, k8s_container_name, previous, all_containers)<br/>- KUBERNETES_VOLUME_SNAPSHOT: k8s_cluster_name, k8s_namespace_name (optional: k8s_pvc_name, k8s_workload_type, k8s_workload_name)<br/>- KUBERNETES_DELETE_VOLUME_SNAPSHOT: k8s_cluster_name, k8s_namespace_name, k8s_pvc_name, k8s_volume_snapshot_name<br/>- CAPTURE: host_id, capture_storage_config_id, capture_duration_ns, capture_past_duration_ns (optional: capture_filters, capture_max_size, container_id, capture_token)<br/>- IAM_QUARANTINE: cloud_provider, cloud_account_id (optional: ct_user_arn, ct_user_identity_type, ct_user)<br/>- IAM_UNQUARANTINE: cloud_provider, cloud_account_id, iam_policy_name, ct_user_identity_type, ct_user<br/>- MAKE_PRIVATE_CLOUD_RESOURCE: cloud_provider, cloud_account_id, cloud_resource_type, cloud_resource_name (optional: cloud_region)<br/>- UNDO_MAKE_PRIVATE_CLOUD_RESOURCE: cloud_provider, cloud_account_id, cloud_resource_type, cloud_resource_name, previous_public_access_settings (optional: cloud_region)<br/>- CLOUD_VOLUME_SNAPSHOT: cloud_provider, cloud_account_id, cloud_region, aws_instance_id<br/>- UNDO_CLOUD_VOLUME_SNAPSHOT: cloud_provider, cloud_account_id, cloud_region, snapshot_ids, aws_instance_id<br/>- FETCH_CLOUD_LOGS: cloud_provider, cloud_account_id, cloud_region, from_timestamp, to_timestamp (optional: ct_original_user, ct_name, ct_src). Possible values are: KILL_PROCESS, KILL_CONTAINER, STOP_CONTAINER, PAUSE_CONTAINER, UNPAUSE_CONTAINER, START_CONTAINER, FILE_QUARANTINE, FILE_ACQUIRE, FILE_UNQUARANTINE, DELETE_POD, ROLLOUT_RESTART, ISOLATE_NETWORK, DELETE_NETWORK_POLICY, GET_LOGS, KUBERNETES_VOLUME_SNAPSHOT, KUBERNETES_DELETE_VOLUME_SNAPSHOT, CAPTURE, IAM_QUARANTINE, IAM_UNQUARANTINE, MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE, CLOUD_VOLUME_SNAPSHOT, UNDO_CLOUD_VOLUME_SNAPSHOT, FETCH_CLOUD_LOGS. | Required |
| callerId | The unique caller identifier for the audit trail. | Required |
| host_id | The host ID where the agent runs. Required for: KILL_PROCESS, KILL_CONTAINER, STOP_CONTAINER, PAUSE_CONTAINER, UNPAUSE_CONTAINER, START_CONTAINER, FILE_QUARANTINE, FILE_ACQUIRE, FILE_UNQUARANTINE, CAPTURE. | Optional |
| container_id | The container ID. Required for: KILL_CONTAINER, STOP_CONTAINER, PAUSE_CONTAINER, UNPAUSE_CONTAINER, START_CONTAINER. Optional for: FILE_QUARANTINE, FILE_ACQUIRE, FILE_UNQUARANTINE, CAPTURE. | Optional |
| process_id | The process ID to kill. Required for: KILL_PROCESS. | Optional |
| path_absolute | The absolute file path. Required for: FILE_QUARANTINE, FILE_ACQUIRE, FILE_UNQUARANTINE. | Optional |
| quarantined_file_path | The path of the quarantined file. Required for: FILE_UNQUARANTINE. | Optional |
| k8s_cluster_name | The Kubernetes cluster name. Required for: DELETE_POD, ROLLOUT_RESTART, ISOLATE_NETWORK, DELETE_NETWORK_POLICY, GET_LOGS, KUBERNETES_VOLUME_SNAPSHOT, KUBERNETES_DELETE_VOLUME_SNAPSHOT. | Optional |
| k8s_namespace_name | The Kubernetes namespace. Required for: DELETE_POD, ROLLOUT_RESTART, ISOLATE_NETWORK, DELETE_NETWORK_POLICY, GET_LOGS, KUBERNETES_VOLUME_SNAPSHOT, KUBERNETES_DELETE_VOLUME_SNAPSHOT. | Optional |
| k8s_pod_name | The Kubernetes pod name. Required for: DELETE_POD. Optional for: GET_LOGS. | Optional |
| k8s_workload_type | The Kubernetes workload type (for example, Deployment, StatefulSet, DaemonSet). Required for: ROLLOUT_RESTART, ISOLATE_NETWORK. Optional for: GET_LOGS, KUBERNETES_VOLUME_SNAPSHOT. | Optional |
| k8s_workload_name | The Kubernetes workload name. Required for: ROLLOUT_RESTART, ISOLATE_NETWORK. Optional for: GET_LOGS, KUBERNETES_VOLUME_SNAPSHOT. | Optional |
| k8s_pvc_name | The PVC name. Optional for: KUBERNETES_VOLUME_SNAPSHOT. Required for: KUBERNETES_DELETE_VOLUME_SNAPSHOT. | Optional |
| k8s_volume_snapshot_name | The volume snapshot name. Required for: KUBERNETES_DELETE_VOLUME_SNAPSHOT. | Optional |
| k8s_container_name | The container name for log retrieval. Optional for: GET_LOGS. | Optional |
| network_policy_name | The network policy name. Required for: DELETE_NETWORK_POLICY. | Optional |
| network_protocol | The network protocol (TCP, UDP). Optional for: ISOLATE_NETWORK. | Optional |
| network_port | The port number. Optional for: ISOLATE_NETWORK. | Optional |
| network_cidr | The CIDR range. Optional for: ISOLATE_NETWORK. | Optional |
| network_direction | The traffic direction (ingress, egress). Optional for: ISOLATE_NETWORK. | Optional |
| previous | Whether to retrieve logs from the previous container instance. Optional for: GET_LOGS. | Optional |
| all_containers | Whether to retrieve logs from all containers. Optional for: GET_LOGS. | Optional |
| capture_storage_config_id | The remote storage configuration ID. Required for: CAPTURE. | Optional |
| capture_duration_ns | The capture duration in nanoseconds. Required for: CAPTURE. | Optional |
| capture_past_duration_ns | The amount of time to capture retroactively, in nanoseconds. Required for: CAPTURE. | Optional |
| capture_filters | The syscall filter expression. Optional for: CAPTURE. | Optional |
| capture_max_size | The maximum capture file size in bytes (0 = no limit). Optional for: CAPTURE. | Optional |
| capture_token | The base name of the capture file. Optional for: CAPTURE. | Optional |
| cloud_provider | The cloud provider name (for example, aws). Required for: IAM_QUARANTINE, IAM_UNQUARANTINE, MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE, CLOUD_VOLUME_SNAPSHOT, UNDO_CLOUD_VOLUME_SNAPSHOT, FETCH_CLOUD_LOGS. | Optional |
| cloud_account_id | The cloud account ID. Required for: IAM_QUARANTINE, IAM_UNQUARANTINE, MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE, CLOUD_VOLUME_SNAPSHOT, UNDO_CLOUD_VOLUME_SNAPSHOT, FETCH_CLOUD_LOGS. | Optional |
| cloud_region | The cloud region. Required for: CLOUD_VOLUME_SNAPSHOT, UNDO_CLOUD_VOLUME_SNAPSHOT, FETCH_CLOUD_LOGS. Optional for: MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE. | Optional |
| ct_user_arn | The AWS identity ARN. Optional for: IAM_QUARANTINE. | Optional |
| ct_user_identity_type | The AWS identity type (IAMUser, Role, AssumedRole). Required for: IAM_UNQUARANTINE. Optional for: IAM_QUARANTINE. | Optional |
| ct_user | The AWS identity name. Required for: IAM_UNQUARANTINE. Optional for: IAM_QUARANTINE. | Optional |
| ct_original_user | The CloudTrail original user. Optional for: FETCH_CLOUD_LOGS. | Optional |
| ct_name | The CloudTrail event name. Optional for: FETCH_CLOUD_LOGS. | Optional |
| ct_src | The CloudTrail source. Optional for: FETCH_CLOUD_LOGS. | Optional |
| iam_policy_name | The IAM policy name to remove. Required for: IAM_UNQUARANTINE. | Optional |
| cloud_resource_type | The cloud resource type (rds, s3). Required for: MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE. | Optional |
| cloud_resource_name | The cloud resource name. Required for: MAKE_PRIVATE_CLOUD_RESOURCE, UNDO_MAKE_PRIVATE_CLOUD_RESOURCE. | Optional |
| previous_public_access_settings | The previous public access settings. Required for: UNDO_MAKE_PRIVATE_CLOUD_RESOURCE. | Optional |
| aws_instance_id | The AWS instance ID. Required for: CLOUD_VOLUME_SNAPSHOT, UNDO_CLOUD_VOLUME_SNAPSHOT. | Optional |
| snapshot_ids | The comma-separated snapshot IDs. Required for: UNDO_CLOUD_VOLUME_SNAPSHOT. | Optional |
| from_timestamp | The start timestamp for the log search. Required for: FETCH_CLOUD_LOGS. | Optional |
| to_timestamp | The end timestamp for the log search. Required for: FETCH_CLOUD_LOGS. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| execute_response_action.Output | Dict | The output of the response-actions API. |

### create-system-capture

***
Triggers a system capture, recording all system calls at the host level.

#### Base Command

`create-system-capture`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_id | The container ID to apply the action. Example "container.id": "123456789123". | Required |
| host_name | The host name. Example "ip-1-1-1-1.us-west-1.compute.internal". | Required |
| capture_name | The capture name. | Required |
| agent_id | The agent ID. | Required |
| customer_id | The customer ID. | Required |
| machine_id | The machine ID/MAC. Example "01:aa:02:bb:03:cc". | Required |
| scan_duration | The capture duration in seconds. | Optional |
| scap_filter | The filter for the scope of the capture to take. Example: (proc.name=ncat or proc.name=vi). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| create_system_capture.Output | Dict | The output of the created system capture. |

### get-capture-file

***
Gets a system capture based on the capture ID.

#### Base Command

`get-capture-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| capture_id | The system capture ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| get_capture_file.Output | Dict | The output of the downloaded system capture. |

### get-action-execution

***
Gets the status and information of a triggered action execution.

#### Base Command

`get-action-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_execution_id | The action execution ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| get_action_execution.Output | Dict | The output of the action execution info. |

### sysdig-agent-info-get

***
Resolves a host MAC address to its Sysdig agent details (agent ID, customer ID, hostname). The result is cached per MAC address.

#### Base Command

`sysdig-agent-info-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The MAC address (machineId) of the host to look up. | Required |
| force_refresh | Whether to force a refresh of the cached agent info from the Sysdig API. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sysdig.Agent.agentId | String | The Sysdig agent ID. |
| Sysdig.Agent.customerId | String | The Sysdig customer ID. |
| Sysdig.Agent.hostName | String | The agent hostname. |
| Sysdig.Agent.machineId | String | The host MAC address. |
| Sysdig.Agent.hostId | String | The opaque host identifier. |
| Sysdig.Agent.clusterName | String | The Kubernetes cluster name. |

### sysdig-customer-info-get

***
Gets the Sysdig customer ID and name. The result is cached per integration instance.

#### Base Command

`sysdig-customer-info-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| force_refresh | Whether to force a refresh of the cached customer info from the Sysdig API. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sysdig.Customer.customerId | String | The Sysdig customer ID. |
| Sysdig.Customer.customerName | String | The Sysdig customer name. |
