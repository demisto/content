The GCP Integration automates management and security configurations for Compute Engine, Storage, and Container resources on GCP.
This integration was integrated and tested with version v1 (Compute, Storage, Container, SERVICE_USAGE), v3 (Resource Manager).

## Configure Google Cloud Platform in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Service Account Private Key file content (JSON). | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gcp-compute-firewall-patch

***
Updates the specified firewall rule with the data included in the request.

#### Base Command

`gcp-compute-firewall-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| resource_name | Name of the firewall rule to update. | Required |
| description | An optional description of this resource, which you provide when you create the resource. | Optional |
| network | URL of the network resource for this firewall rule. If not specified when creating a firewall rule, the default network is used. | Optional |
| priority | Priority for this rule. This is an integer between 0 and 65535, both inclusive. When not specified, the value assumed is 1000. Relative priorities determine precedence of conflicting rules. Lower value of priority implies higher precedence (eg, a rule with priority 0 has higher precedence than a rule with priority 1). DENY rules take precedence over ALLOW rules. | Optional |
| sourceRanges | If source ranges are specified, the firewall applies only to traffic with source IP addresses in these ranges. These ranges must be expressed in CIDR format. One or both of sourceRanges and sourceTags may be set. If both properties are set, the firewall applies to traffic with a source IP address within sourceRanges OR the source IP belonging to a tag listed in the sourceTags property. The connection does not need to match both properties for the firewall to apply. Only IPv4 is supported, comma-separated. | Optional |
| destinationRanges | If destination ranges are specified, the firewall applies only to traffic with destination IP addresses in these ranges. These ranges must be expressed in CIDR format. Only IPv4 is supported. Comma-separated. | Optional |
| sourceTags | If source tags are specified, the firewall rule applies only to traffic with source IPs that match the primary network interfaces of VM instances that have the tag and are in the same VPC network. Source tags cannot be used to control traffic to an instance's external IP address. It only applies to traffic between instances in the same virtual network, because tags are associated with instances, not IP addresses. One or both of sourceRanges and sourceTags may be set. If both properties are set, the firewall will apply to traffic with a source IP address within sourceRanges OR the source IP belonging to a tag listed in the sourceTags property. The connection does not need to match both properties for the firewall to apply. Comma-separated. | Optional |
| targetTags | A list of tags that controls which instances the firewall rule applies to. If targetTags are specified, then the firewall rule applies only to instances in the VPC network that have one of those tags. If no targetTags are specified, the firewall rule applies to all instances on the specified network. Comma-separated. | Optional |
| sourceServiceAccounts | If source service accounts are specified, the firewall applies only to traffic originating from an instance with a service account in this list. Source service accounts cannot be used to control traffic to an instance's external IP address because service accounts are associated with an instance, not an IP address. sourceRanges can be set at the same time as sourceServiceAccounts. If both are set, the firewall will apply to traffic that has a source IP address within sourceRanges OR the source IP belongs to an instance with a service account listed in sourceServiceAccount. The connection does not need to match both properties for the firewall to apply. sourceServiceAccounts cannot be used simultaneously as sourceTags or targetTags. Comma-separated. | Optional |
| targetServiceAccounts | A list of service accounts indicating sets of instances located in the network that may make network connections as specified in allowed[]. targetServiceAccounts cannot be used at the same time as targetTags or sourceTags. If neither targetServiceAccounts nor targetTags are specified, the firewall rule applies to all instances on the specified network. Comma-separated. | Optional |
| allowed | The ALLOW rules list specified by this firewall. Each rule specifies a protocol and port-range tuple that describes a permitted connection. For example, ipprotocol=tcp,ports=22,443;ipprotocol=tcp,ports=8080,80. | Optional |
| denied | The DENY rules list specified by this firewall. Each rule specifies a protocol and port-range tuple that describes a denied connection. For example, ipprotocol=tcp,ports=22,443;ipprotocol=tcp,ports=8080,80. | Optional |
| direction | Direction of traffic to which this firewall applies; default is INGRESS. Note: For INGRESS traffic, it is NOT supported to specify destinationRanges; For EGRESS traffic, it is NOT supported to specify sourceRanges OR sourceTags. | Optional |
| logConfigEnable | This field denotes whether to enable logging for a particular firewall rule. Possible values are: true, false. | Optional |
| disabled | Denotes whether the firewall rule is disabled, i.e not applied to the network it is associated with. When set to true, the firewall rule is not enforced and the network behaves as if it did not exist. If this is unspecified, the firewall rule will be enabled. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-storage-bucket-policy-delete

***
Removes an entity from a bucket's Access Control List.

#### Base Command

`gcp-storage-bucket-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| resource_name | Name of the GCS bucket. | Required |
| entity | Entity to remove from the Access Control List.<br/>Common entity formats are:<br/>*user:&lt;userId or email&gt;<br/>* group:&lt;groupId or email&gt;<br/>*allUsers<br/>* allAuthenticatedUsers<br/>For more options and details, see: https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource . Default is allUsers. | Optional |

#### Context Output

There is no context output for this command.

### gcp-compute-subnet-update

***
Enables flow logs or Private Google Access on a subnet.

#### Base Command

`gcp-compute-subnet-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| region | GCP region. | Required |
| resource_name | Subnet name. | Required |
| enable_flow_logs | Enable VPC Flow Logs. Possible values are: true, false. | Optional |
| enable_private_ip_google_access | Enable Private Google Access. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.name | String | The name of the updated subnet. |
| GCP.Compute.Operations.region | String | The region of the updated subnet. |
| GCP.Compute.Operations.subnetName | String | The name of the subnet that was updated. |
| GCP.Compute.Operations.enableFlowLogs | Boolean | Whether flow logs are enabled for the subnet. |
| GCP.Compute.Operations.ipCidrRange | String | The updated CIDR range for the subnet. |
| GCP.Compute.Operations.privateIpGoogleAccess | Boolean | Whether private Google access is enabled for the subnet. |
| GCP.Compute.Operations.privateIpv6GoogleAccess | Boolean | Whether private IPv6 Google access is enabled for the subnet. |
| GCP.Compute.Operations.stackType | String | The stack type of the subnet \(e.g., \`IPV4\`, \`IPV6\`\). |
| GCP.Compute.Operations.rangeName | String | The name of the IP range associated with the subnet. |
| GCP.Compute.Operations.secondaryIpRanges | Unknown | List of secondary IP ranges for the subnet. |
| GCP.Compute.Operations.description | String | The description of the subnet. |

### gcp-container-cluster-security-update

***
Configures security settings for GKE clusters, including access controls and visibility.

#### Base Command

`gcp-container-cluster-security-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| region | GCP region. | Required |
| resource_name | Name of the GKE cluster. | Required |
| enable_intra_node_visibility | Enable intra-node visibility. Possible values are: true, false. | Optional |
| enable_master_authorized_networks | Enable Master Authorized Networks. Possible values are: true, false. | Optional |
| cidrs | Comma-separated list of up to 50 CIDR blocks (e.g., "192.168.0.0/24,10.0.0.0/32") that are allowed to access the Kubernetes master via HTTPS.<br/>If enable_master_authorized_networks is true and no CIDRs are provided, all access will be blocked.<br/>. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Container.Operations.name | String | The name of the GKE cluster. |
| GCP.Container.Operations.zone | String | The zone of the GKE cluster. |
| GCP.Container.Operations.enableStackdriverLogging | Boolean | Whether Stackdriver Logging is enabled for the cluster. |
| GCP.Container.Operations.enableStackdriverMonitoring | Boolean | Whether Stackdriver Monitoring is enabled for the cluster. |
| GCP.Container.Operations.enablePrivateNodes | Boolean | Whether private nodes are enabled for the GKE cluster. |
| GCP.Container.Operations.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the GKE cluster control plane. |
| GCP.Container.Operations.enableHttpsOnly | Boolean | Whether HTTPS-only traffic is enforced for the cluster. |
| GCP.Container.Operations.enableNetworkPolicy | Boolean | Whether network policies are enabled for the cluster. |
| GCP.Container.Operations.enableAutoscaling | Boolean | Whether autoscaling is enabled for the cluster nodes. |
| GCP.Container.Operations.enableIstio | Boolean | Whether Istio is enabled for the GKE cluster. |
| GCP.Container.Operations.enablePodSecurityPolicy | Boolean | Whether PodSecurityPolicy is enabled for the GKE cluster. |
| GCP.Container.Operations.enableBinaryAuthorization | Boolean | Whether Binary Authorization is enabled for the cluster. |
| GCP.Container.Operations.enableLegacyABAC | Boolean | Whether legacy ABAC is enabled for the cluster. |
| GCP.Container.Operations.clusterIpv4Cidr | String | The cluster’s IPv4 CIDR block. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.cidrBlocks | Unknown | List of authorized CIDR blocks that can access the GKE cluster master. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.enabled | Boolean | Whether master authorized networks are enabled for the cluster. |
| GCP.Container.Operations.network | String | The network to which the GKE cluster belongs. |
| GCP.Container.Operations.subnetwork | String | The subnetwork to which the GKE cluster belongs. |
| GCP.Container.Operations.loggingService | String | The logging service used for the cluster \(e.g., "logging.googleapis.com"\). |
| GCP.Container.Operations.monitoringService | String | The monitoring service used for the cluster \(e.g., "monitoring.googleapis.com"\). |
| GCP.Container.Operations.nodePools | Unknown | A list of node pools in the cluster, with their configuration and security settings. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateNodes | Boolean | Whether private nodes are enabled in the cluster. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the cluster control plane. |
| GCP.Container.Operations.masterVersion | String | The current version of the Kubernetes master in the GKE cluster. |

### gcp-storage-bucket-metadata-update

***
Updates the metadata of a Google Cloud Storage (GCS) bucket, including settings such as versioning and Uniform Bucket-Level Access (UBLA).

#### Base Command

`gcp-storage-bucket-metadata-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| resource_name | Name of the bucket. | Required |
| enable_versioning | Enable versioning. Possible values are: true, false. | Optional |
| enable_uniform_access | Enable uniform bucket-level access. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.StorageBucket.Metadata | Unknown | Updated bucket metadata. |
| GCP.StorageBucket.Metadata.name | String | The name of the GCP bucket. |
| GCP.StorageBucket.Metadata.id | String | The ID of the GCP bucket. |
| GCP.StorageBucket.Metadata.location | String | The location of the bucket. |
| GCP.StorageBucket.Metadata.storageClass | String | The storage class of the bucket \(e.g., STANDARD, NEARLINE\). |
| GCP.StorageBucket.Metadata.created | Date | The creation timestamp of the bucket. |
| GCP.StorageBucket.Metadata.updated | Date | The last update timestamp of the bucket. |
| GCP.StorageBucket.Metadata.metageneration | Number | The metadata generation of the bucket. |
| GCP.StorageBucket.Metadata.labels | Unknown | The labels attached to the bucket. |
| GCP.StorageBucket.Metadata.defaultEventBasedHold | Boolean | Whether a default event-based hold is enabled on the bucket. |
| GCP.StorageBucket.Metadata.retentionPolicy.retentionPeriod | Number | The duration in seconds that objects in the bucket must be retained. |
| GCP.StorageBucket.Metadata.retentionPolicy.effectiveTime | Date | The time from which the retention policy is effective. |
| GCP.StorageBucket.Metadata.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.StorageBucket.Metadata.versioning.enabled | Boolean | Whether object versioning is enabled. |
| GCP.StorageBucket.Metadata.logging.logBucket | String | The destination bucket where access logs are stored. |
| GCP.StorageBucket.Metadata.logging.logObjectPrefix | String | The object prefix used for logging. |
| GCP.StorageBucket.Metadata.lifecycle.rule | Unknown | A list of lifecycle management rules for the bucket. |
| GCP.StorageBucket.Metadata.iamConfiguration.uniformBucketLevelAccess | Boolean | Whether uniform bucket-level access is enabled. |
| GCP.StorageBucket.Metadata.cors | Unknown | CORS configuration for the bucket. |
| GCP.StorageBucket.Metadata.customPlacementConfig | Unknown | Custom placement configuration for multi-region buckets. |
| GCP.StorageBucket.Metadata.encryption.defaultKmsKeyName | String | The default Cloud KMS key used to encrypt objects. |
| GCP.StorageBucket.Metadata.billing.requesterPays | Boolean | Whether requester pays is enabled. |
| GCP.StorageBucket.Metadata.website.mainPageSuffix | String | Suffix appended to requests for the bucket's website configuration. |
| GCP.StorageBucket.Metadata.website.notFoundPage | String | The path to the custom 404 page for the bucket website. |

### gcp-iam-project-policy-binding-remove

***
Removes a specified IAM role binding from a GCP project.

#### Base Command

`gcp-iam-project-policy-binding-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| member | Member to remove (e.g., user:test@example.com). | Required |
| role | Role to remove (e.g., roles/viewer). | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-instance-service-account-set

***
Sets the service account for a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed.

#### Base Command

`gcp-compute-instance-service-account-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| resource_name | Name of the VM instance. | Required |
| service_account_email | Email of the service account. | Required |
| scopes | OAuth scopes to assign (full URLs), e.g., `https://www.googleapis.com/auth/cloud-platform`. Empty list means no scopes. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-service-account-remove

***
Removes the service account associated with a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed.

#### Base Command

`gcp-compute-instance-service-account-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| resource_name | Name of the VM instance. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-start

***
Starts an instance that was stopped using the instances().stop method.

#### Base Command

`gcp-compute-instance-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| resource_name | Name of the instance resource to start. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-stop

***
Stops a running instance, shutting it down cleanly, and allows you to restart the instance at a later time. Stopped instances do not incur VM usage charges while they are stopped. However, resources that the VM is using, such as persistent disks and static IP addresses, will continue to be charged until they are deleted.

#### Base Command

`gcp-compute-instance-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| resource_name | Name of the instance resource to stop. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not configurable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-storage-bucket-metadata-update-enable-GCP-bucket-versioning-quick-action

***
Enables versioning on a GCP Storage bucket to preserve object versions.

#### Base Command

`gcp-storage-bucket-metadata-update-enable-GCP-bucket-versioning-quick-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| resource_name | Name of the bucket. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.StorageBucket.Metadata | Unknown | Updated bucket metadata. |
| GCP.StorageBucket.Metadata.name | String | The name of the GCP bucket. |
| GCP.StorageBucket.Metadata.id | String | The ID of the GCP bucket. |
| GCP.StorageBucket.Metadata.location | String | The location of the bucket. |
| GCP.StorageBucket.Metadata.storageClass | String | The storage class of the bucket \(e.g., STANDARD, NEARLINE\). |
| GCP.StorageBucket.Metadata.created | Date | The creation timestamp of the bucket. |
| GCP.StorageBucket.Metadata.updated | Date | The last update timestamp of the bucket. |
| GCP.StorageBucket.Metadata.metageneration | Number | The metadata generation of the bucket. |
| GCP.StorageBucket.Metadata.labels | Unknown | The labels attached to the bucket. |
| GCP.StorageBucket.Metadata.defaultEventBasedHold | Boolean | Whether a default event-based hold is enabled on the bucket. |
| GCP.StorageBucket.Metadata.retentionPolicy.retentionPeriod | Number | The duration in seconds that objects in the bucket must be retained. |
| GCP.StorageBucket.Metadata.retentionPolicy.effectiveTime | Date | The time from which the retention policy is effective. |
| GCP.StorageBucket.Metadata.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.StorageBucket.Metadata.versioning.enabled | Boolean | Whether object versioning is enabled. |
| GCP.StorageBucket.Metadata.logging.logBucket | String | The destination bucket where access logs are stored. |
| GCP.StorageBucket.Metadata.logging.logObjectPrefix | String | The object prefix used for logging. |
| GCP.StorageBucket.Metadata.lifecycle.rule | Unknown | A list of lifecycle management rules for the bucket. |
| GCP.StorageBucket.Metadata.iamConfiguration.uniformBucketLevelAccess | Boolean | Whether uniform bucket-level access is enabled. |
| GCP.StorageBucket.Metadata.cors | Unknown | CORS configuration for the bucket. |
| GCP.StorageBucket.Metadata.customPlacementConfig | Unknown | Custom placement configuration for multi-region buckets. |
| GCP.StorageBucket.Metadata.encryption.defaultKmsKeyName | String | The default Cloud KMS key used to encrypt objects. |
| GCP.StorageBucket.Metadata.billing.requesterPays | Boolean | Whether requester pays is enabled. |
| GCP.StorageBucket.Metadata.website.mainPageSuffix | String | Suffix appended to requests for the bucket's website configuration. |
| GCP.StorageBucket.Metadata.website.notFoundPage | String | The path to the custom 404 page for the bucket website. |

### gcp-container-cluster-security-update-enable-gke-cluster-intra-node-visibility-quick-action

***
Enables intra-node visibility on a GKE cluster for enhanced network monitoring.

#### Base Command

`gcp-container-cluster-security-update-enable-gke-cluster-intra-node-visibility-quick-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| region | GCP region. | Required |
| resource_name | Name of the GKE cluster. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Container.Operations.name | String | The name of the GKE cluster. |
| GCP.Container.Operations.zone | String | The zone of the GKE cluster. |
| GCP.Container.Operations.enableStackdriverLogging | Boolean | Whether Stackdriver Logging is enabled for the cluster. |
| GCP.Container.Operations.enableStackdriverMonitoring | Boolean | Whether Stackdriver Monitoring is enabled for the cluster. |
| GCP.Container.Operations.enablePrivateNodes | Boolean | Whether private nodes are enabled for the GKE cluster. |
| GCP.Container.Operations.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the GKE cluster control plane. |
| GCP.Container.Operations.enableHttpsOnly | Boolean | Whether HTTPS-only traffic is enforced for the cluster. |
| GCP.Container.Operations.enableNetworkPolicy | Boolean | Whether network policies are enabled for the cluster. |
| GCP.Container.Operations.enableAutoscaling | Boolean | Whether autoscaling is enabled for the cluster nodes. |
| GCP.Container.Operations.enableIstio | Boolean | Whether Istio is enabled for the GKE cluster. |
| GCP.Container.Operations.enablePodSecurityPolicy | Boolean | Whether PodSecurityPolicy is enabled for the GKE cluster. |
| GCP.Container.Operations.enableBinaryAuthorization | Boolean | Whether Binary Authorization is enabled for the cluster. |
| GCP.Container.Operations.enableLegacyABAC | Boolean | Whether legacy ABAC is enabled for the cluster. |
| GCP.Container.Operations.clusterIpv4Cidr | String | The cluster's IPv4 CIDR block. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.cidrBlocks | Unknown | List of authorized CIDR blocks that can access the GKE cluster master. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.enabled | Boolean | Whether master authorized networks are enabled for the cluster. |
| GCP.Container.Operations.network | String | The network to which the GKE cluster belongs. |
| GCP.Container.Operations.subnetwork | String | The subnetwork to which the GKE cluster belongs. |
| GCP.Container.Operations.loggingService | String | The logging service used for the cluster \(e.g., "logging.googleapis.com"\). |
| GCP.Container.Operations.monitoringService | String | The monitoring service used for the cluster \(e.g., "monitoring.googleapis.com"\). |
| GCP.Container.Operations.nodePools | Unknown | A list of node pools in the cluster, with their configuration and security settings. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateNodes | Boolean | Whether private nodes are enabled in the cluster. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the cluster control plane. |
| GCP.Container.Operations.masterVersion | String | The current version of the Kubernetes master in the GKE cluster. |

### gcp-compute-instances-list

***
Retrieves the list of instances in the specified zone.

#### Base Command

`gcp-compute-instances-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| filters | A filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance. | Optional |
| limit | The maximum number of results per page that should be returned. Acceptable values are 0 to 500, inclusive. (Default: 500). Default is 500. | Optional |
| order_by | Sorts list results in a specific order. By default, results are returned in alphanumerical order based on the resource name.  You can also sort results in descending order based on the creation timestamp using order_by="creationTimestamp desc". | Optional |
| page_token | Specifies a page token. Set page_token to the nextPageToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Instances.kind | String | Type of the resource.Always compute\#instance for instances. |
| GCP.Compute.Instances.id | String | The unique identifier of the resource. |
| GCP.Compute.Instances.creationTimestamp | String | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Instances.name | String | The name of the resource, provided by the client when the resource is first created. |
| GCP.Compute.Instances.description | String | An optional description for this resource. |
| GCP.Compute.Instances.tags | String | Tags to apply to this instance. |
| GCP.Compute.Instances.machineType | String | Full or partial URL of the machine type resource to use for this instance, in the format: zones/zone/machineTypes/machine-type. |
| GCP.Compute.Instances.status | String | The status of the instance. |
| GCP.Compute.Instances.statusMessage | String | An optional, human-readable explanation of the status. |
| GCP.Compute.Instances.zone | String | URL of the zone where the instance resides. |
| GCP.Compute.Instances.canIpForward | String | Allows this instance to send and receive packets with non-matching destination or source IPs. |
| GCP.Compute.Instances.networkInterfaces | Object | An array of network configurations for the instance. |
| GCP.Compute.Instances.disks | Object | Array of disks associated with the instance. |
| GCP.Compute.Instances.metadata | Object | The metadata key/value pairs assigned to the instance. |
| GCP.Compute.Instances.serviceAccounts | Object | A list of service accounts, with their specified scopes, authorized for the instance. |
| GCP.Compute.Instances.selfLink | String | Server-defined URL for the resource. |
| GCP.Compute.Instances.scheduling | Object | Sets the scheduling options for the instance. |
| GCP.Compute.Instances.cpuPlatform | String | The CPU platform used by the instance. |
| GCP.Compute.Instances.labels | String | Labels to apply to the instance. |
| GCP.Compute.Instances.labelFingerprint | String | A fingerprint for this request, which is essentially a hash of the label's contents and used for optimistic locking. |
| GCP.Compute.Instances.instanceEncryptionKey | Object | Encrypts suspended data for an instance with a customer-managed encryption key. |
| GCP.Compute.Instances.minCpuPlatform | String | Specifies a minimum CPU platform for the VM instance. |
| GCP.Compute.Instances.guestAccelerators | Object | A list of the type and count of accelerator cards attached to the instance. |
| GCP.Compute.Instances.startRestricted | Boolean | Indicates whether a VM has been restricted from starting because Compute Engine detected suspicious activity. |
| GCP.Compute.Instances.deletionProtection | Boolean | Whether the resource should be protected against deletion. |
| GCP.Compute.Instances.resourcePolicies | String | Resource policies applied to this instance. |
| GCP.Compute.Instances.sourceMachineImage | String | Source machine image. |
| GCP.Compute.Instances.reservationAffinity | Object | Specifies the reservations that the instance can consume from. |
| GCP.Compute.Instances.hostname | String | Specifies the hostname of the instance. |
| GCP.Compute.Instances.displayDevice | Object | Enables display device for the instance. |
| GCP.Compute.Instances.shieldedInstanceConfig | Object |  |
| GCP.Compute.Instances.sourceMachineImageEncryptionKey | Object | The source machine image encryption key used when creating an instance from a machine image. |
| GCP.Compute.Instances.confidentialInstanceConfig | Object |  |
| GCP.Compute.Instances.fingerprint | String | Specifies a fingerprint for this resource, which is essentially a hash of the instance's contents and used for optimistic locking. |
| GCP.Compute.Instances.privateIpv6GoogleAccess | String | The private IPv6 Google access type for the VM. |
| GCP.Compute.Instances.advancedMachineFeatures | Object | Controls for advanced machine-related behavior features. |
| GCP.Compute.Instances.lastStartTimestamp | String | Last start timestamp in RFC3339 text format. |
| GCP.Compute.Instances.lastStopTimestamp | String | Last stop timestamp in RFC3339 text format. |
| GCP.Compute.Instances.lastSuspendedTimestamp | String | Last suspended timestamp in RFC3339 text format. |
| GCP.Compute.Instances.satisfiesPzs | String |  |
| GCP.Compute.Instances.satisfiesPzi | String |  |
| GCP.Compute.Instances.resourceStatus | Object | The resource status. |
| GCP.Compute.Instances.networkPerformanceConfig | Object | Network performance configuration. |
| GCP.Compute.Instances.keyRevocationActionType | String | KeyRevocationActionType of the instance. |
| GCP.Compute.InstancesNextPageToken | String | The token used to retrieve the next page of results for list requests. |
| GCP.Compute.InstancesSelfLink | String | Server-defined URL for the resource. |
| GCP.Compute.InstancesWarning | Object | Informational warning message. |

### gcp-storage-bucket-metadata-update-set-GCP-bucket-access-to-uniform-quick-action

***
Enables uniform bucket-level access on a GCP Storage bucket for enhanced security.

#### Base Command

`gcp-storage-bucket-metadata-update-set-GCP-bucket-access-to-uniform-quick-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| resource_name | Name of the bucket. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.StorageBucket.Metadata | Unknown | Updated bucket metadata. |
| GCP.StorageBucket.Metadata.name | String | The name of the GCP bucket. |
| GCP.StorageBucket.Metadata.id | String | The ID of the GCP bucket. |
| GCP.StorageBucket.Metadata.location | String | The location of the bucket. |
| GCP.StorageBucket.Metadata.storageClass | String | The storage class of the bucket \(e.g., STANDARD, NEARLINE\). |
| GCP.StorageBucket.Metadata.created | Date | The creation timestamp of the bucket. |
| GCP.StorageBucket.Metadata.updated | Date | The last update timestamp of the bucket. |
| GCP.StorageBucket.Metadata.metageneration | Number | The metadata generation of the bucket. |
| GCP.StorageBucket.Metadata.labels | Unknown | The labels attached to the bucket. |
| GCP.StorageBucket.Metadata.defaultEventBasedHold | Boolean | Whether a default event-based hold is enabled on the bucket. |
| GCP.StorageBucket.Metadata.retentionPolicy.retentionPeriod | Number | The duration in seconds that objects in the bucket must be retained. |
| GCP.StorageBucket.Metadata.retentionPolicy.effectiveTime | Date | The time from which the retention policy is effective. |
| GCP.StorageBucket.Metadata.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.StorageBucket.Metadata.versioning.enabled | Boolean | Whether object versioning is enabled. |
| GCP.StorageBucket.Metadata.logging.logBucket | String | The destination bucket where access logs are stored. |
| GCP.StorageBucket.Metadata.logging.logObjectPrefix | String | The object prefix used for logging. |
| GCP.StorageBucket.Metadata.lifecycle.rule | Unknown | A list of lifecycle management rules for the bucket. |
| GCP.StorageBucket.Metadata.iamConfiguration.uniformBucketLevelAccess | Boolean | Whether uniform bucket-level access is enabled. |
| GCP.StorageBucket.Metadata.cors | Unknown | CORS configuration for the bucket. |
| GCP.StorageBucket.Metadata.customPlacementConfig | Unknown | Custom placement configuration for multi-region buckets. |
| GCP.StorageBucket.Metadata.encryption.defaultKmsKeyName | String | The default Cloud KMS key used to encrypt objects. |
| GCP.StorageBucket.Metadata.billing.requesterPays | Boolean | Whether requester pays is enabled. |
| GCP.StorageBucket.Metadata.website.mainPageSuffix | String | Suffix appended to requests for the bucket's website configuration. |
| GCP.StorageBucket.Metadata.website.notFoundPage | String | The path to the custom 404 page for the bucket website. |

### gcp-container-cluster-security-update-enable-master-authorized-networks-on-gke-quick-action

***
Enables Master Authorized Networks on a GKE cluster to restrict API server access.

#### Base Command

`gcp-container-cluster-security-update-enable-master-authorized-networks-on-gke-quick-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| region | GCP region. | Required |
| resource_name | Name of the GKE cluster. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Container.Operations.name | String | The name of the GKE cluster. |
| GCP.Container.Operations.zone | String | The zone of the GKE cluster. |
| GCP.Container.Operations.enableStackdriverLogging | Boolean | Whether Stackdriver Logging is enabled for the cluster. |
| GCP.Container.Operations.enableStackdriverMonitoring | Boolean | Whether Stackdriver Monitoring is enabled for the cluster. |
| GCP.Container.Operations.enablePrivateNodes | Boolean | Whether private nodes are enabled for the GKE cluster. |
| GCP.Container.Operations.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the GKE cluster control plane. |
| GCP.Container.Operations.enableHttpsOnly | Boolean | Whether HTTPS-only traffic is enforced for the cluster. |
| GCP.Container.Operations.enableNetworkPolicy | Boolean | Whether network policies are enabled for the cluster. |
| GCP.Container.Operations.enableAutoscaling | Boolean | Whether autoscaling is enabled for the cluster nodes. |
| GCP.Container.Operations.enableIstio | Boolean | Whether Istio is enabled for the GKE cluster. |
| GCP.Container.Operations.enablePodSecurityPolicy | Boolean | Whether PodSecurityPolicy is enabled for the GKE cluster. |
| GCP.Container.Operations.enableBinaryAuthorization | Boolean | Whether Binary Authorization is enabled for the cluster. |
| GCP.Container.Operations.enableLegacyABAC | Boolean | Whether legacy ABAC is enabled for the cluster. |
| GCP.Container.Operations.clusterIpv4Cidr | String | The cluster's IPv4 CIDR block. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.cidrBlocks | Unknown | List of authorized CIDR blocks that can access the GKE cluster master. |
| GCP.Container.Operations.masterAuthorizedNetworksConfig.enabled | Boolean | Whether master authorized networks are enabled for the cluster. |
| GCP.Container.Operations.network | String | The network to which the GKE cluster belongs. |
| GCP.Container.Operations.subnetwork | String | The subnetwork to which the GKE cluster belongs. |
| GCP.Container.Operations.loggingService | String | The logging service used for the cluster \(e.g., "logging.googleapis.com"\). |
| GCP.Container.Operations.monitoringService | String | The monitoring service used for the cluster \(e.g., "monitoring.googleapis.com"\). |
| GCP.Container.Operations.nodePools | Unknown | A list of node pools in the cluster, with their configuration and security settings. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateNodes | Boolean | Whether private nodes are enabled in the cluster. |
| GCP.Container.Operations.privateClusterConfig.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the cluster control plane. |
| GCP.Container.Operations.masterVersion | String | The current version of the Kubernetes master in the GKE cluster. |

### gcp-compute-instance-labels-set

***
Sets labels on an instance.

#### Base Command

`gcp-compute-instance-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance | Name of the instance resource to return. | Required |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| labels | An object containing a list of "key": value pairs, without spaces. Example: key=abc,value=123;key=ABC,value=321. | Required |
| label_fingerprint | Fingerprint of the previous set of labels for this resource, used to prevent conflicts. Provide the latest fingerprint value when making a request to add or change labels. | Required |
| add_labels | Whether to add the new labels to the existing ones or override the previous labels with the news. True - add, False - override. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For snapshot-creation operations, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | User who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator ranging from 0 to 100. It does not need to be linear or support any specific granularity of operations. This indicator should not be used to estimate completion time. The value should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-get

***
Returns the specified Instance resource. To get a list of available instances, make a list() request.

#### Base Command

`gcp-compute-instance-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required |
| zone | The name of the zone for this request. | Required |
| instance | Name of the instance resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Instances.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Instances.creationTimestamp | string | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Instances.name | string | The name of the resource, provided by the client when first creating it. The name must be 1–63 characters long and comply with RFC1035. It must match the regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)?, meaning the first character must be a lowercase letter, and all following characters can be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Instances.description | string | An optional description of this resource. Provide this property when you create the resource. |
| GCP.Compute.Instances.tags | string | Tags to apply to this instance. Tags identify valid sources or targets for network firewalls and are specified by the client during instance creation. Tags can later be modified using the setTags method. Each tag must comply with RFC1035. Multiple tags can be specified via the tags.items field. |
| GCP.Compute.Instances.tags.items | string | An array of tags. Each tag must be 1-63 characters long, and comply with RFC1035. |
| GCP.Compute.Instances.tags.fingerprint | string | Specifies a fingerprint for this request, which is essentially a hash of the tags contents and used for optimistic locking. The fingerprint is initially generated by Compute Engine and changes after every request to modify or update tags. You must always provide an up-to-date fingerprint hash in order to update or change tags. |
| GCP.Compute.Instances.machineType | string | Full or partial URL of the machine type resource to use for this instance, in the format: zones/zone/machineTypes/machine-type. This is provided by the client when the instance is created. |
| GCP.Compute.Instances.status | string | The status of the instance. One of the following values: PROVISIONING, STAGING, RUNNING, STOPPING, STOPPED, SUSPENDING, SUSPENDED, and TERMINATED. |
| GCP.Compute.Instances.statusMessage | string | An optional, human-readable explanation of the status. |
| GCP.Compute.Instances.zone | string | URL of the zone where the instance resides. This field must be specified in the HTTP request URL and cannot be set in the request body. |
| GCP.Compute.Instances.canIpForward | boolean | Allows this instance to send and receive packets with non-matching destination or source IPs. This is required if you plan to use this instance to forward routes. |
| GCP.Compute.Instances.networkInterfaces | string | An array of network configurations for this instance. These specify how interfaces are configured to interact with other network services, such as connecting to the internet. Multiple interfaces are supported per instance. |
| GCP.Compute.Instances.networkInterfaces.network | string | URL of the network resource for this instance. When creating an instance, if neither the network nor the subnetwork is specified, the default network global/networks/default is used; if the network is not specified but the subnetwork is specified, the network is inferred. |
| GCP.Compute.Instances.networkInterfaces.subnetwork | string | The URL of the Subnetwork resource for this instance. For legacy networks, do not provide this property. For auto subnet networks, specifying the subnetwork is optional. For custom subnet networks, this field must be specified. If provided, the subnetwork can be a full or partial URL. |
| GCP.Compute.Instances.networkInterfaces.networkIP | string | An IPv4 internal network address to assign to the instance for this network interface. If not specified by the user, an unused internal IP is assigned by the system. |
| GCP.Compute.Instances.networkInterfaces.name | string |  The name of the network interface, generated by the server. For network devices, these are eth0, eth1, etc. |
| GCP.Compute.Instances.networkInterfaces.accessConfigs | string | An array of configurations for this interface. Currently, only one access config, ONE_TO_ONE_NAT, is supported. If there are no accessConfigs specified, then the instance will have no external internet access. |
| GCP.Compute.Instances.networkInterfaces.aliasIpRanges | string | An array of alias IP ranges for this network interface. Can only be specified for network interfaces on subnet-mode networks. |
| GCP.Compute.Instances.networkInterfaces.fingerprint | string | Fingerprint hash of the contents stored in this network interface. This field is ignored when inserting an instance or adding a network interface. To update the network interface, an up-to-date fingerprint must be provided; otherwise, the request fails with error 412 conditionNotMet. |
| GCP.Compute.Instances.networkInterfaces.kind | string | Type of the resource. Always compute\#networkInterface for network interfaces. |
| GCP.Compute.Instances.disks | string | Array of disks associated with this instance. Persistent disks must be created before you can assign them. |
| GCP.Compute.Instances.disks.type | string | Specifies the type of the disk, either SCRATCH or PERSISTENT. If not specified, the default is PERSISTENT. |
| GCP.Compute.Instances.disks.mode | string | The mode in which to attach this disk, either READ_WRITE or READ_ONLY. If not specified, the default is to attach the disk in READ_WRITE mode. |
| GCP.Compute.Instances.disks.source | string | Specifies a valid partial or full URL to an existing Persistent Disk resource. When creating a new instance, one of initializeParams.sourceImage or disks.source is required except for local SSD. |
| GCP.Compute.Instances.disks.deviceName | string | Specifies a unique device name of your choice that is reflected into the /dev/disk/by-id/google-\* tree of a Linux operating system running within the instance. This name can be used to reference the device for mounting, resizing, and other operations from within the instance. |
| GCP.Compute.Instances.disks.index | number | A zero-based index for this disk, where 0 is reserved for the boot disk. Each attached disk on an instance has a unique index number. |
| GCP.Compute.Instances.disks.boot | boolean | Indicates that this is a boot disk. The VM uses the first partition of the disk as its root filesystem. |
| GCP.Compute.Instances.disks.initializeParams | string | Specifies parameters for a new disk to be created with the instance. Use initialization parameters to create boot disks or local SSDs attached to the instance. |
| GCP.Compute.Instances.disks.autoDelete | boolean | Specifies whether the disk is auto-deleted when the instance is deleted \(not when the disk is detached\). |
| GCP.Compute.Instances.disks.licenses | string |  Any valid publicly visible licenses. |
| GCP.Compute.Instances.disks.interface | string | Specifies the disk interface for attaching this disk, either SCSI or NVME. The default is SCSI. Persistent disks must use SCSI; attaching a persistent disk with any other interface will fail. Local SSDs can use either NVME or SCSI. For performance characteristics of SCSI versus NVMe, see Local SSD performance. |
| GCP.Compute.Instances.disks.guestOsFeatures | string | A list of features to enable on the guest operating system. Applicable only for bootable images. Read Enabling guest operating system features to see a list of available options. |
| GCP.Compute.Instances.disks.diskEncryptionKey | Object | Encrypts or decrypts a disk using a customer-supplied encryption key. |
| GCP.Compute.Instances.disks.kind | string | Type of the resource. Always compute\#attachedDisk for attached disks. |
| GCP.Compute.Instances.metadata | string | The metadata key/value pairs assigned to the instance. This includes custom metadata and predefined keys. |
| GCP.Compute.Instances.metadata.fingerprint | string | Specifies a fingerprint for this request, which is a hash of the metadata contents used for optimistic locking. The fingerprint is generated by Compute Engine and changes after every metadata update. You must provide an up-to-date fingerprint to modify metadata; otherwise, the request fails with error 412 conditionNotMet. |
| GCP.Compute.Instances.metadata.items | string | Array of key/value pairs. The total size of all keys and values must be less than 512 KB. |
| GCP.Compute.Instances.metadata.kind | string | Type of the resource. Always compute\#metadata for metadata. |
| GCP.Compute.Instances.serviceAccounts | string | A list of service accounts, with their specified scopes, authorized for the instance. Only one service account per VM instance is supported. |
| GCP.Compute.Instances.serviceAccounts.email | string | Email address of the service account. |
| GCP.Compute.Instances.serviceAccounts.scopes | string | The list of scopes to be made available for this service account. |
| GCP.Compute.Instances.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Instances.scheduling | string | Sets the scheduling options for the instance. |
| GCP.Compute.Instances.scheduling.onHostMaintenance | string | Defines the maintenance behavior for this instance. For standard instances, the default behavior is MIGRATE. For preemptible instances, the default and only possible behavior is TERMINATE. For more information, see Setting Instance Scheduling Options. |
| GCP.Compute.Instances.scheduling.automaticRestart | boolean | Specifies whether the instance should be automatically restarted if it is terminated by Compute Engine \(not terminated by a user\). You can only set the automatic restart option for standard instances. Preemptible instances cannot be automatically restarted. |
| GCP.Compute.Instances.scheduling.preemptible | boolean | Defines whether the instance is preemptible. This can only be set during instance creation, it cannot be set or changed after the instance has been created. |
| GCP.Compute.Instances.scheduling.nodeAffinities | string | A set of node affinity and anti-affinity. |
| GCP.Compute.Instances.cpuPlatform | string | The CPU platform used by the instance. |
| GCP.Compute.Instances.labels | string | Labels to apply to the instance. These can be later modified by the setLabels method. |
| GCP.Compute.Instances.labels.key | string | The label key. |
| GCP.Compute.Instances.labels.value | string | The label value. |
| GCP.Compute.Instances.labelFingerprint | string | A fingerprint for this request, which is essentially a hash of the labels contents and used for optimistic locking. The fingerprint is initially generated by Compute Engine and changes after every request to modify or update labels. You must always provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Instances.minCpuPlatform | string | Specifies a minimum CPU platform for the VM instance. Applicable values are the friendly names of CPU platforms, such as minCpuPlatform: "Intel Haswell" or minCpuPlatform: "Intel Sandy Bridge". |
| GCP.Compute.Instances.guestAccelerators | string | A list of the type and count of accelerator cards attached to the instance. |
| GCP.Compute.Instances.guestAccelerators.acceleratorType | string | Full or partial URL of the accelerator type resource to attach to this instance. For example: projects/my-project/zones/us-central1-c/acceleratorTypes/nvidia-tesla-p100. When creating an instance template, specify only the accelerator name. |
| GCP.Compute.Instances.guestAccelerators.acceleratorCount | string | The number of the guest accelerator cards exposed to the instance. |
| GCP.Compute.Instances.startRestricted | boolean | Indicates whether a VM has been restricted from starting because Compute Engine detected suspicious activity. |
| GCP.Compute.Instances.deletionProtection | boolean | Whether the resource should be protected against deletion. |
| GCP.Compute.Instances.hostname | string | Hostname. |
| GCP.Compute.Instances.kind | string | Type of the resource. Always compute\#instance for instances. |
