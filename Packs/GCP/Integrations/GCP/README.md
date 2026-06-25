The GCP Integration automates management and security configurations for Compute Engine, Storage, and Container resources on GCP.
This integration was integrated and tested with version v1 (Compute, Storage, Container, SERVICE_USAGE), v3 (Resource Manager).

## Configure Google Cloud Platform in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service Account Private Key (JSON) | The full content of a GCP Service Account private key JSON file. Required for Cortex XSOAR and Cortex XSIAM \(version &amp;lt; 3.0\). On Cortex XSIAM \(version &amp;gt;= 3.0\) and Cortex Platform, authentication is handled automatically via the cloud connector, so this can be left empty. In the Google Cloud Console, go to IAM &amp;amp; Admin &amp;gt; Service Accounts, create a service account with the required roles, then under its 'Keys' tab create a JSON key. Paste the downloaded JSON contents here. | True |
| GCP Project ID | The GCP project ID to authenticate against when testing the integration \(e.g. my-project-123\). If left empty, the project ID from the Service Account private key JSON is used. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gcp-compute-firewall-patch

***
Updates a specific firewall rule with the data included in the request. Required permissions: compute.firewalls.update, compute.firewalls.get, compute.firewalls.list, compute.networks.updatePolicy, compute.networks.list.

#### Base Command

`gcp-compute-firewall-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Removes an entity from a bucket's Access Control List. Required permissions: storage.buckets.getIamPolicy, storage.buckets.setIamPolicy.

#### Base Command

`gcp-storage-bucket-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| resource_name | Name of the GCS bucket. | Required |
| entity | Entity to remove from the Access Control List.<br/>Common entity formats are:<br/>*user:&lt;userId or email&gt;<br/>* group:&lt;groupId or email&gt;<br/>*allUsers<br/>* allAuthenticatedUsers<br/>For more options and details, see: https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource . Default is allUsers. | Optional |

#### Context Output

There is no context output for this command.

### gcp-compute-subnet-update

***

### gcp-compute-subnet-update

***
Enables flow logs or Private Google Access on a subnet. Required permissions: compute.subnetworks.setPrivateIpGoogleAccess, compute.subnetworks.update, compute.subnetworks.get, compute.subnetworks.list.

#### Base Command

`gcp-compute-subnet-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Configures security settings for GKE clusters, including access controls and visibility. Required permissions: container.clusters.update, container.clusters.get, container.clusters.list.

#### Base Command

`gcp-container-cluster-security-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Updates Google Cloud Storage (GCS) bucket metadata, including settings such as versioning and Uniform Bucket-Level Access (UBLA). Required permission: storage.buckets.update.

#### Base Command

`gcp-storage-bucket-metadata-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Removes a specified IAM role binding from a GCP project. Required permissions: resourcemanager.projects.getIamPolicy, resourcemanager.projects.setIamPolicy.

#### Base Command

`gcp-iam-project-policy-binding-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| member | Member to remove (e.g., user:test@example.com). | Required |
| role | Role to remove (e.g., roles/viewer). | Required |

#### Context Output

There is no context output for this command.
Sets the service account for a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed. Required permissions: compute.instances.setServiceAccount, compute.instances.get.

### gcp-compute-instance-service-account-set

***
Sets the service account for a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed. Required permissions: compute.instances.setServiceAccount, compute.instances.get.

#### Base Command

`gcp-compute-instance-service-account-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Removes the service account associated with a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed. Required permissions: compute.instances.setServiceAccount, compute.instances.get.

#### Base Command

`gcp-compute-instance-service-account-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Starts an instance that was stopped using the instances().stop method. Required permission: compute.instances.start.

#### Base Command

`gcp-compute-instance-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Stops and cleanly shuts down a running instance, allowing you to restart the instance at a later time. Stopped instances do not incur VM usage charges while they are stopped. However, resources that the VM is using such as persistent disks and static IP addresses will continue to be charged until they are deleted. Required permission: compute.instances.stop.

#### Base Command

`gcp-compute-instance-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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

### gcp-compute-instances-list

***
Retrieves the list of instances in the specified zone. Required permission: compute.instances.list.

#### Base Command

`gcp-compute-instances-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| filters | A filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance. | Optional |
| limit | The maximum number of results per page that should be returned. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
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
| GCP.Compute.Instances.shieldedInstanceConfig | Object | Shielded VM configuration for the instance. |
| GCP.Compute.Instances.sourceMachineImageEncryptionKey | Object | The source machine image encryption key used when creating an instance from a machine image. |
| GCP.Compute.Instances.confidentialInstanceConfig | Object | Confidential computing configuration for the instance. |
| GCP.Compute.Instances.fingerprint | String | Specifies a fingerprint for this resource, which is essentially a hash of the instance's contents and used for optimistic locking. |
| GCP.Compute.Instances.privateIpv6GoogleAccess | String | The private IPv6 Google access type for the VM. |
| GCP.Compute.Instances.advancedMachineFeatures | Object | Controls for advanced machine-related behavior features. |
| GCP.Compute.Instances.lastStartTimestamp | String | Last start timestamp in RFC3339 text format. |
| GCP.Compute.Instances.lastStopTimestamp | String | Last stop timestamp in RFC3339 text format. |
| GCP.Compute.Instances.lastSuspendedTimestamp | String | Last suspended timestamp in RFC3339 text format. |
| GCP.Compute.Instances.satisfiesPzs | String | Indicates whether the instance satisfies physical zone separation requirements. |
| GCP.Compute.Instances.satisfiesPzi | String | Indicates whether the instance satisfies physical zone isolation requirements. |
| GCP.Compute.Instances.resourceStatus | Object | The resource status. |
| GCP.Compute.Instances.networkPerformanceConfig | Object | Network performance configuration. |
| GCP.Compute.Instances.keyRevocationActionType | String | KeyRevocationActionType of the instance. |
| GCP.Compute.InstancesNextPageToken | String | The token used to retrieve the next page of results for list requests. |
| GCP.Compute.InstancesSelfLink | String | Server-defined URL for the resource. |
| GCP.Compute.InstancesWarning | Object | Informational warning message. |

### gcp-compute-instance-labels-set

***
Sets labels on an instance. Required permission: compute.instances.setLabels.

#### Base Command

`gcp-compute-instance-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance | Name of the instance resource to return. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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
Returns a specific instance resource. To get a list of available instances, make a list() request. Required permission: compute.instances.get.

#### Base Command

`gcp-compute-instance-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
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

***

### gcp-storage-bucket-list

***
Retrieves the list of buckets in the project associated with the client. Required permission: storage.buckets.list.

#### Base Command

`gcp-storage-bucket-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| limit | Maximum number of buckets to return. | Optional |
| prefix | Filter results to buckets whose names begin with this prefix. | Optional |
| page_token | Token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Bucket.id | String | The unique identifier for the bucket. |
| GCP.Storage.Bucket.name | String | The name of the bucket. |
| GCP.Storage.Bucket.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Bucket.location | String | The location of the bucket. |
| GCP.Storage.Bucket.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Bucket.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Bucket.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Bucket.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Bucket.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Bucket.generation | String | The generation number of the bucket. |
| GCP.Storage.Bucket.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Bucket.timeCreated | Date | The time the bucket was created. |
| GCP.Storage.Bucket.timeUpdated | Date | The time the bucket was last updated. |
| GCP.Storage.Bucket.selfLink | String | The link to the bucket resource on the GCP API. |

Retrieves information about a specific bucket. Required permission: storage.buckets.get.

#### Base Command

### gcp-storage-bucket-get

***
Retrieves information about a specific bucket. Required permission: storage.buckets.get.

#### Base Command

`gcp-storage-bucket-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Bucket.id | String | The unique identifier for the bucket. |
| GCP.Storage.Bucket.name | String | The name of the bucket. |
| GCP.Storage.Bucket.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Bucket.location | String | The location of the bucket. |
| GCP.Storage.Bucket.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Bucket.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Bucket.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Bucket.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Bucket.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Bucket.generation | String | The generation number of the bucket. |
| GCP.Storage.Bucket.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Bucket.timeCreated | Date | The time the bucket was created. |
| GCP.Storage.Bucket.timeUpdated | Date | The time the bucket was last updated. |
| GCP.Storage.Bucket.selfLink | String | The link to the bucket resource on the GCP API. |

### gcp-storage-bucket-objects-list

***
Retrieves the list of objects in a bucket. Required permission: storage.objects.list.

#### Base Command

`gcp-storage-bucket-objects-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to list objects from. | Required |
| prefix | Filter results to objects whose names begin with this prefix. | Optional |
| delimiter | Delimiter to use for grouping objects. For example delimiter="/" Returns results in a directory-like mode, with / being a common value for the delimiter. | Optional |
| limit | Maximum number of objects to return. | Optional |
| page_token | Token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObject.id | String | The unique identifier for the object. |
| GCP.Storage.BucketObject.name | String | The name of the object. |
| GCP.Storage.BucketObject.kind | String | The type of resource \(for example, storage\#object\). |
| GCP.Storage.BucketObject.bucket | String | The name of the bucket containing the object. |
| GCP.Storage.BucketObject.contentType | String | The MIME type of the object. |
| GCP.Storage.BucketObject.size | Number | The size of the object in bytes. |
| GCP.Storage.BucketObject.crc32c | String | The CRC32C checksum of the object. |
| GCP.Storage.BucketObject.md5Hash | String | The MD5 hash of the object. |
| GCP.Storage.BucketObject.etag | String | The HTTP entity tag of the object. |
| GCP.Storage.BucketObject.generation | String | The generation number of the object. |
| GCP.Storage.BucketObject.metageneration | String | The metageneration number of the object. |
| GCP.Storage.BucketObject.storageClass | String | The storage class of the object. |
| GCP.Storage.BucketObject.mediaLink | String | The link for downloading the object content. |
| GCP.Storage.BucketObject.selfLink | String | The link to the object resource in the GCP API. |
| GCP.Storage.BucketObject.timeCreated | Date | The time when the object was created. |
| GCP.Storage.BucketObject.timeFinalized | Date | The time when the object was finalized. |
| GCP.Storage.BucketObject.timeStorageClassUpdated | Date | The time when the object's storage class was last updated. |
| GCP.Storage.BucketObject.updated | Date | The time when the object was last modified. |

`gcp-storage-bucket-policy-list`

#### Input

### gcp-storage-bucket-policy-list

***
Retrieves the IAM policy for a bucket. Required permissions: storage.buckets.getIamPolicy, storage.buckets.get.

#### Base Command

`gcp-storage-bucket-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to retrieve IAM policy from. | Required |
| requested_policy_version | The IAM policy version to be returned. If the optionsRequestedPolicyVersion is for an older version that doesn't support part of the requested IAM policy, the request fails. Required to be 3 or greater for buckets with IAM Conditions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketPolicy.version | Number | IAM policy version. |
| GCP.Storage.BucketPolicy.etag | String | ETag of the IAM policy. |
| GCP.Storage.BucketPolicy.bindings | List | List of role bindings for the bucket. |
| GCP.Storage.BucketPolicy.resourceId | String | Resource ID of the updated IAM policy. e.g. projects/_/buckets/BUCKET_NAME. |

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Cloud; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to set IAM policy on. | Required |

### gcp-storage-bucket-policy-set

***
Sets the IAM policy for a bucket. Required permission: storage.buckets.setIamPolicy.

#### Base Command

`gcp-storage-bucket-policy-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to set IAM policy on. | Required |
| policy | JSON string representing the IAM policy to set. | Required |
| add | When true, merges the provided policy bindings into the current bucket policy (per role, deduplicating members) by first calling getIamPolicy and then setIamPolicy with the merged result. When false, replaces the entire policy with the provided JSON via setIamPolicy.<br/>. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketPolicy.version | Number | IAM policy version after update. |
| GCP.Storage.BucketPolicy.etag | String | ETag of the updated IAM policy. |
| GCP.Storage.BucketPolicy.bindings | List | List of role bindings for the bucket. |

| object_name | Name of the object to set IAM policy on. | Required |
| policy | JSON string representing the IAM policy to set. | Required |
| generation | Generation of the object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObjectPolicy.version | Number | IAM policy version after update. |
| GCP.Storage.BucketObjectPolicy.etag | String | ETag of the updated IAM policy. |
| GCP.Storage.BucketObjectPolicy.bindings | Unknown | List of role bindings for the object. |

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Cloud; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| limit | Maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |

### gcp-storage-bucket-object-policy-list

***
Retrieves the IAM policy for a specific object in a bucket. Required permission: storage.objects.getIamPolicy.

#### Base Command

`gcp-storage-bucket-object-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket containing the object. | Required |
| object_name | Name of the object to retrieve IAM policy from. | Required |
| generation | Generation of the object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObjectPolicy.bucketName | String | Name of the bucket containing the object. |
| GCP.Storage.BucketObjectPolicy.objectName | String | Name of the object. |
| GCP.Storage.BucketObjectPolicy.bindings | List | List of role bindings for the object. |

### gcp-storage-bucket-object-policy-set

***
Sets the IAM policy for a specific object in a bucket. Required permission: storage.objects.setIamPolicy.

#### Base Command

`gcp-storage-bucket-object-policy-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket containing the object. | Required |
| object_name | Name of the object to set IAM policy on. | Required |
| policy | JSON string representing the IAM policy to set. | Required |
| generation | Generation of the object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObjectPolicy.version | Number | IAM policy version after update. |
| GCP.Storage.BucketObjectPolicy.etag | String | ETag of the updated IAM policy. |
| GCP.Storage.BucketObjectPolicy.bindings | Unknown | List of role bindings for the object. |

| GCP.Compute.Snapshot.downloadBytes | Number | Total bytes downloaded to create the snapshot. |
| GCP.Compute.Snapshot.enableConfidentialCompute | Boolean | Indicates if confidential compute is enabled for this snapshot. |
| GCP.Compute.Snapshot.labelFingerprint | String | Fingerprint for the labels applied to the snapshot. |
| GCP.Compute.Snapshot.licenseCodes | Unknown | List of license code identifiers attached to the snapshot. |
| GCP.Compute.Snapshot.licenses | Unknown | List of license URLs associated with the snapshot. |
| GCP.Compute.Snapshot.selfLink | String | Server-defined URL for the snapshot resource. |
| GCP.Compute.Snapshot.sourceDisk | String | URL of the source disk used to create the snapshot. |
| GCP.Compute.Snapshot.sourceDiskId | String | Unique ID of the source disk used to create the snapshot. |
| GCP.Compute.Snapshot.sourceSnapshotSchedulePolicy | String | URL of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshot.sourceSnapshotSchedulePolicyId | String | Unique ID of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshot.storageBytes | Number | Total storage size of the snapshot in bytes. |
| GCP.Compute.Snapshot.storageBytesStatus | String | Status of the storage bytes usage, for example UP_TO_DATE. |
| GCP.Compute.Snapshot.storageLocations | Unknown | List of storage locations for the snapshot. |
| GCP.Compute.SnapshotNextToken | String | Next page token for pagination. |

### gcp-compute-snapshot-get

***
Retrieves details for a specific snapshot. Required permission: compute.snapshots.get.

#### Base Command

`gcp-compute-snapshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| resource_name | Snapshot name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Snapshot.id | String | Unique identifier for the snapshot resource. |
| GCP.Compute.Snapshot.name | String | Name of the snapshot resource. |
| GCP.Compute.Snapshot.kind | String | Type of the resource, for example compute\#snapshot. |
| GCP.Compute.Snapshot.status | String | Current status of the snapshot, such as READY or FAILED. |
| GCP.Compute.Snapshot.autoCreated | Boolean | Indicates whether the snapshot was automatically created. |
| GCP.Compute.Snapshot.architecture | String | CPU architecture of the source disk, for example X86_64. |
| GCP.Compute.Snapshot.creationTimestamp | Date | The time when the snapshot was created. |
| GCP.Compute.Snapshot.creationSizeBytes | Number | Total size of the snapshot in bytes at creation time. |
| GCP.Compute.Snapshot.diskSizeGb | Number | Size of the snapshot in gigabytes. |
| GCP.Compute.Snapshot.downloadBytes | Number | Total bytes downloaded to create the snapshot. |
| GCP.Compute.Snapshot.enableConfidentialCompute | Boolean | Indicates if confidential compute is enabled for this snapshot. |
| GCP.Compute.Snapshot.labelFingerprint | String | Fingerprint for the labels applied to the snapshot. |
| GCP.Compute.Snapshot.licenseCodes | Unknown | List of license code identifiers attached to the snapshot. |
| GCP.Compute.Snapshot.licenses | Unknown | List of license URLs associated with the snapshot. |
| GCP.Compute.Snapshot.selfLink | String | Server-defined URL for the snapshot resource. |
| GCP.Compute.Snapshot.sourceDisk | String | URL of the source disk used to create the snapshot. |
| GCP.Compute.Snapshot.sourceDiskId | String | Unique ID of the source disk used to create the snapshot. |
| GCP.Compute.Snapshot.sourceSnapshotSchedulePolicy | String | URL of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshot.sourceSnapshotSchedulePolicyId | String | Unique ID of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshot.storageBytes | Number | Total storage size of the snapshot in bytes. |
| GCP.Compute.Snapshot.storageBytesStatus | String | Status of the storage bytes usage, for example UP_TO_DATE. |
| GCP.Compute.Snapshot.storageLocations | Unknown | List of storage locations for the snapshot. |

### gcp-compute-instances-aggregated-list-by-ip

***
Returns an aggregated list of instances across all zones that can be filtered by internal or external IP. Required permission: cloudasset.assets.searchAllResources.

#### Base Command

`gcp-compute-instances-aggregated-list-by-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| ip_address | The IP address to search for. | Required |
| match_external | If true, match against external NAT IPs; otherwise internal NIC IPs. Possible values are: true, false. | Optional |
| limit | Maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
| page_token | Token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Instance.name | string | Instance name. |
| GCP.Compute.Instance.id | string | Instance ID. |
| GCP.Compute.Instance.zone | string | Instance zone URL. |
| GCP.Compute.Instance.status | string | Instance status. |
| GCP.Compute.Instance.networkInterfaces | Unknown | Network interfaces of the instance. |

### gcp-compute-network-tag-set

***
Adds a network tag to a VM instance (merges with existing tags). Required permission: compute.instances.setTags.

#### Base Command

`gcp-compute-network-tag-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| zone | Zone of the VM (e.g., us-central1-a). | Required |
| resource_name | Instance name. | Required |
| tag | Tag to add. | Required |
| tags_fingerprint | Fingerprint of the previous set of tags for this resource, used to prevent conflicts. Provide the latest fingerprint value when making a request to add or change tags. To retrieve the fingerprint use the command gcp-compute-instance-get. | Required |
| add_tag | If true, adds the tag to the existing tags; otherwise, overrides them. The default is true. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | Operation ID. |
| GCP.Compute.Operations.name | string | Operation name. |
| GCP.Compute.Operations.status | string | Current operation status \(e.g., RUNNING, DONE\). |
| GCP.Compute.Operations.operationType | string | Type of operation being performed. |
| GCP.Compute.Operations.progress | number | Operation progress percentage \(0-100\). |
| GCP.Compute.Operations.user | string | User or service account that initiated the operation. |
| GCP.Compute.Operations.targetLink | string | Full URL of the target resource for this operation. |
| GCP.Compute.Operations.targetId | string | Target resource ID. |
| GCP.Compute.Operations.zone | string | Zone where the operation is performed. |
| GCP.Compute.Operations.insertTime | string | Time when the operation was inserted. |
| GCP.Compute.Operations.startTime | string | Time when the operation started. |
| GCP.Compute.Operations.selfLink | string | URL for this operation resource. |
| GCP.Compute.Operations.kind | string | Type of the resource \(e.g., compute\#operation\). |

### gcp-compute-image-get

***
Returns a specific image. Required permission: compute.images.get.

#### Base Command

`gcp-compute-image-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID for this request. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Cloud; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| image | Name of the image resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Images.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Images.creationTimestamp | string | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Images.name | string | Name of the resource; provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Images.description | string | An optional description of this resource. |
| GCP.Compute.Images.sourceType | string | The type of the image used to create this disk. The default and only value is RAW. |
| GCP.Compute.Images.rawDisk | string | The parameters of the raw disk image. |
| GCP.Compute.Images.rawDisk.source | string | The full Google Cloud Storage URL where the disk image is stored. You must provide either this property or the sourceDisk property but not both. |
| GCP.Compute.Images.rawDisk.sha1Checksum | string | An optional SHA1 checksum of the disk image before unpackaging provided by the client when the disk image is created. |
| GCP.Compute.Images.rawDisk.containerType | string | The format used to encode and transmit the block device, which should be TAR. This is just a container and transmission format and not a runtime format. Provided by the client when the disk image is created. |
| GCP.Compute.Images.deprecated | string | The deprecation status associated with this image. |
| GCP.Compute.Images.deprecated.state | string | The deprecation state of this resource. This can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image, can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Images.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The suggested replacement resource must be the same kind of resource as the deprecated resource. |
| GCP.Compute.Images.deprecated.deprecated | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.deprecated.obsolete | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.deprecated.deleted | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.status | string | The status of the image. An image can be used to create other resources, such as instances, only after the image has been successfully created and the status is set to READY. Possible values are FAILED, PENDING, or READY. |
| GCP.Compute.Images.archiveSizeBytes | string | Size of the image tar.gz archive stored in Google Cloud Storage \(in bytes\). |
| GCP.Compute.Images.diskSizeGb | string | Size of the image when restored onto a persistent disk \(in GB\). |
| GCP.Compute.Images.sourceDisk | string | URL of the source disk used to create this image. This can be a full or valid partial URL. You must provide either this property or the rawDisk.source property but not both to create an image. For example, the following are valid values: https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/disk , projects/project/zones/zone/disks/disk , zones/zone/disks/disk. |
| GCP.Compute.Images.sourceDiskId | string | The ID value of the disk used to create this image. This value may be used to determine whether the image was taken from the current or a previous instance of a given disk name. |
| GCP.Compute.Images.licenses | string | Any applicable license URI. |
| GCP.Compute.Images.family | string | The name of the image family to which this image belongs. You can create disks by specifying an image family instead of a specific image name. The image family always returns its latest image that is not deprecated. The name of the image family must comply with RFC1035. |
| GCP.Compute.Images.imageEncryptionKey | string | Encrypts the image using a customer-supplied encryption key. After you encrypt an image with a customer-supplied key, you must provide the same key if you use the image later \(e.g. to create a disk from the image\). Customer-supplied encryption keys do not protect access to metadata of the disk. If you do not provide an encryption key when creating the image, then the disk will be encrypted using an automatically generated key and you do not need to provide a key to use the image later. |
| GCP.Compute.Images.imageEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.imageEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.imageEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.sourceDiskEncryptionKey | string | The customer-supplied encryption key of the source disk. Required if the source disk is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceDiskEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceDiskEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceDiskEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Images.labels | string | Labels to apply to this image. These can be later modified by the setLabels method. |
| GCP.Compute.Images.labelFingerprint | string | A fingerprint for the labels being applied to this image, which is essentially a hash of the labels used for optimistic locking. The fingerprint is initially generated by Compute Engine and changes after every request to modify or update labels. You must always provide an up-to-date fingerprint hash in order to update or change labels, otherwise the request will fail with error 412 conditionNotMet. |
| GCP.Compute.Images.guestOsFeatures | string | A list of features to enable on the guest operating system. Applicable only for bootable images. Read Enabling guest operating system features to see a list of available options. |
| GCP.Compute.Images.guestOsFeatures.type | string | The ID of a supported feature. Read Enabling guest operating system features to see a list of available options. |
| GCP.Compute.Images.licenseCodes | string | Integer license codes indicating which licenses are attached to this image. |
| GCP.Compute.Images.sourceImage | string | URL of the source image used to create this image. This can be a full or valid partial URL. |
| GCP.Compute.Images.sourceImageId | string | The ID value of the image used to create this image. This value may be used to determine whether the image was taken from the current or a previous instance of a given image name. |
| GCP.Compute.Images.sourceImageEncryptionKey | string | The customer-supplied encryption key of the source image. Required if the source image is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceImageEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceImageEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceImageEncryptionKey.sha256 | string |  The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.sourceSnapshot | string | URL of the source snapshot used to create this image. This can be a full or valid partial URL. |
| GCP.Compute.Images.sourceSnapshotId | string |  The ID value of the snapshot used to create this image. This value may be used to determine whether the snapshot was taken from the current or a previous instance of a given snapshot name. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey | string | The customer-supplied encryption key of the source snapshot. Required if the source snapshot is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.kind | string | Type of the resource. Always compute\#image for images. |

### gcp-compute-instance-group-get

***
Returns a specific instance group. Required permission: compute.instanceGroups.get.

#### Base Command

`gcp-compute-instance-group-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_group | The name of the instance group. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Cloud; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.InstanceGroups.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.InstanceGroups.creationTimestamp | string | The creation timestamp for this instance group in RFC3339 text format. |
| GCP.Compute.InstanceGroups.name | string | The name of the instance group. The name must be 1-63 characters long, and comply with RFC1035. |
| GCP.Compute.InstanceGroups.description | string | An optional description of this resource. |
| GCP.Compute.InstanceGroups.namedPorts | string | Assigns a name to a port number. |
| GCP.Compute.InstanceGroups.namedPorts.name | string | The name for this named port. The name must be 1-63 characters long, and comply with RFC1035. |
| GCP.Compute.InstanceGroups.namedPorts.port | string | The port number, which can be a value between 1 and 65535. |
| GCP.Compute.InstanceGroups.network | string | The URL of the network to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.fingerprint | string | The fingerprint of the named ports. The system uses this fingerprint to detect conflicts when multiple users change the named ports concurrently. |
| GCP.Compute.InstanceGroups.zone | string | The URL of the zone where the instance group is located \(for zonal resources\). |
| GCP.Compute.InstanceGroups.selfLink | string | The URL for this instance group. The server generates this URL. |
| GCP.Compute.InstanceGroups.size | string | The total number of instances in the instance group. |
| GCP.Compute.InstanceGroups.region | string | The URL of the region where the instance group is located \(for regional resources\). |
| GCP.Compute.InstanceGroups.subnetwork | string | The URL of the subnetwork to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.kind | string |  The resource type, which is always compute\#instance_group for instance groups. |

### gcp-compute-region-get

***
Returns a specific region resource. Required permission: compute.regions.get.

#### Base Command

`gcp-compute-region-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | Name of the region resource to return. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Cloud; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Regions.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Regions.creationTimestamp | string |  Creation timestamp in RFC3339 text format. |
| GCP.Compute.Regions.name | string | Name of the resource. |
| GCP.Compute.Regions.description | string | Textual description of the resource. |
| GCP.Compute.Regions.status | string | Status of the region, either UP or DOWN. |
| GCP.Compute.Regions.zones | string | A list of zones available in this region, in the form of resource URLs. |
| GCP.Compute.Regions.quotas | string | Quotas assigned to this region. |
| GCP.Compute.Regions.quotas.metric | string | Name of the quota metric. |
| GCP.Compute.Regions.quotas.limit | string | Quota limit for this metric. |
| GCP.Compute.Regions.quotas.usage | string |  Current usage of this metric. |
| GCP.Compute.Regions.quotas.owner | string | Owning resource. The resource to which this quota applies. |
| GCP.Compute.Regions.deprecated | string | The deprecation status associated with this region. |
| GCP.Compute.Regions.deprecated.state | string | The deprecation state of this resource. This can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image, can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Regions.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The suggested replacement resource must be the same kind of resource as the deprecated resource. |
| GCP.Compute.Regions.deprecated.deprecated | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.obsolete | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.deleted | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Regions.kind | string | Type of the resource. Always compute\#region for regions. |

### gcp-compute-zone-get

***
Returns a specific zone resource. Required permission: compute.zones.get.

#### Base Command

`gcp-compute-zone-get`

### gcp-compute-image-get

***
Returns a specific image. Required permission: compute.images.get.

#### Base Command

`gcp-compute-image-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID for this request. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| image | Name of the image resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Images.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Images.creationTimestamp | string | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Images.name | string | Name of the resource; provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Images.description | string | An optional description of this resource. |
| GCP.Compute.Images.sourceType | string | The type of the image used to create this disk. The default and only value is RAW. |
| GCP.Compute.Images.rawDisk | string | The parameters of the raw disk image. |
| GCP.Compute.Images.rawDisk.source | string | The full Google Cloud Storage URL where the disk image is stored. You must provide either this property or the sourceDisk property but not both. |
| GCP.Compute.Images.rawDisk.sha1Checksum | string | An optional SHA1 checksum of the disk image before unpackaging provided by the client when the disk image is created. |
| GCP.Compute.Images.rawDisk.containerType | string | The format used to encode and transmit the block device, which should be TAR. This is just a container and transmission format and not a runtime format. Provided by the client when the disk image is created. |
| GCP.Compute.Images.deprecated | string | The deprecation status associated with this image. |
| GCP.Compute.Images.deprecated.state | string | The deprecation state of this resource. This can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image, can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Images.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The suggested replacement resource must be the same kind of resource as the deprecated resource. |
| GCP.Compute.Images.deprecated.deprecated | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.deprecated.obsolete | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.deprecated.deleted | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Images.status | string | The status of the image. An image can be used to create other resources, such as instances, only after the image has been successfully created and the status is set to READY. Possible values are FAILED, PENDING, or READY. |
| GCP.Compute.Images.archiveSizeBytes | string | Size of the image tar.gz archive stored in Google Cloud Storage \(in bytes\). |
| GCP.Compute.Images.diskSizeGb | string | Size of the image when restored onto a persistent disk \(in GB\). |
| GCP.Compute.Images.sourceDisk | string | URL of the source disk used to create this image. This can be a full or valid partial URL. You must provide either this property or the rawDisk.source property but not both to create an image. For example, the following are valid values: https://www.googleapis.com/compute/v1/projects/project/zones/zone/disks/disk , projects/project/zones/zone/disks/disk , zones/zone/disks/disk. |
| GCP.Compute.Images.sourceDiskId | string | The ID value of the disk used to create this image. This value may be used to determine whether the image was taken from the current or a previous instance of a given disk name. |
| GCP.Compute.Images.licenses | string | Any applicable license URI. |
| GCP.Compute.Images.family | string | The name of the image family to which this image belongs. You can create disks by specifying an image family instead of a specific image name. The image family always returns its latest image that is not deprecated. The name of the image family must comply with RFC1035. |
| GCP.Compute.Images.imageEncryptionKey | string | Encrypts the image using a customer-supplied encryption key. After you encrypt an image with a customer-supplied key, you must provide the same key if you use the image later \(e.g. to create a disk from the image\). Customer-supplied encryption keys do not protect access to metadata of the disk. If you do not provide an encryption key when creating the image, then the disk will be encrypted using an automatically generated key and you do not need to provide a key to use the image later. |
| GCP.Compute.Images.imageEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.imageEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.imageEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.sourceDiskEncryptionKey | string | The customer-supplied encryption key of the source disk. Required if the source disk is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceDiskEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceDiskEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceDiskEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Images.labels | string | Labels to apply to this image. These can be later modified by the setLabels method. |
| GCP.Compute.Images.labelFingerprint | string | A fingerprint for the labels being applied to this image, which is essentially a hash of the labels used for optimistic locking. The fingerprint is initially generated by Compute Engine and changes after every request to modify or update labels. You must always provide an up-to-date fingerprint hash in order to update or change labels, otherwise the request will fail with error 412 conditionNotMet. |
| GCP.Compute.Images.guestOsFeatures | string | A list of features to enable on the guest operating system. Applicable only for bootable images. Read Enabling guest operating system features to see a list of available options. |
| GCP.Compute.Images.guestOsFeatures.type | string | The ID of a supported feature. Read Enabling guest operating system features to see a list of available options. |
| GCP.Compute.Images.licenseCodes | string | Integer license codes indicating which licenses are attached to this image. |
| GCP.Compute.Images.sourceImage | string | URL of the source image used to create this image. This can be a full or valid partial URL. |
| GCP.Compute.Images.sourceImageId | string | The ID value of the image used to create this image. This value may be used to determine whether the image was taken from the current or a previous instance of a given image name. |
| GCP.Compute.Images.sourceImageEncryptionKey | string | The customer-supplied encryption key of the source image. Required if the source image is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceImageEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceImageEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceImageEncryptionKey.sha256 | string |  The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.sourceSnapshot | string | URL of the source snapshot used to create this image. This can be a full or valid partial URL. |
| GCP.Compute.Images.sourceSnapshotId | string |  The ID value of the snapshot used to create this image. This value may be used to determine whether the snapshot was taken from the current or a previous instance of a given snapshot name. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey | string | The customer-supplied encryption key of the source snapshot. Required if the source snapshot is protected by a customer-supplied encryption key. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.rawKey | string | Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648 base64 to either encrypt or decrypt this resource. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.kmsKeyName | string | The name of the encryption key that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.sha256 | string | The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource. |
| GCP.Compute.Images.kind | string | Type of the resource. Always compute\#image for images. |

### gcp-compute-instance-group-get

***
Returns a specific instance group. Required permission: compute.instanceGroups.get.

#### Base Command

`gcp-compute-instance-group-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_group | The name of the instance group. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.InstanceGroups.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.InstanceGroups.creationTimestamp | string | The creation timestamp for this instance group in RFC3339 text format. |
| GCP.Compute.InstanceGroups.name | string | The name of the instance group. The name must be 1-63 characters long, and comply with RFC1035. |
| GCP.Compute.InstanceGroups.description | string | An optional description of this resource. |
| GCP.Compute.InstanceGroups.namedPorts | string | Assigns a name to a port number. |
| GCP.Compute.InstanceGroups.namedPorts.name | string | The name for this named port. The name must be 1-63 characters long, and comply with RFC1035. |
| GCP.Compute.InstanceGroups.namedPorts.port | string | The port number, which can be a value between 1 and 65535. |
| GCP.Compute.InstanceGroups.network | string | The URL of the network to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.fingerprint | string | The fingerprint of the named ports. The system uses this fingerprint to detect conflicts when multiple users change the named ports concurrently. |
| GCP.Compute.InstanceGroups.zone | string | The URL of the zone where the instance group is located \(for zonal resources\). |
| GCP.Compute.InstanceGroups.selfLink | string | The URL for this instance group. The server generates this URL. |
| GCP.Compute.InstanceGroups.size | string | The total number of instances in the instance group. |
| GCP.Compute.InstanceGroups.region | string | The URL of the region where the instance group is located \(for regional resources\). |
| GCP.Compute.InstanceGroups.subnetwork | string | The URL of the subnetwork to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.kind | string |  The resource type, which is always compute\#instance_group for instance groups. |

### gcp-compute-region-get

***
Returns a specific region resource. Required permission: compute.regions.get.

#### Base Command

`gcp-compute-region-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | Name of the region resource to return. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Regions.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Regions.creationTimestamp | string |  Creation timestamp in RFC3339 text format. |
| GCP.Compute.Regions.name | string | Name of the resource. |
| GCP.Compute.Regions.description | string | Textual description of the resource. |
| GCP.Compute.Regions.status | string | Status of the region, either UP or DOWN. |
| GCP.Compute.Regions.zones | string | A list of zones available in this region, in the form of resource URLs. |
| GCP.Compute.Regions.quotas | string | Quotas assigned to this region. |
| GCP.Compute.Regions.quotas.metric | string | Name of the quota metric. |
| GCP.Compute.Regions.quotas.limit | string | Quota limit for this metric. |
| GCP.Compute.Regions.quotas.usage | string |  Current usage of this metric. |
| GCP.Compute.Regions.quotas.owner | string | Owning resource. The resource to which this quota applies. |
| GCP.Compute.Regions.deprecated | string | The deprecation status associated with this region. |
| GCP.Compute.Regions.deprecated.state | string | The deprecation state of this resource. This can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image, can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Regions.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The suggested replacement resource must be the same kind of resource as the deprecated resource. |
| GCP.Compute.Regions.deprecated.deprecated | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.obsolete | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.deleted | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Regions.kind | string | Type of the resource. Always compute\#region for regions. |

### gcp-compute-zone-get

***
Returns a specific zone resource. Required permission: compute.zones.get.

#### Base Command

`gcp-compute-zone-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zone | Name of the zone resource to return. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Zones.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Zones.creationTimestamp | string |  Creation timestamp in RFC3339 text format. |
| GCP.Compute.Zones.name | string | Name of the resource. |
| GCP.Compute.Zones.description | string | Textual description of the resource. |
| GCP.Compute.Zones.status | string | Status of the zone, either UP or DOWN. |
| GCP.Compute.Zones.deprecated | string | The deprecation status associated with this zone. |
| GCP.Compute.Zones.deprecated.state | string | The deprecation state of this resource. This can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image, can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Zones.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The suggested replacement resource must be the same kind of resource as the deprecated resource. |
| GCP.Compute.Zones.deprecated.deprecated | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.deprecated.obsolete | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.deprecated.deleted | string | An optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED. This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.region | string | Full URL reference to the region which hosts the zone. |
| GCP.Compute.Zones.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Zones.availableCpuPlatforms | string | Available cpu/platform selections for the zone. Do not use field = 7 or field = 11. Next available field = 14. |
| GCP.Compute.Zones.kind | string | Type of the resource. Always compute\#zone for zones. |

### gcp-compute-networks-list

***
Retrieves a list of networks available for the specified project. Required permission: compute.networks.list.

#### Base Command

`gcp-compute-networks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results per page that should be returned. If the number of available results is larger than limit, Compute Engine returns a nextPageToken that can be used to get the next page of results in subsequent list requests. Acceptable values are 0 to 50, inclusive. Default is 50. | Optional |
| filters | A filter expression that filters resources listed in the response. The expression must specify the field name, a comparison operator, and the value that you want to use for filtering. The value must be a string, a number, or a boolean. The comparison operator must be either =, !=, &gt;, or &lt;.  For example, if you are filtering Compute Engine instances, you can exclude instances named example-instance by specifying name != example-instance. | Optional |
| order_by | Sorts list results by a certain order. By default, results are returned in alphanumerical order based on the resource name.  You can also sort results in descending order based on the creation timestamp using order_by="creationTimestamp desc". This sorts results based on the creationTimestamp field in reverse chronological order (newest result first). Use this to sort resources like operations so that the newest operation is returned first. | Optional |
| page_token | Specifies a page token to use. Set page_token to the nextPageToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Networks.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Networks.creationTimestamp | string | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Networks.name | string | Name of the resource. Provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Networks.description | string | An optional description of this resource. |
| GCP.Compute.Networks.gatewayIPv4 | string | The gateway address for default routing out of the network. This value is read only and is selected by GCP. |
| GCP.Compute.Networks.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Networks.autoCreateSubnetworks | boolean | When set to true, the VPC network is created in "auto" mode. When set to false, the VPC network is created in "custom" mode. |
| GCP.Compute.Networks.subnetworks | string | Server-defined fully-qualified URLs for all subnetworks in this VPC network. |
| GCP.Compute.Networks.peerings | string |  A list of network peerings for the resource. |
| GCP.Compute.Networks.peerings.name | string | Name of this peering. Provided by the client when the peering is created. The name must comply with RFC1035. Specifically, the name must be 1-63 characters long and match regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all the following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Networks.peerings.network | string | The URL of the peer network. It can be either full URL or partial URL. The peer network may belong to a different project. If the partial URL does not contain project, it is assumed that the peer network is in the same project as the current network. |
| GCP.Compute.Networks.peerings.state | string | State for the peering. |
| GCP.Compute.Networks.peerings.stateDetails | string | Details about the current state of the peering. |
| GCP.Compute.Networks.peerings.autoCreateRoutes | boolean | This field will be deprecated soon. Prefer using exchangeSubnetRoutes instead. Indicates whether full mesh connectivity is created and managed automatically. When set to true, Google Compute Engine automatically creates and manages the routes between two networks while the state is ACTIVE. If set to false, the user must manually create routes to direct packets to the peer network. |
| GCP.Compute.Networks.peerings.exchangeSubnetRoutes | boolean | Whether full mesh connectivity is created and managed automatically. When set to true, Google Compute Engine automatically creates and manages the routes between two networks while the peering state is ACTIVE. If set to false, the user must manually create routes to send packets to the peer network. |
| GCP.Compute.Networks.routingConfig | string | The network-level routing configuration for this network. Used by Cloud Router to determine what type of network-wide routing behavior to enforce. |
| GCP.Compute.Networks.routingConfig.routingMode | string | Specifies the network-wide routing mode. If set to REGIONAL, the network’s cloud routers advertise routes only for subnets in the same region as the router. If set to GLOBAL, cloud routers advertise routes for all subnets in the network across all regions. |
| GCP.Compute.Networks.kind | string | Type of the resource. Always compute\#network for networks. |

### gcp-compute-network-insert

***
Creates a network in the specified project using the data included in the request. Required permission: compute.networks.create.

#### Base Command

`gcp-compute-network-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |
| name | Name of the resource. Provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression [a-z]([-a-z0-9]*[a-z0-9])? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. | Required |
| description | An optional description of this resource. | Optional |
| auto_create_sub_networks | When set to true, the VPC network is created in "auto" mode. When set to false, the VPC network is created in "custom" mode. An auto mode VPC network starts with one subnet per region. Each subnet has a predetermined range as described in Auto mode VPC network IP ranges. Possible values are: true, false. | Optional |
| routing_config_routing_mode | The network-wide routing mode to use. If set to REGIONAL, this network's cloud routers will only advertise routes with subnets of this network in the same region as the router. If set to GLOBAL, this network's cloud routers will advertise routes with all subnets of this network, across regions. Possible values are: REGIONAL, GLOBAL. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Operations.name | string | Name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if you provided it in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | User who requested the operation for example EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format. |
| GCP.Compute.Operations.error | string | If errors are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.error.errors | string | The array of errors encountered while processing this operation. |
| GCP.Compute.Operations.error.errors | string | The error type identifier for this error. |
| GCP.Compute.Operations.error.errors | string | Indicates the field in the request that caused the error. This property is optional. |
| GCP.Compute.Operations.error.errors | string | An optional, human-readable error message. |
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. |
| GCP.Compute.Operations.warnings.code | string | A warning code, if applicable. For example, Compute Engine returns NO_RESULTS_ON_PAGE if there are no results in the response. |
| GCP.Compute.Operations.warnings.message | string | A human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | string | Metadata about this warning in key: value format. |
| GCP.Compute.Operations.warnings.data | string | A key that provides more detail on the warning being returned. For example, for warnings where there are no results in a list request for a particular zone, this key might be scope and the key value might be the zone name. Other examples might be a key indicating a deprecated resource and a suggested replacement, or a warning about invalid network settings \(for example, if an instance attempts to perform IP forwarding but is not enabled for IP forwarding\). |
| GCP.Compute.Operations.warnings.data | string | A warning data value corresponding to the key. |
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-network-get

***
Returns the specified network.

#### Base Command

`gcp-compute-network-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | Name of the network to return. | Required |
| project_id | The GCP project ID. Required for Cortex XSIAM (version &gt;= 3.0) and Cortex Platform; optional for Cortex XSOAR and Cortex XSIAM (version &lt; 3.0), where it can be retrieved from the integration configuration. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Networks.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Networks.creationTimestamp | string | Creation timestamp in RFC3339 text format. |
| GCP.Compute.Networks.name | string | Name of the resource. Provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Networks.description | string | An optional description of this resource. |
| GCP.Compute.Networks.gatewayIPv4 | string | The gateway address for default routing out of the network. This value is read only and is selected by GCP. |
| GCP.Compute.Networks.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Networks.autoCreateSubnetworks | boolean | When set to true, the VPC network is created in "auto" mode. When set to false, the VPC network is created in "custom" mode. |
| GCP.Compute.Networks.subnetworks | string | Server-defined fully-qualified URLs for all subnetworks in this VPC network. |
| GCP.Compute.Networks.peerings | string |  A list of network peerings for the resource. |
| GCP.Compute.Networks.peerings.name | string | Name of this peering. Provided by the client when the peering is created. The name must comply with RFC1035. Specifically, the name must be 1-63 characters long and match regular expression \[a-z\]\(\[-a-z0-9\]\*\[a-z0-9\]\)? which means the first character must be a lowercase letter, and all the following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. |
| GCP.Compute.Networks.peerings.network | string | The URL of the peer network. It can be either full URL or partial URL. The peer network may belong to a different project. If the partial URL does not contain project, it is assumed that the peer network is in the same project as the current network. |
| GCP.Compute.Networks.peerings.state | string | State for the peering. |
| GCP.Compute.Networks.peerings.stateDetails | string | Details about the current state of the peering. |
| GCP.Compute.Networks.peerings.autoCreateRoutes | boolean | This field will be deprecated soon. Prefer using exchangeSubnetRoutes instead. Indicates whether full mesh connectivity is created and managed automatically. When it is set to true, Google Compute Engine will automatically create and manage the routes between two networks when the state is ACTIVE. Otherwise, user needs to create routes manually to route packets to peer network. |
| GCP.Compute.Networks.peerings.exchangeSubnetRoutes | boolean | Whether full mesh connectivity is created and managed automatically. When it is set to true, Google Compute Engine will automatically create and manage the routes between two networks when the peering state is ACTIVE. Otherwise, user needs to create routes manually to route packets to peer network. |
| GCP.Compute.Networks.routingConfig | string | The network-level routing configuration for this network. Used by Cloud Router to determine what type of network-wide routing behavior to enforce. |
| GCP.Compute.Networks.routingConfig.routingMode | string | The network-wide routing mode to use. If set to REGIONAL, this networks cloud routers will only advertise routes with subnets of this network in the same region as the router. If set to GLOBAL, this networks cloud routers will advertise routes with all subnets of this network, across regions. |
| GCP.Compute.Networks.kind | string | Type of the resource. Always compute\#network for networks. |

| email | The email address to remove from the dataset access list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.BigQuery.Datasets.kind | String | The resource type. |
| GCP.BigQuery.Datasets.etag | String | A hash of the resource. |
| GCP.BigQuery.Datasets.id | String | The fully-qualified unique name of the dataset in the format projectId:datasetId. |
| GCP.BigQuery.Datasets.selfLink | String | A URL that can be used to access the resource again. |
| GCP.BigQuery.Datasets.datasetReference | Unknown | A reference that identifies the dataset. |
| GCP.BigQuery.Datasets.friendlyName | String | A descriptive name for the dataset. |
| GCP.BigQuery.Datasets.description | String | A user-friendly description of the dataset. |
| GCP.BigQuery.Datasets.defaultTableExpirationMs | String | The default lifetime of all tables in the dataset, in milliseconds. |
| GCP.BigQuery.Datasets.defaultPartitionExpirationMs | String | The default partition expiration, in milliseconds. |
| GCP.BigQuery.Datasets.labels | String | The labels associated with this dataset. |
| GCP.BigQuery.Datasets.access.role | String | The role assigned to the entity. |
| GCP.BigQuery.Datasets.access.userByEmail | String | An email address of a user to grant access to. |
| GCP.BigQuery.Datasets.access.groupByEmail | String | An email address of a group to grant access to. |
| GCP.BigQuery.Datasets.access.domain | String | A domain to grant access to. |
| GCP.BigQuery.Datasets.access.specialGroup | String | A special group to grant access to. |
| GCP.BigQuery.Datasets.access.iamMember | String | A type of member that appears in the IAM Policy that isn't a user, group, domain, or special group. |
| GCP.BigQuery.Datasets.access.view | Unknown | A view from a different dataset to grant access to. |
| GCP.BigQuery.Datasets.access.routine | Unknown | A routine from a different dataset to grant access to. |
| GCP.BigQuery.Datasets.access.dataset | Unknown | A grant authorizing access to this dataset for all resources of a particular type. |
| GCP.BigQuery.Datasets.access.condition | Unknown | The binding condition. |
| GCP.BigQuery.Datasets.creationTime | String | The time since the epoch the dataset was created, in milliseconds. |
| GCP.BigQuery.Datasets.lastModifiedTime | String | The time since the epoch the dataset was last modified, in milliseconds. |
| GCP.BigQuery.Datasets.location | String | The geographic location where the dataset resides. |
| GCP.BigQuery.Datasets.defaultEncryptionConfiguration | String | The default encryption configuration for all tables in the dataset. |
| GCP.BigQuery.Datasets.type | String | The type of the dataset. |
| GCP.BigQuery.Datasets.linkedDatasetSource | Unknown | The source dataset reference when the dataset is of type LINKED. |
| GCP.BigQuery.Datasets.linkedDatasetMetadata | Unknown | Metadata about the LinkedDataset. |
| GCP.BigQuery.Datasets.externalDatasetReference | Unknown | Reference to a read-only external dataset defined in data catalogs outside of BigQuery. |
| GCP.BigQuery.Datasets.externalCatalogDatasetOptions | Unknown | Options defining open source compatible datasets in the BigQuery catalog. Contains metadata of the open source database, schema, or namespace of the current dataset. |
| GCP.BigQuery.Datasets.isCaseInsensitive | String | True if the dataset and its table names are case-insensitive. |
| GCP.BigQuery.Datasets.defaultCollation | String | The default collation specification of future tables created in the dataset. |
| GCP.BigQuery.Datasets.defaultRoundingMode | String | The default rounding mode specification of new tables created within this dataset. |
| GCP.BigQuery.Datasets.maxTimeTravelHours | String | The time travel window in hours. |
| GCP.BigQuery.Datasets.resourceTags | String | The tags attached to this dataset. |
| GCP.BigQuery.Datasets.storageBillingModel | String | The billing model that will be applied to the dataset. |
| GCP.BigQuery.Datasets.catalogSource | String | The origin of the dataset. |
