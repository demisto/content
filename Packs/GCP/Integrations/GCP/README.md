The GCP Integration automates management and security configurations for Compute Engine, Storage, and Container resources on GCP.
This integration was integrated and tested with version v1 (Compute, Storage, Container) and v3 (Resource Manager) of GCP APIs.

## Configure GCP in Cortex


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
| resource_name | Name of the resource; provided by the client when the resource is created. The name must be 1-63 characters long, and comply with RFC1035. Specifically, the name must be 1-63 characters long and match the regular expression [a-z]([-a-z0-9]*[a-z0-9])? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. | Required | 
| description | An optional description of this resource. Provide this property when you create the resource. | Optional | 
| network | URL of the network resource for this firewall rule. If not specified when creating a firewall rule, the default network is used. | Optional | 
| priority | Priority for this rule. This is an integer between 0 and 65535, both inclusive. When not specified, the value assumed is 1000. Relative priorities determine precedence of conflicting rules. Lower value of priority implies higher precedence (eg, a rule with priority 0 has higher precedence than a rule with priority 1). DENY rules take precedence over ALLOW rules having equal priority. | Optional | 
| sourceRanges | If source ranges are specified, the firewall will apply only to traffic that has source IP address in these ranges. These ranges must be expressed in CIDR format. One or both of sourceRanges and sourceTags may be set. If both properties are set, the firewall will apply to traffic that has source IP address within sourceRanges OR the source IP that belongs to a tag listed in the sourceTags property. The connection does not need to match both properties for the firewall to apply. Only IPv4 is supported. comma separated. . | Optional | 
| destinationRanges | If destination ranges are specified, the firewall will apply only to traffic that has destination IP address in these ranges. These ranges must be expressed in CIDR format. Only IPv4 is supported. comma separated. | Optional | 
| sourceTags | If source tags are specified, the firewall rule applies only to traffic with source IPs that match the primary network interfaces of VM instances that have the tag and are in the same VPC network. Source tags cannot be used to control traffic to an instance's external IP address, it only applies to traffic between instances in the same virtual network. Because tags are associated with instances, not IP addresses. One or both of sourceRanges and sourceTags may be set. If both properties are set, the firewall will apply to traffic that has source IP address within sourceRanges OR the source IP that belongs to a tag listed in the sourceTags property. The connection does not need to match both properties for the firewall to apply. comma separated. | Optional | 
| targetTags | A list of tags that controls which instances the firewall rule applies to. If targetTags are specified, then the firewall rule applies only to instances in the VPC network that have one of those tags. If no targetTags are specified, the firewall rule applies to all instances on the specified network. comma separated. | Optional | 
| sourceServiceAccounts | If source service accounts are specified, the firewall will apply only to traffic originating from an instance with a service account in this list. Source service accounts cannot be used to control traffic to an instance's external IP address because service accounts are associated with an instance, not an IP address. sourceRanges can be set at the same time as sourceServiceAccounts. If both are set, the firewall will apply to traffic that has source IP address within sourceRanges OR the source IP belongs to an instance with service account listed in sourceServiceAccount. The connection does not need to match both properties for the firewall to apply. sourceServiceAccounts cannot be used at the same time as sourceTags or targetTags. comma separated. | Optional | 
| targetServiceAccounts | A list of service accounts indicating sets of instances located in the network that may make network connections as specified in allowed[]. targetServiceAccounts cannot be used at the same time as targetTags or sourceTags. If neither targetServiceAccounts nor targetTags are specified, the firewall rule applies to all instances on the specified network. comma separated. | Optional | 
| allowed | The list of ALLOW rules specified by this firewall. Each rule specifies a protocol and port-range tuple that describes a permitted connection. Ex: ipprotocol=tcp,ports=22,443;ipprotocol=tcp,ports=8080,80. | Optional | 
| denied | The list of DENY rules specified by this firewall. Each rule specifies a protocol and port-range tuple that describes a denied connection. Ex: ipprotocol=tcp,ports=22,443;ipprotocol=tcp,ports=8080,80. | Optional | 
| direction | Direction of traffic to which this firewall applies; default is INGRESS. Note: For INGRESS traffic, it is NOT supported to specify destinationRanges; For EGRESS traffic, it is NOT supported to specify sourceRanges OR sourceTags. | Optional | 
| logConfigEnable | This field denotes whether to enable logging for a particular firewall rule. Possible values are: true, false. | Optional | 
| disabled | Denotes whether the firewall rule is disabled, i.e not applied to the network it is associated with. When set to true, the firewall rule is not enforced and the network behaves as if it did not exist. If this is unspecified, the firewall rule will be enabled. Possible values are: true, false. | Optional | 

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
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. | 
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. | 
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. | 
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. | 
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. | 
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
| entity | Entity to remove from the Access Control List.<br/>Common entity formats are:<br/>* user:&lt;userId or email&gt;<br/>* group:&lt;groupId or email&gt;<br/>* allUsers<br/>* allAuthenticatedUsers<br/>For more options and details, see: https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource . Default is allUsers. | Optional | 

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

### gcp-compute-instance-metadata-add

***
Sets metadata for the specified instance to the data included in the request.

#### Base Command

`gcp-compute-instance-metadata-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| zone | The name of the zone for this request. | Required | 
| resource_name | Name of the instance scoping this request. | Required | 
| metadata | Metadata to be made available to the guest operating system running on the instances. Each entry is a key/value pair separated by ';' like so: key=abc,value=123;key=abc,value=123. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. | 
| GCP.Compute.Operations.insertTime | Date | The time that this operation was started by the server. | 
| GCP.Compute.Operations.selfLink | String | Server-defined URL for the project. | 
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. | 
| GCP.Compute.Operations.name | String | Name of the operation. | 
| GCP.Compute.Operations.progress | number | Progress indicator that ranges from 0 to 100. | 
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. | 
| GCP.Compute.Operations.startTime | String | The time that this operation was started by the server. | 
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following PENDING, RUNNING, or DONE. | 
| GCP.Compute.Operations.kind | String | Type of the resource. Always compute\#operation. | 

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
| cidrs | Comma-separated list of up to 50 CIDR blocks (e.g., "192.168.0.0/24,10.0.0.0/32") that are allowed to access the Kubernetes master via HTTPS.<br/>Required if `enable_master_authorized_networks` is true.<br/>. | Optional | 

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
### gcp-iam-project-deny-policy-create

***
Creates an IAM deny policy to explicitly block access to specific resources, services, or permissions.

#### Base Command

`gcp-iam-project-deny-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| policy_id | ID of the deny policy. | Required | 
| denied_principals | List of members to deny access. | Required | 
| denied_permissions | List of permissions to deny. | Required | 
| resource | Full resource name (e.g., //cloudresourcemanager.googleapis.com/projects/my-project). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.IAM.DenyPolicy.policyId | string | ID of the deny policy. | 
| GCP.IAM.DenyPolicy.name | string | Full resource name of the policy. | 
| GCP.IAM.DenyPolicy.rules | unknown | Deny rules in the policy. | 
| GCP.IAM.DenyPolicy.etag | string | Etag of the policy for concurrency control. | 

### gcp-compute-instance-service-account-set

***
Sets or removes a service account from a GCP Compute Engine VM instance.

#### Base Command

`gcp-compute-instance-service-account-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| zone | The name of the zone for this request. | Required | 
| resource_name | Name of the VM instance. | Required | 
| service_account | Email of the service account. | Optional | 
| scopes | OAuth scopes to assign. | Optional | 

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
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. | 
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. | 
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. | 
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. | 
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. | 
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. | 
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. | 

### gcp-compute-instance-service-account-remove

***
Removes the service account associated with a GCP Compute Engine VM instance.

#### Base Command

`gcp-compute-instance-service-account-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| zone | The name of the zone for this request. | Required | 
| resource_name | Name of the VM instance. | Required | 

#### Context Output

There is no context output for this command.
### gcp-iam-group-membership-delete

***
Removes a user or service account from a GSuite group.

#### Base Command

`gcp-iam-group-membership-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| group_id | ID or email of the group. | Required | 
| member_key | ID or email of the member to remove. | Required | 

#### Context Output

There is no context output for this command.
### gcp-iam-service-account-delete

***
Deletes a GCP IAM service account.

#### Base Command

`gcp-iam-service-account-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| service_account_email | Email of the service account to delete. | Required | 

#### Context Output

There is no context output for this command.
### gcp-compute-instance-start

***
Starts an instance that was stopped using the instances().stop method. For more information, see Restart an instance.

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
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. | 
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. | 
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. | 
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. | 
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. | 
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. | 
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. | 

### gcp-compute-instance-stop

***
Stops a running instance, shutting it down cleanly, and allows you to restart the instance at a later time. Stopped instances do not incur VM usage charges while they are stopped. However, resources that the VM is using, such as persistent disks and static IP addresses, will continue to be charged until they are deleted. For more information, see Stopping an instance.

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
| GCP.Compute.Operations.warnings | string | If warning messages are generated during processing of the operation, this field will be populated. | 
| GCP.Compute.Operations.httpErrorStatusCode | number | If the operation fails, this field contains the HTTP error status code that was returned. For example, a 404 means the resource was not found. | 
| GCP.Compute.Operations.httpErrorMessage | string | If the operation fails, this field contains the HTTP error message that was returned, such as NOT FOUND. | 
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. | 
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. You must specify this field as part of the HTTP request URL. It is not settable as a field in the request body. | 
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. | 
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. | 

### gcp-admin-user-update

***
Updates user account fields in GSuite, such as names, org unit, or status.

#### Base Command

`gcp-admin-user-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| user_key | Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID. | Required | 
| update_fields | JSON payload of fields to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GSuite.User.id | String | The unique ID for the user. | 
| GCP.GSuite.User.primaryEmail | String | The user's primary email address. | 
| GCP.GSuite.User.firstName | String | The user's first name. | 
| GCP.GSuite.User.lastName | String | The user's last name. | 
| GCP.GSuite.User.customerId | String | The unique ID for the customer's G Suite account. | 
| GCP.GSuite.User.gender | String | Gender. | 
| GCP.GSuite.User.suspended | Boolean | Indicates if the user is suspended. | 
| GCP.GSuite.User.notesValue | String | Contents of notes. | 
| GCP.GSuite.User.notesContentType | String | Content type of notes. | 
| GCP.GSuite.User.isAdmin | Boolean | Indicates a user with super administrator privileges. | 
| GCP.GSuite.User.creationTime | Date | The time the user's account was created. | 
| GCP.GSuite.User.phones.value | String | A human-readable phone number. It may be in any telephone number format. | 
| GCP.GSuite.User.phones.type | String | The type of phone number. | 
| GCP.GSuite.User.phones.primary | Boolean | Indicates if this is the user's primary phone number. | 
| GCP.GSuite.User.phones.customType | String | If the value of type is custom, this property contains the custom type. | 
| GCP.GSuite.User.addresses.type | String | The address type. | 
| GCP.GSuite.User.addresses.customType | String | If the address type is custom, this property contains the custom value. | 
| GCP.GSuite.User.addresses.sourceIsStructured | Boolean | Indicates if the user-supplied address was formatted. Formatted addresses are not currently supported. | 
| GCP.GSuite.User.addresses.formatted | String | A full and unstructured postal address. This is not synced with the structured address fields. | 
| GCP.GSuite.User.addresses.poBox | String | The post office box, if present. | 
| GCP.GSuite.User.addresses.locality | String | The town or city of the address. | 
| GCP.GSuite.User.addresses.countryCode | String | The country code. Uses the ISO 3166-1 standard. | 
| GCP.GSuite.User.addresses.country | String | Country. | 
| GCP.GSuite.User.addresses.postalCode | String | The ZIP or postal code. | 
| GCP.GSuite.User.addresses.region | String | The abbreviated province or state. | 
| GCP.GSuite.User.addresses.streetAddress | String | The street address. | 
| GCP.GSuite.User.addresses.extendedAddress | String | For extended addresses, such as an  address that includes a sub-region. | 
| GCP.GSuite.User.addresses.primary | Boolean | If this is the user's primary address. | 
| GCP.GSuite.User.emails.address | String | The user's secondary email. | 
| GCP.GSuite.User.emails.type | String | The secondary email type. | 
| GCP.GSuite.User.emails.customType | String | If the value of type is custom, this property contains the custom type string. | 
| GCP.GSuite.User.emails.primary | Boolean | Indicates if this is the user's primary email. Only one entry can be marked as primary. | 
| GCP.GSuite.User.ipWhitelisted | Boolean | If true, the user's IP address is added to allow list. | 
| GCP.GSuite.User.recoveryEmail | String | Recovery email of the user. | 
| GCP.GSuite.User.isDelegatedAdmin | Boolean | Indicates if the user is a delegated administrator. | 
| GCP.GSuite.User.recoveryPhone | String | Recovery phone of the user. | 
| GCP.GSuite.User.orgUnitPath | String | The full path of the parent organization associated with the user. If the parent organization is the top-level, it is represented as a forward slash \(/\). | 
| GCP.GSuite.User.isMailboxSetup | Boolean | Indicates if the user's Google mailbox is created. | 
| GCP.GSuite.User.kind | Boolean | The type of the API resource. | 
| GCP.GSuite.User.etag | Boolean | ETag of the resource. | 
| GCP.GSuite.User.hashFunction | String | Stores the hash format of the password property. | 
| GCP.GSuite.User.archived | Boolean | Indicates if the user is archived. | 
| GCP.GSuite.User.fullName | String | The user's full name formed by concatenating the first and last name values. | 
| GCP.GSuite.User.lastLoginTime | Date | The last time the user logged into the user's account. The value is in ISO 8601 date and time format. The time is the complete date plus hours, minutes, and seconds in the form YYYY-MM-DDThh:mm:ssTZD. For example, 2010-04-05T17:30:04\+01:00. | 
| GCP.GSuite.User.deletionTime | Date | The time the user's account was deleted. The value is in ISO 8601 date and time format. The time is the complete date plus hours, minutes, and seconds in the form YYYY-MM-DDThh:mm:ssTZD. For example 2010-04-05T17:30:04\+01:00. | 
| GCP.GSuite.User.agreedToTerms | Boolean | This property is true if the user has completed an initial login and accepted the Terms of Service agreement. | 
| GCP.GSuite.User.suspensionReason | String | Has the reason a user account is suspended either by the administrator or by Google at the time of suspension. The property is returned only if the suspended property is true. | 
| GCP.GSuite.User.changePasswordAtNextLogin | Boolean | Indicates if the user is forced to change their password at next login. This setting doesn't apply when the user signs in via a third-party identity provider. | 
| GCP.GSuite.User.ims.type | Boolean | Type of the user's Instant Messenger \(IM\) account. | 
| GCP.GSuite.User.ims.customType | String | If the IM type is custom, this property holds the custom type string. | 
| GCP.GSuite.User.ims.protocol | String | An IM protocol identifies the IM network. The value can be a custom network or the standard network. | 
| GCP.GSuite.User.ims.customProtocol | String | If the protocol value is custom_protocol, this property holds the custom protocol's string. | 
| GCP.GSuite.User.ims.im | String | The user's IM network ID. | 
| GCP.GSuite.User.ims.primary | Boolean | If this is the user's primary IM. Only one entry in the IM list can have a value of true. | 
| GCP.GSuite.User.externalIds.value | String | The value of the external ID. | 
| GCP.GSuite.User.externalIds.type | String | The type of the external ID. | 
| GCP.GSuite.User.externalIds.customType | String | If the external ID type is custom, this property holds the custom type. | 
| GCP.GSuite.User.relations.value | String | The name of the person the user is related to. | 
| GCP.GSuite.User.relations.type | String | The type of relation. | 
| GCP.GSuite.User.relations.customType | String | If the value of type is custom, this property contains the custom type. | 
| GCP.GSuite.User.organizations.name | String | The name of the organization. | 
| GCP.GSuite.User.organizations.title | String | The user's title within the organization, for example 'member' or 'engineer'. | 
| GCP.GSuite.User.organizations.primary | Boolean | Indicates if this is the user's primary organization. A user may only have one primary organization. | 
| GCP.GSuite.User.organizations.type | String | The type of organization. | 
| GCP.GSuite.User.organizations.customType | String | If the value of type is custom, this property contains the custom type. | 
| GCP.GSuite.User.organizations.department | String | Specifies the department within the organization, such as 'sales' or 'engineering'. | 
| GCP.GSuite.User.organizations.symbol | String | Text string symbol of the organization. For example, the text symbol for Google is GOOG. | 
| GCP.GSuite.User.organizations.location | String | The physical location of the organization. This does not need to be a fully qualified address. | 
| GCP.GSuite.User.organizations.description | String | The description of the organization. | 
| GCP.GSuite.User.organizations.domain | String | The domain the organization belongs to. | 
| GCP.GSuite.User.organizations.costCenter | String | The cost center of the user's organization. | 
| GCP.GSuite.User.organizations.fullTimeEquivalent | String | The full-time equivalent millipercent within the organization \(100000 = 100%\). | 
| GCP.GSuite.User.languages.languageCode | String | Language Code. Should be used for storing Google III LanguageCode string representation for language. Illegal values cause SchemaException. | 
| GCP.GSuite.User.languages.customLanguage | String | Other language. A user can provide their own language name if there is no corresponding Google III language code. If this is set, LanguageCode can't be set. | 
| GCP.GSuite.User.posixAccounts.username | String | The username of the account. | 
| GCP.GSuite.User.posixAccounts.uid | Number | The POSIX compliant user ID. | 
| GCP.GSuite.User.posixAccounts.gid | Number | The default group ID. | 
| GCP.GSuite.User.posixAccounts.homeDirectory | String | The path to the home directory for this account. | 
| GCP.GSuite.User.posixAccounts.shell | String | The path to the login shell for this account. | 
| GCP.GSuite.User.posixAccounts.gecos | String | The GECOS \(user information\) for this account. | 
| GCP.GSuite.User.posixAccounts.systemId | String | System identifier for which account Username or Uid apply to. | 
| GCP.GSuite.User.posixAccounts.primary | Boolean | If this is user's primary account within the SystemId. | 
| GCP.GSuite.User.posixAccounts.accountId | String | A POSIX account field identifier. | 
| GCP.GSuite.User.posixAccounts.operatingSystemType | String | The operating system type for this account. | 
| GCP.GSuite.User.sshPublicKeys.key | String | An SSH public key. | 
| GCP.GSuite.User.sshPublicKeys.expirationTimeUsec | String | An expiration time in microseconds since epoch. | 
| GCP.GSuite.User.sshPublicKeys.fingerprint | String | A SHA-256 fingerprint of the SSH public key. | 
| GCP.GSuite.User.aliases | Unknown | List of the user's alias email addresses. | 
| GCP.GSuite.User.nonEditableAliases | Unknown | List of the user's non-editable alias email addresses. These are typically outside the account's primary domain or sub-domain. | 
| GCP.GSuite.User.websites.value | String | The URL of the website. | 
| GCP.GSuite.User.websites.primary | Boolean | If this is user's primary website or not. | 
| GCP.GSuite.User.websites.type | String | The type or purpose of the website. For example, a website could be labeled as home or blog. Alternatively, an entry can have a custom type. | 
| GCP.GSuite.User.websites.customType | String | The custom type. Only used if the type is custom. | 
| GCP.GSuite.User.locations.type | String | The location type. | 
| GCP.GSuite.User.locations.customType | String | If the location type is custom, this property contains the custom value. | 
| GCP.GSuite.User.locations.area | String | Textual location. This is most useful for display purposes to concisely describe the location. For example, "Mountain View, CA", "Near Seattle". | 
| GCP.GSuite.User.locations.buildingId | String | Building identifier. | 
| GCP.GSuite.User.locations.floorName | String | Floor name/number. | 
| GCP.GSuite.User.locations.floorSection | String | Floor section. More specific location within the floor. For example, if a floor is divided into sections "A", "B", and "C", this field would identify one of those values. | 
| GCP.GSuite.User.locations.deskCode | String | Most specific textual code of individual desk location. | 
| GCP.GSuite.User.keywords.type | String | Each entry can have a type which indicates standard type of that entry. For example, keyword could be of type occupation or outlook. In addition to the standard type, an entry can have a custom type and can give it any name. Such types should have the CUSTOM value as type and also have a customType value. | 
| GCP.GSuite.User.keywords.customType | String | Custom Type. | 
| GCP.GSuite.User.keywords.value | String | Keyword. | 
| GCP.GSuite.User.isEnrolledIn2Sv | Boolean | Is enrolled in 2-step verification. | 
| GCP.GSuite.User.isEnforcedIn2Sv | Boolean | Is 2-step verification enforced. | 
| GCP.GSuite.User.includeInGlobalAddressList | Boolean | Indicates if the user's profile is visible in the G Suite global address list when the contact sharing feature is enabled for the domain. | 
| GCP.GSuite.User.thumbnailPhotoUrl | String | Photo Url of the user. | 
| GCP.GSuite.User.thumbnailPhotoEtag | String | ETag of the user's photo. | 
| GCP.GSuite.User.customSchemas | Unknown | Custom fields of the user. | 

### gcp-admin-user-password-reset

***
Resets the password for a GSuite user account.

#### Base Command

`gcp-admin-user-password-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| user_key | Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID. | Required | 
| new_password | New password to set. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GSuite.User.id | String | The unique ID for the user. | 
| GCP.GSuite.User.primaryEmail | String | The user's primary email address. | 
| GCP.GSuite.User.firstName | String | The user's first name. | 
| GCP.GSuite.User.lastName | String | The user's last name. | 
| GCP.GSuite.User.customerId | String | The unique ID for the customer's G Suite account. | 
| GCP.GSuite.User.gender | String | The user's gender. | 
| GCP.GSuite.User.suspended | Boolean | Indicates if the user is suspended. | 
| GCP.GSuite.User.notesValue | String | Content of the notes. | 
| GCP.GSuite.User.notesContentType | String | Content type of the notes. | 
| GCP.GSuite.User.isAdmin | Boolean | Indicates a user with super administrator privileges. | 
| GCP.GSuite.User.creationTime | Date | The time the user's account was created. | 
| GCP.GSuite.User.phones.value | String | A human-readable phone number. It may be in any telephone number format. | 
| GCP.GSuite.User.phones.type | String | The type of phone number. | 
| GCP.GSuite.User.phones.primary | Boolean | Indicates if this is the user's primary phone number. | 
| GCP.GSuite.User.phones.customType | String | If the value of type is custom, this property contains the custom type string. | 
| GCP.GSuite.User.addresses.type | String | The address type. | 
| GCP.GSuite.User.addresses.customType | String | If the value of type is custom, this property contains the custom type string. | 
| GCP.GSuite.User.addresses.sourceIsStructured | Boolean | Indicates if the user-supplied address was formatted. Formatted addresses are not currently supported. | 
| GCP.GSuite.User.addresses.formatted | String | A full and unstructured postal address. This is not synced with the structured address fields. | 
| GCP.GSuite.User.addresses.poBox | String | The post office box, if present. | 
| GCP.GSuite.User.addresses.locality | String | The town or city of the address. | 
| GCP.GSuite.User.addresses.countryCode | String | The country code. Uses the ISO 3166-1 standard. | 
| GCP.GSuite.User.addresses.country | String | Country. | 
| GCP.GSuite.User.addresses.postalCode | String | The ZIP or postal code. | 
| GCP.GSuite.User.addresses.region | String | The abbreviated province or state. | 
| GCP.GSuite.User.addresses.streetAddress | String | The street address. | 
| GCP.GSuite.User.addresses.extendedAddress | String | For extended addresses, such as an address that includes a sub-region. | 
| GCP.GSuite.User.addresses.primary | Boolean | If this is the user's primary address. | 
| GCP.GSuite.User.emails.address | String | The user's secondary email. | 
| GCP.GSuite.User.emails.type | String | The secondary email type. | 
| GCP.GSuite.User.emails.customType | String | If the value of type is custom, this property contains the custom type string. | 
| GCP.GSuite.User.emails.primary | Boolean | Indicates if this is the user's primary email. Only one entry can be marked as primary. | 
| GCP.GSuite.User.ipWhitelisted | Boolean | If true, the user's IP address is added to the allow list. | 
| GCP.GSuite.User.recoveryEmail | String | Recovery email of the user. | 
| GCP.GSuite.User.isDelegatedAdmin | Boolean | Indicates if the user is a delegated administrator. | 
| GCP.GSuite.User.recoveryPhone | String | Recovery phone of the user. | 
| GCP.GSuite.User.orgUnitPath | String | The full path of the parent organization associated with the user. If the parent organization is the top-level, it is represented as a forward slash \(/\). | 
| GCP.GSuite.User.isMailboxSetup | Boolean | Indicates if the user's Google mailbox is created. | 
| GCP.GSuite.User.kind | Boolean | The type of the API resource. | 
| GCP.GSuite.User.etag | Boolean | ETag of the resource. | 
| GCP.GSuite.User.hashFunction | String | Stores the hash format of the password property. | 
| GCP.GSuite.User.archived | Boolean | Indicates if the user is archived. | 
| GCP.GSuite.User.fullName | String | The user's full name formed by concatenating the first and last name values. | 
| GCP.GSuite.User.lastLoginTime | Date | The last time the user logged into the user's account. The value is in ISO 8601 date and time format. The time is the complete date plus hours, minutes, and seconds in the form YYYY-MM-DDThh:mm:ssTZD. For example, 2010-04-05T17:30:04\+01:00. | 
| GCP.GSuite.User.deletionTime | Date | The time the user's account was deleted. The value is in ISO 8601 date and time format. The time is the complete date plus hours, minutes, and seconds in the form YYYY-MM-DDThh:mm:ssTZD. For example 2010-04-05T17:30:04\+01:00. | 
| GCP.GSuite.User.agreedToTerms | Boolean | This property is true if the user has completed an initial login and accepted the Terms of Service agreement. | 
| GCP.GSuite.User.suspensionReason | String | The reason a user account is suspended either by the administrator or by Google at the time of suspension. The property is returned only if the suspended property is true. | 
| GCP.GSuite.User.changePasswordAtNextLogin | Boolean | Indicates if the user is forced to change their password at next login. This setting doesn't apply when the user signs in via a third-party identity provider. | 
| GCP.GSuite.User.ims.type | Boolean | Type of the user's Instant Messenger \(IM\) account. | 
| GCP.GSuite.User.ims.customType | String | If the IM type is custom, this property holds the custom type string. | 
| GCP.GSuite.User.ims.protocol | String | An IM protocol identifies the IM network. The value can be a custom network or the standard network. | 
| GCP.GSuite.User.ims.customProtocol | String | If the protocol value is custom_protocol, this property holds the custom protocol's string. | 
| GCP.GSuite.User.ims.im | String | The user's IM network ID. | 
| GCP.GSuite.User.ims.primary | Boolean | If this is the user's primary IM. Only one entry in the IM list can have a value of true. | 
| GCP.GSuite.User.externalIds.value | String | The value of the external ID. | 
| GCP.GSuite.User.externalIds.type | String | The type of the external ID. | 
| GCP.GSuite.User.externalIds.customType | String | If the external ID type is custom, this property holds the custom type. | 
| GCP.GSuite.User.relations.value | String | The name of the person the user is related to. | 
| GCP.GSuite.User.relations.type | String | The type of relationship. | 
| GCP.GSuite.User.relations.customType | String | If the value of type is custom, this property contains the custom type. | 
| GCP.GSuite.User.organizations.name | String | The name of the organization. | 
| GCP.GSuite.User.organizations.title | String | The user's title within the organization, for example 'member' or 'engineer'. | 
| GCP.GSuite.User.organizations.primary | Boolean | Indicates if this is the user's primary organization. A user may only have one primary organization. | 
| GCP.GSuite.User.organizations.type | String | The type of organization. | 
| GCP.GSuite.User.organizations.customType | String | If the value of type is custom, this property contains the custom type. | 
| GCP.GSuite.User.organizations.department | String | Specifies the department within the organization, such as 'sales' or 'engineering'. | 
| GCP.GSuite.User.organizations.symbol | String | Text string symbol of the organization. For example, the text symbol for Google is GOOG. | 
| GCP.GSuite.User.organizations.location | String | The physical location of the organization. This does not need to be a fully qualified address. | 
| GCP.GSuite.User.organizations.description | String | The description of the organization. | 
| GCP.GSuite.User.organizations.domain | String | The domain the organization belongs to. | 
| GCP.GSuite.User.organizations.costCenter | String | The cost center of the user's organization. | 
| GCP.GSuite.User.organizations.fullTimeEquivalent | String | The full-time equivalent millipercent within the organization \(100000 = 100%\). | 
| GCP.GSuite.User.languages.languageCode | String | Language Code. Should be used for storing Google III LanguageCode string representation for language. Illegal values cause SchemaException. | 
| GCP.GSuite.User.languages.customLanguage | String | Other language. A user can provide their own language name if there is no corresponding Google III language code. If this is set, LanguageCode can't be set. | 
| GCP.GSuite.User.posixAccounts.username | String | The username of the account. | 
| GCP.GSuite.User.posixAccounts.uid | Number | The POSIX compliant user ID. | 
| GCP.GSuite.User.posixAccounts.gid | Number | The default group ID. | 
| GCP.GSuite.User.posixAccounts.homeDirectory | String | The path to the home directory for this account. | 
| GCP.GSuite.User.posixAccounts.shell | String | The path to the login shell for this account. | 
| GCP.GSuite.User.posixAccounts.gecos | String | The GECOS \(user information\) for this account. | 
| GCP.GSuite.User.posixAccounts.systemId | String | System identifier for which account Username or UID applies to. | 
| GCP.GSuite.User.posixAccounts.primary | Boolean | If this is the user's primary account within the SystemId. | 
| GCP.GSuite.User.posixAccounts.accountId | String | A POSIX account field identifier. | 
| GCP.GSuite.User.posixAccounts.operatingSystemType | String | The operating system type for this account. | 
| GCP.GSuite.User.sshPublicKeys.key | String | An SSH public key. | 
| GCP.GSuite.User.sshPublicKeys.expirationTimeUsec | String | An expiration time in microseconds since epoch. | 
| GCP.GSuite.User.sshPublicKeys.fingerprint | String | A SHA-256 fingerprint of the SSH public key. | 
| GCP.GSuite.User.aliases | Unknown | List of the user's alias email addresses. | 
| GCP.GSuite.User.nonEditableAliases | Unknown | List of the user's non-editable alias email addresses. These are typically outside the account's primary domain or sub-domain. | 
| GCP.GSuite.User.websites.value | String | The URL of the website. | 
| GCP.GSuite.User.websites.primary | Boolean | If this is the user's primary website or not. | 
| GCP.GSuite.User.websites.type | String | The type or purpose of the website. For example, a website could be labeled as home or blog. Alternatively, an entry can have a custom type. | 
| GCP.GSuite.User.websites.customType | String | The custom type. Only used if the type is custom. | 
| GCP.GSuite.User.locations.type | String | The location type. | 
| GCP.GSuite.User.locations.customType | String | If the location type is custom, this property contains the custom value. | 
| GCP.GSuite.User.locations.area | String | Textual location. This is most useful for display purposes to concisely describe the location. For example, "Mountain View, CA", "Near Seattle". | 
| GCP.GSuite.User.locations.buildingId | String | Building identifier. | 
| GCP.GSuite.User.locations.floorName | String | Floor name/number. | 
| GCP.GSuite.User.locations.floorSection | String | Floor section. More specific location within the floor. For example, if a floor is divided into sections "A", "B", and "C", this field would identify one of those values. | 
| GCP.GSuite.User.locations.deskCode | String | Most specific textual code of individual desk location. | 
| GCP.GSuite.User.keywords.type | String | Each entry can have a type which indicates the standard type of that entry. For example, keyword could be of type occupation or outlook. In addition to the standard type, an entry can have a custom type and can give it any name. Such types should have the CUSTOM value as type and also have a customType value. | 
| GCP.GSuite.User.keywords.customType | String | Custom Type. | 
| GCP.GSuite.User.keywords.value | String | Keyword. | 
| GCP.GSuite.User.isEnrolledIn2Sv | Boolean | Is enrolled in 2-step verification. | 
| GCP.GSuite.User.isEnforcedIn2Sv | Boolean | Is 2-step verification enforced. | 
| GCP.GSuite.User.includeInGlobalAddressList | Boolean | Indicates if the user's profile is visible in the G Suite global address list when the contact sharing feature is enabled for the domain. | 
| GCP.GSuite.User.thumbnailPhotoUrl | String | Photo URL of the user. | 
| GCP.GSuite.User.thumbnailPhotoEtag | String | ETag of the user's photo. | 
| GCP.GSuite.User.customSchemas | Unknown | Custom fields of the user. | 

### gcp-admin-user-signout

***
Signs a user out of all web and device sessions and reset their sign-in cookies.

#### Base Command

`gcp-admin-user-signout`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | GCP project ID. | Required | 
| user_key | Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID. | Required | 

#### Context Output

There is no context output for this command.
