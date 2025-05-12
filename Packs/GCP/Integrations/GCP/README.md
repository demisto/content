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
| GCP.Compute.Operations.error.errors | string | The array of errors encountered while processing this operation. | 
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
