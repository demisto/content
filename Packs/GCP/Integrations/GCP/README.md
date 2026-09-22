The GCP Integration automates management and security configurations for Compute Engine, Storage, and Container resources on GCP.
This integration was integrated and tested with version v1 (Compute, Storage, Container, SERVICE_USAGE), v3 (Resource Manager).

## Configure Google Cloud Platform in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service Account Private Key (JSON) | The full content of a GCP Service Account private key JSON file. In the Google Cloud Console, go to IAM & Admin > Service Accounts and create a service account with the required roles. Then under the Keys tab, create a JSON key. Paste the downloaded JSON contents here. | True |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | Name of the GCS bucket. | Required |
| entity | Entity to remove from the Access Control List.<br/>Common entity formats are:<br/>*user:&lt;userId or email&gt;<br/>* group:&lt;groupId or email&gt;<br/>*allUsers<br/>* allAuthenticatedUsers<br/>For more options and details, see: https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource . Default is allUsers. | Optional |

#### Context Output

There is no context output for this command.

### gcp-compute-subnet-update

***
Enables flow logs or Private Google Access on a subnet. Required permissions: compute.subnetworks.setPrivateIpGoogleAccess, compute.subnetworks.update, compute.subnetworks.get, compute.subnetworks.list.

#### Base Command

`gcp-compute-subnet-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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

### gcp-gke-cluster-legacy-abac-auth-set

***
Enables or disables legacy ABAC authorization for a GKE cluster. Required permissions: container.clusters.update.

#### Base Command

`gcp-gke-cluster-legacy-abac-auth-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the cluster. | Required |
| resource_name | The name of the GKE cluster. | Required |
| enabled | Whether to enable legacy ABAC authorization on the cluster. Possible values are: true, false. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Operations.clusterConditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Operations.detail | String | Detailed operation progress, if available. |
| GCP.GKE.Operations.endTime | String | The time the operation completed, in RFC3339 text format. |
| GCP.GKE.Operations.error | Unknown | The error result of the operation in case of failure. |
| GCP.GKE.Operations.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Operations.name | String | The server-assigned ID for the operation. |
| GCP.GKE.Operations.nodepoolConditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.Operations.operationType | String | The operation type. |
| GCP.GKE.Operations.progress | Unknown | Progress information for an operation. |
| GCP.GKE.Operations.selfLink | String | Server-defined URI for the operation. |
| GCP.GKE.Operations.startTime | String | The time the operation started, in RFC3339 text format. |
| GCP.GKE.Operations.status | String | The current status of the operation. |
| GCP.GKE.Operations.statusMessage | String | If an error has occurred, a textual description of the error. |
| GCP.GKE.Operations.targetLink | String | Server-defined URI for the target of the operation. |
| GCP.GKE.Operations.zone | String | The name of the Google Compute Engine zone in which the operation is taking place. |

### gcp-gke-clusters-list

***
Lists all GKE clusters owned by a project in the specified location. Required permissions: container.clusters.list.

#### Base Command

`gcp-gke-clusters-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) to list clusters from. Use "-" to list clusters from all locations. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Clusters.addonsConfig | Unknown | Configurations for the various addons available to run in the cluster. |
| GCP.GKE.Clusters.alphaClusterFeatureGates | Unknown | The list of user specified Kubernetes feature gates. |
| GCP.GKE.Clusters.anonymousAuthenticationConfig | Unknown | Configuration for limiting anonymous access to all endpoints except the health checks. |
| GCP.GKE.Clusters.authenticatorGroupsConfig | Unknown | Configuration controlling RBAC group membership information. |
| GCP.GKE.Clusters.autopilot | Unknown | Autopilot configuration for the cluster. |
| GCP.GKE.Clusters.autoscaling | Unknown | Cluster-level autoscaling configuration. |
| GCP.GKE.Clusters.binaryAuthorization | Unknown | Configuration for Binary Authorization. |
| GCP.GKE.Clusters.clusterIpv4Cidr | String | The IP address range of the container pods in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.compliancePostureConfig | Unknown | Compliance posture configuration for the cluster \(no longer supported\). |
| GCP.GKE.Clusters.conditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Clusters.confidentialNodes | Unknown | Configuration of Confidential Nodes. |
| GCP.GKE.Clusters.controlPlaneEgress | Unknown | Configuration for control plane egress control. |
| GCP.GKE.Clusters.controlPlaneEndpointsConfig | Unknown | Configuration for all cluster's control plane endpoints. |
| GCP.GKE.Clusters.costManagementConfig | Unknown | Configuration for the fine-grained cost management feature. |
| GCP.GKE.Clusters.createTime | String | The time the cluster was created, in RFC3339 text format. |
| GCP.GKE.Clusters.currentEmulatedVersion | String | The current emulated version of the master endpoint. |
| GCP.GKE.Clusters.currentMasterVersion | String | The current software version of the master endpoint. |
| GCP.GKE.Clusters.currentNodeCount | Number | The number of nodes currently in the cluster. |
| GCP.GKE.Clusters.currentNodeVersion | String | The current version of the Kubernetes nodes in the cluster \(deprecated; use the node pool version instead\). |
| GCP.GKE.Clusters.databaseEncryption | Unknown | Configuration of etcd encryption. |
| GCP.GKE.Clusters.defaultMaxPodsConstraint | Unknown | The default constraint on the maximum number of pods that can be run simultaneously on a node in the node pool of this cluster. |
| GCP.GKE.Clusters.description | String | An optional description of this cluster. |
| GCP.GKE.Clusters.enableK8sBetaApis | Unknown | Beta APIs Config. |
| GCP.GKE.Clusters.enableKubernetesAlpha | Boolean | Kubernetes alpha features are enabled on this cluster. |
| GCP.GKE.Clusters.enableTpu | Boolean | Enable the ability to use Cloud TPUs in this cluster. |
| GCP.GKE.Clusters.endpoint | String | The IP address of this cluster's master endpoint. |
| GCP.GKE.Clusters.enterpriseConfig | Unknown | GKE Enterprise Configuration. |
| GCP.GKE.Clusters.etag | String | This checksum is computed by the server based on the value of cluster fields, and may be sent on update requests to ensure the client has an up-to-date value before proceeding. |
| GCP.GKE.Clusters.expireTime | String | The time the cluster will be automatically deleted in RFC3339 text format. |
| GCP.GKE.Clusters.fleet | Unknown | Fleet information for the cluster. |
| GCP.GKE.Clusters.gkeAutoUpgradeConfig | Unknown | Configuration for GKE auto upgrades. |
| GCP.GKE.Clusters.id | String | Unique id for the cluster. |
| GCP.GKE.Clusters.identityServiceConfig | Unknown | Configuration for Identity Service component. |
| GCP.GKE.Clusters.initialClusterVersion | String | The initial Kubernetes version for this cluster. |
| GCP.GKE.Clusters.initialNodeCount | Number | The number of nodes to create in this cluster. |
| GCP.GKE.Clusters.instanceGroupUrls | Unknown | The instanceGroupUrls of the resource. |
| GCP.GKE.Clusters.ipAllocationPolicy | Unknown | Configuration for cluster IP allocation. |
| GCP.GKE.Clusters.labelFingerprint | String | The fingerprint of the set of labels for this cluster. |
| GCP.GKE.Clusters.legacyAbac | Unknown | Configuration for the legacy ABAC authorization mode. |
| GCP.GKE.Clusters.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Clusters.locations | Unknown | The list of Google Compute Engine zones in which the cluster's nodes should be located. |
| GCP.GKE.Clusters.loggingConfig | Unknown | Logging configuration for the cluster. |
| GCP.GKE.Clusters.loggingService | String | The logging service the cluster should use to write logs. |
| GCP.GKE.Clusters.maintenancePolicy | Unknown | Configure the maintenance policy for this cluster. |
| GCP.GKE.Clusters.managedMachineLearningDiagnosticsConfig | Unknown | Configuration for Managed Machine Learning Diagnostics. |
| GCP.GKE.Clusters.managedOpentelemetryConfig | Unknown | Configuration for Managed OpenTelemetry pipeline. |
| GCP.GKE.Clusters.masterAuth | Unknown | The authentication information for accessing the master endpoint. |
| GCP.GKE.Clusters.masterAuthorizedNetworksConfig | Unknown | The configuration options for master authorized networks feature. |
| GCP.GKE.Clusters.meshCertificates | Unknown | Configuration for issuance of mTLS keys and certificates to Kubernetes pods. |
| GCP.GKE.Clusters.monitoringConfig | Unknown | Monitoring configuration for the cluster. |
| GCP.GKE.Clusters.monitoringService | String | The monitoring service the cluster should use to write metrics. |
| GCP.GKE.Clusters.name | String | The name of this cluster. |
| GCP.GKE.Clusters.network | String | The name of the Google Compute Engine network to which the cluster is connected. |
| GCP.GKE.Clusters.networkConfig | Unknown | Configuration for cluster networking. |
| GCP.GKE.Clusters.networkPolicy | Unknown | Configuration options for the NetworkPolicy feature. |
| GCP.GKE.Clusters.nodeConfig | Unknown | Parameters used in creating the cluster's nodes. |
| GCP.GKE.Clusters.nodeCreationConfig | Unknown | Configuration for Node Creation Mode. |
| GCP.GKE.Clusters.nodeIpv4CidrSize | Number | The size of the address space on each node for hosting containers. |
| GCP.GKE.Clusters.nodePoolAutoConfig | Unknown | Node pool configs that apply to all auto-provisioned node pools in autopilot clusters and node auto-provisioning enabled clusters. |
| GCP.GKE.Clusters.nodePoolDefaults | Unknown | Default NodePool settings for the entire cluster. |
| GCP.GKE.Clusters.nodePools | Unknown | The node pools associated with this cluster. |
| GCP.GKE.Clusters.notificationConfig | Unknown | Notification configuration of the cluster. |
| GCP.GKE.Clusters.parentProductConfig | Unknown | The configuration of the parent product of the cluster. |
| GCP.GKE.Clusters.podAutoscaling | Unknown | The config for pod autoscaling. |
| GCP.GKE.Clusters.privateClusterConfig | Unknown | Configuration for private cluster. |
| GCP.GKE.Clusters.rbacBindingConfig | Unknown | RBACBindingConfig allows user to restrict ClusterRoleBindings an RoleBindings that can be created. |
| GCP.GKE.Clusters.releaseChannel | Unknown | Release channel configuration. |
| GCP.GKE.Clusters.resourceLabels | Unknown | The resource labels for the cluster to use to annotate any related Google Compute Engine resources. |
| GCP.GKE.Clusters.resourceUsageExportConfig | Unknown | Configuration for exporting resource usages. |
| GCP.GKE.Clusters.rollbackSafeUpgrade | Unknown | The rollback safe upgrade information of the cluster. |
| GCP.GKE.Clusters.satisfiesPzi | Boolean | Reserved for future use. |
| GCP.GKE.Clusters.satisfiesPzs | Boolean | Reserved for future use. |
| GCP.GKE.Clusters.scheduleUpgradeConfig | Unknown | Configuration for scheduled upgrades. |
| GCP.GKE.Clusters.secretManagerConfig | Unknown | Secret CSI driver configuration. |
| GCP.GKE.Clusters.secretSyncConfig | Unknown | Configuration for sync Secret Manager secrets as k8s secrets. |
| GCP.GKE.Clusters.securityPostureConfig | Unknown | Enable/Disable Security Posture API features for the cluster. |
| GCP.GKE.Clusters.selfLink | String | Server-defined URL for the resource. |
| GCP.GKE.Clusters.servicesIpv4Cidr | String | The IP address range of the Kubernetes services in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.shieldedNodes | Unknown | Shielded Nodes configuration. |
| GCP.GKE.Clusters.status | String | The current status of this cluster. |
| GCP.GKE.Clusters.statusMessage | String | The statusMessage of the resource. |
| GCP.GKE.Clusters.subnetwork | String | The name of the Google Compute Engine subnetwork to which the cluster is connected. |
| GCP.GKE.Clusters.tpuIpv4CidrBlock | String | The IP address range of the Cloud TPUs in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.userManagedKeysConfig | Unknown | The Custom keys configuration for the cluster. |
| GCP.GKE.Clusters.verticalPodAutoscaling | Unknown | Cluster-level Vertical Pod Autoscaling configuration. |
| GCP.GKE.Clusters.workloadIdentityConfig | Unknown | Configuration for the use of Kubernetes Service Accounts in IAM policies. |
| GCP.GKE.Clusters.zone | String | The name of the Google Compute Engine zone in which the cluster resides. |

### gcp-gke-cluster-get

***
Gets the details of a specific GKE cluster. Required permissions: container.clusters.get.

#### Base Command

`gcp-gke-cluster-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the cluster. | Required |
| resource_name | The name of the GKE cluster. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Clusters.addonsConfig | Unknown | Configurations for the various addons available to run in the cluster. |
| GCP.GKE.Clusters.alphaClusterFeatureGates | Unknown | The list of user specified Kubernetes feature gates. |
| GCP.GKE.Clusters.anonymousAuthenticationConfig | Unknown | Configuration for limiting anonymous access to all endpoints except the health checks. |
| GCP.GKE.Clusters.authenticatorGroupsConfig | Unknown | Configuration controlling RBAC group membership information. |
| GCP.GKE.Clusters.autopilot | Unknown | Autopilot configuration for the cluster. |
| GCP.GKE.Clusters.autoscaling | Unknown | Cluster-level autoscaling configuration. |
| GCP.GKE.Clusters.binaryAuthorization | Unknown | Configuration for Binary Authorization. |
| GCP.GKE.Clusters.clusterIpv4Cidr | String | The IP address range of the container pods in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.compliancePostureConfig | Unknown | Compliance posture configuration for the cluster \(no longer supported\). |
| GCP.GKE.Clusters.conditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Clusters.confidentialNodes | Unknown | Configuration of Confidential Nodes. |
| GCP.GKE.Clusters.controlPlaneEgress | Unknown | Configuration for control plane egress control. |
| GCP.GKE.Clusters.controlPlaneEndpointsConfig | Unknown | Configuration for all cluster's control plane endpoints. |
| GCP.GKE.Clusters.costManagementConfig | Unknown | Configuration for the fine-grained cost management feature. |
| GCP.GKE.Clusters.createTime | String | The time the cluster was created, in RFC3339 text format. |
| GCP.GKE.Clusters.currentEmulatedVersion | String | The current emulated version of the master endpoint. |
| GCP.GKE.Clusters.currentMasterVersion | String | The current software version of the master endpoint. |
| GCP.GKE.Clusters.currentNodeCount | Number | The number of nodes currently in the cluster. |
| GCP.GKE.Clusters.currentNodeVersion | String | The current version of the Kubernetes nodes in the cluster \(deprecated; use the node pool version instead\). |
| GCP.GKE.Clusters.databaseEncryption | Unknown | Configuration of etcd encryption. |
| GCP.GKE.Clusters.defaultMaxPodsConstraint | Unknown | The default constraint on the maximum number of pods that can be run simultaneously on a node in the node pool of this cluster. |
| GCP.GKE.Clusters.description | String | An optional description of this cluster. |
| GCP.GKE.Clusters.enableK8sBetaApis | Unknown | Beta APIs Config. |
| GCP.GKE.Clusters.enableKubernetesAlpha | Boolean | Kubernetes alpha features are enabled on this cluster. |
| GCP.GKE.Clusters.enableTpu | Boolean | Enable the ability to use Cloud TPUs in this cluster. |
| GCP.GKE.Clusters.endpoint | String | The IP address of this cluster's master endpoint. |
| GCP.GKE.Clusters.enterpriseConfig | Unknown | GKE Enterprise Configuration. |
| GCP.GKE.Clusters.etag | String | This checksum is computed by the server based on the value of cluster fields, and may be sent on update requests to ensure the client has an up-to-date value before proceeding. |
| GCP.GKE.Clusters.expireTime | String | The time the cluster will be automatically deleted in RFC3339 text format. |
| GCP.GKE.Clusters.fleet | Unknown | Fleet information for the cluster. |
| GCP.GKE.Clusters.gkeAutoUpgradeConfig | Unknown | Configuration for GKE auto upgrades. |
| GCP.GKE.Clusters.id | String | Unique id for the cluster. |
| GCP.GKE.Clusters.identityServiceConfig | Unknown | Configuration for Identity Service component. |
| GCP.GKE.Clusters.initialClusterVersion | String | The initial Kubernetes version for this cluster. |
| GCP.GKE.Clusters.initialNodeCount | Number | The number of nodes to create in this cluster. |
| GCP.GKE.Clusters.instanceGroupUrls | Unknown | The instanceGroupUrls of the resource. |
| GCP.GKE.Clusters.ipAllocationPolicy | Unknown | Configuration for cluster IP allocation. |
| GCP.GKE.Clusters.labelFingerprint | String | The fingerprint of the set of labels for this cluster. |
| GCP.GKE.Clusters.legacyAbac | Unknown | Configuration for the legacy ABAC authorization mode. |
| GCP.GKE.Clusters.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Clusters.locations | Unknown | The list of Google Compute Engine zones in which the cluster's nodes should be located. |
| GCP.GKE.Clusters.loggingConfig | Unknown | Logging configuration for the cluster. |
| GCP.GKE.Clusters.loggingService | String | The logging service the cluster should use to write logs. |
| GCP.GKE.Clusters.maintenancePolicy | Unknown | Configure the maintenance policy for this cluster. |
| GCP.GKE.Clusters.managedMachineLearningDiagnosticsConfig | Unknown | Configuration for Managed Machine Learning Diagnostics. |
| GCP.GKE.Clusters.managedOpentelemetryConfig | Unknown | Configuration for Managed OpenTelemetry pipeline. |
| GCP.GKE.Clusters.masterAuth | Unknown | The authentication information for accessing the master endpoint. |
| GCP.GKE.Clusters.masterAuthorizedNetworksConfig | Unknown | The configuration options for master authorized networks feature. |
| GCP.GKE.Clusters.meshCertificates | Unknown | Configuration for issuance of mTLS keys and certificates to Kubernetes pods. |
| GCP.GKE.Clusters.monitoringConfig | Unknown | Monitoring configuration for the cluster. |
| GCP.GKE.Clusters.monitoringService | String | The monitoring service the cluster should use to write metrics. |
| GCP.GKE.Clusters.name | String | The name of this cluster. |
| GCP.GKE.Clusters.network | String | The name of the Google Compute Engine network to which the cluster is connected. |
| GCP.GKE.Clusters.networkConfig | Unknown | Configuration for cluster networking. |
| GCP.GKE.Clusters.networkPolicy | Unknown | Configuration options for the NetworkPolicy feature. |
| GCP.GKE.Clusters.nodeConfig | Unknown | Parameters used in creating the cluster's nodes. |
| GCP.GKE.Clusters.nodeCreationConfig | Unknown | Configuration for Node Creation Mode. |
| GCP.GKE.Clusters.nodeIpv4CidrSize | Number | The size of the address space on each node for hosting containers. |
| GCP.GKE.Clusters.nodePoolAutoConfig | Unknown | Node pool configs that apply to all auto-provisioned node pools in autopilot clusters and node auto-provisioning enabled clusters. |
| GCP.GKE.Clusters.nodePoolDefaults | Unknown | Default NodePool settings for the entire cluster. |
| GCP.GKE.Clusters.nodePools | Unknown | The node pools associated with this cluster. |
| GCP.GKE.Clusters.notificationConfig | Unknown | Notification configuration of the cluster. |
| GCP.GKE.Clusters.parentProductConfig | Unknown | The configuration of the parent product of the cluster. |
| GCP.GKE.Clusters.podAutoscaling | Unknown | The config for pod autoscaling. |
| GCP.GKE.Clusters.privateClusterConfig | Unknown | Configuration for private cluster. |
| GCP.GKE.Clusters.rbacBindingConfig | Unknown | RBACBindingConfig allows user to restrict ClusterRoleBindings an RoleBindings that can be created. |
| GCP.GKE.Clusters.releaseChannel | Unknown | Release channel configuration. |
| GCP.GKE.Clusters.resourceLabels | Unknown | The resource labels for the cluster to use to annotate any related Google Compute Engine resources. |
| GCP.GKE.Clusters.resourceUsageExportConfig | Unknown | Configuration for exporting resource usages. |
| GCP.GKE.Clusters.rollbackSafeUpgrade | Unknown | The rollback safe upgrade information of the cluster. |
| GCP.GKE.Clusters.satisfiesPzi | Boolean | Reserved for future use. |
| GCP.GKE.Clusters.satisfiesPzs | Boolean | Reserved for future use. |
| GCP.GKE.Clusters.scheduleUpgradeConfig | Unknown | Configuration for scheduled upgrades. |
| GCP.GKE.Clusters.secretManagerConfig | Unknown | Secret CSI driver configuration. |
| GCP.GKE.Clusters.secretSyncConfig | Unknown | Configuration for sync Secret Manager secrets as k8s secrets. |
| GCP.GKE.Clusters.securityPostureConfig | Unknown | Enable/Disable Security Posture API features for the cluster. |
| GCP.GKE.Clusters.selfLink | String | Server-defined URL for the resource. |
| GCP.GKE.Clusters.servicesIpv4Cidr | String | The IP address range of the Kubernetes services in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.shieldedNodes | Unknown | Shielded Nodes configuration. |
| GCP.GKE.Clusters.status | String | The current status of this cluster. |
| GCP.GKE.Clusters.statusMessage | String | The statusMessage of the resource. |
| GCP.GKE.Clusters.subnetwork | String | The name of the Google Compute Engine subnetwork to which the cluster is connected. |
| GCP.GKE.Clusters.tpuIpv4CidrBlock | String | The IP address range of the Cloud TPUs in this cluster, in CIDR notation. |
| GCP.GKE.Clusters.userManagedKeysConfig | Unknown | The Custom keys configuration for the cluster. |
| GCP.GKE.Clusters.verticalPodAutoscaling | Unknown | Cluster-level Vertical Pod Autoscaling configuration. |
| GCP.GKE.Clusters.workloadIdentityConfig | Unknown | Configuration for the use of Kubernetes Service Accounts in IAM policies. |
| GCP.GKE.Clusters.zone | String | The name of the Google Compute Engine zone in which the cluster resides. |

### gcp-gke-node-pools-list

***
Lists the node pools for a GKE cluster. Required permissions: container.clusters.get.

#### Base Command

`gcp-gke-node-pools-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the cluster. | Required |
| cluster | The name of the GKE cluster. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.NodePools.autoscaling | Unknown | Autoscaler configuration for this NodePool. |
| GCP.GKE.NodePools.bestEffortProvisioning | Unknown | Enable best effort provisioning for nodes. |
| GCP.GKE.NodePools.conditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.NodePools.config | Unknown | The node configuration of the pool. |
| GCP.GKE.NodePools.etag | String | This checksum is computed by the server based on the value of node pool fields, and may be sent on update requests to ensure the client has an up-to-date value before proceeding. |
| GCP.GKE.NodePools.initialNodeCount | Number | The initial node count for the pool. |
| GCP.GKE.NodePools.instanceGroupUrls | Unknown | The resource URLs of the managed instance groups associated with this node pool. |
| GCP.GKE.NodePools.kubeletCertInfo | Unknown | Contains expiry information about the kubelet certificate. |
| GCP.GKE.NodePools.locations | Unknown | The list of Google Compute Engine zones in which the NodePool's nodes should be located. |
| GCP.GKE.NodePools.maintenancePolicy | Unknown | Specifies the maintenance policy for the node pool. |
| GCP.GKE.NodePools.management | Unknown | NodeManagement configuration for this NodePool. |
| GCP.GKE.NodePools.maxPodsConstraint | Unknown | The constraint on the maximum number of pods that can be run simultaneously on a node in the node pool. |
| GCP.GKE.NodePools.name | String | The name of the node pool. |
| GCP.GKE.NodePools.networkConfig | Unknown | Networking configuration for this NodePool. |
| GCP.GKE.NodePools.nodeDrainConfig | Unknown | Specifies the node drain configuration for this node pool. |
| GCP.GKE.NodePools.placementPolicy | Unknown | Specifies the node placement policy. |
| GCP.GKE.NodePools.podIpv4CidrSize | Number | The pod CIDR block size per node in this node pool. |
| GCP.GKE.NodePools.queuedProvisioning | Unknown | Specifies the configuration of queued provisioning. |
| GCP.GKE.NodePools.selfLink | String | Server-defined URL for the resource. |
| GCP.GKE.NodePools.status | String | The status of the nodes in this pool instance. |
| GCP.GKE.NodePools.statusMessage | String | Additional information about the current status of the node pool, if available. |
| GCP.GKE.NodePools.updateInfo | Unknown | Update info contains relevant information during a node pool update. |
| GCP.GKE.NodePools.upgradeSettings | Unknown | Upgrade settings control disruption and speed of the upgrade. |
| GCP.GKE.NodePools.version | String | The version of Kubernetes running on this NodePool's nodes. |
| GCP.GKE.NodePools.config.machineType | String | The machine type of the Compute Engine instances in the node pool. |
| GCP.GKE.NodePools.config.diskSizeGb | Number | The disk size \(in GB\) of the nodes in the node pool. |
| GCP.GKE.NodePools.autoscaling.enabled | Boolean | Whether autoscaling is enabled for the node pool. |
| GCP.GKE.NodePools.autoscaling.minNodeCount | Number | The minimum number of nodes when autoscaling is enabled. |
| GCP.GKE.NodePools.autoscaling.maxNodeCount | Number | The maximum number of nodes when autoscaling is enabled. |
| GCP.GKE.NodePools.management.autoRepair | Boolean | Whether node auto-repair is enabled for the node pool. |
| GCP.GKE.NodePools.management.autoUpgrade | Boolean | Whether node auto-upgrade is enabled for the node pool. |

### gcp-gke-node-pool-get

***
Gets the details of a specific node pool in a GKE cluster. Required permissions: container.clusters.get.

#### Base Command

`gcp-gke-node-pool-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the cluster. | Required |
| cluster | The name of the GKE cluster. | Required |
| node_pool | The name of the node pool. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.NodePools.autoscaling | Unknown | Autoscaler configuration for this NodePool. |
| GCP.GKE.NodePools.bestEffortProvisioning | Unknown | Enable best effort provisioning for nodes. |
| GCP.GKE.NodePools.conditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.NodePools.config | Unknown | The node configuration of the pool. |
| GCP.GKE.NodePools.etag | String | This checksum is computed by the server based on the value of node pool fields, and may be sent on update requests to ensure the client has an up-to-date value before proceeding. |
| GCP.GKE.NodePools.initialNodeCount | Number | The initial node count for the pool. |
| GCP.GKE.NodePools.instanceGroupUrls | Unknown | The resource URLs of the managed instance groups associated with this node pool. |
| GCP.GKE.NodePools.kubeletCertInfo | Unknown | Contains expiry information about the kubelet certificate. |
| GCP.GKE.NodePools.locations | Unknown | The list of Google Compute Engine zones in which the NodePool's nodes should be located. |
| GCP.GKE.NodePools.maintenancePolicy | Unknown | Specifies the maintenance policy for the node pool. |
| GCP.GKE.NodePools.management | Unknown | NodeManagement configuration for this NodePool. |
| GCP.GKE.NodePools.maxPodsConstraint | Unknown | The constraint on the maximum number of pods that can be run simultaneously on a node in the node pool. |
| GCP.GKE.NodePools.name | String | The name of the node pool. |
| GCP.GKE.NodePools.networkConfig | Unknown | Networking configuration for this NodePool. |
| GCP.GKE.NodePools.nodeDrainConfig | Unknown | Specifies the node drain configuration for this node pool. |
| GCP.GKE.NodePools.placementPolicy | Unknown | Specifies the node placement policy. |
| GCP.GKE.NodePools.podIpv4CidrSize | Number | The pod CIDR block size per node in this node pool. |
| GCP.GKE.NodePools.queuedProvisioning | Unknown | Specifies the configuration of queued provisioning. |
| GCP.GKE.NodePools.selfLink | String | Server-defined URL for the resource. |
| GCP.GKE.NodePools.status | String | The status of the nodes in this pool instance. |
| GCP.GKE.NodePools.statusMessage | String | Additional information about the current status of the node pool, if available. |
| GCP.GKE.NodePools.updateInfo | Unknown | Update info contains relevant information during a node pool update. |
| GCP.GKE.NodePools.upgradeSettings | Unknown | Upgrade settings control disruption and speed of the upgrade. |
| GCP.GKE.NodePools.version | String | The version of Kubernetes running on this NodePool's nodes. |
| GCP.GKE.NodePools.config.machineType | String | The machine type of the Compute Engine instances in the node pool. |
| GCP.GKE.NodePools.config.diskSizeGb | Number | The disk size \(in GB\) of the nodes in the node pool. |
| GCP.GKE.NodePools.autoscaling.enabled | Boolean | Whether autoscaling is enabled for the node pool. |
| GCP.GKE.NodePools.autoscaling.minNodeCount | Number | The minimum number of nodes when autoscaling is enabled. |
| GCP.GKE.NodePools.autoscaling.maxNodeCount | Number | The maximum number of nodes when autoscaling is enabled. |
| GCP.GKE.NodePools.management.autoRepair | Boolean | Whether node auto-repair is enabled for the node pool. |
| GCP.GKE.NodePools.management.autoUpgrade | Boolean | Whether node auto-upgrade is enabled for the node pool. |

### gcp-gke-node-pool-management-set

***
Enables or disables the auto-repair and/or auto-upgrade management features of a node pool. Required permissions: container.clusters.update.

#### Base Command

`gcp-gke-node-pool-management-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the cluster. | Required |
| cluster | The name of the GKE cluster. | Required |
| node_pool | The name of the node pool. | Required |
| auto_repair | Whether to enable node auto-repair for the node pool. Possible values are: true, false. | Optional |
| auto_upgrade | Whether to enable node auto-upgrade for the node pool. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Operations.clusterConditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Operations.detail | String | Detailed operation progress, if available. |
| GCP.GKE.Operations.endTime | String | The time the operation completed, in RFC3339 text format. |
| GCP.GKE.Operations.error | Unknown | The error result of the operation in case of failure. |
| GCP.GKE.Operations.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Operations.name | String | The server-assigned ID for the operation. |
| GCP.GKE.Operations.nodepoolConditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.Operations.operationType | String | The operation type. |
| GCP.GKE.Operations.progress | Unknown | Progress information for an operation. |
| GCP.GKE.Operations.selfLink | String | Server-defined URI for the operation. |
| GCP.GKE.Operations.startTime | String | The time the operation started, in RFC3339 text format. |
| GCP.GKE.Operations.status | String | The current status of the operation. |
| GCP.GKE.Operations.statusMessage | String | If an error has occurred, a textual description of the error. |
| GCP.GKE.Operations.targetLink | String | Server-defined URI for the target of the operation. |
| GCP.GKE.Operations.zone | String | The name of the Google Compute Engine zone in which the operation is taking place. |

### gcp-gke-operations-list

***
Lists all GKE operations in a project for the specified location. Required permissions: container.operations.list.

#### Base Command

`gcp-gke-operations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) to list operations from. Use "-" to list operations from all locations. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Operations.clusterConditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Operations.detail | String | Detailed operation progress, if available. |
| GCP.GKE.Operations.endTime | String | The time the operation completed, in RFC3339 text format. |
| GCP.GKE.Operations.error | Unknown | The error result of the operation in case of failure. |
| GCP.GKE.Operations.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Operations.name | String | The server-assigned ID for the operation. |
| GCP.GKE.Operations.nodepoolConditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.Operations.operationType | String | The operation type. |
| GCP.GKE.Operations.progress | Unknown | Progress information for an operation. |
| GCP.GKE.Operations.selfLink | String | Server-defined URI for the operation. |
| GCP.GKE.Operations.startTime | String | The time the operation started, in RFC3339 text format. |
| GCP.GKE.Operations.status | String | The current status of the operation. |
| GCP.GKE.Operations.statusMessage | String | If an error has occurred, a textual description of the error. |
| GCP.GKE.Operations.targetLink | String | Server-defined URI for the target of the operation. |
| GCP.GKE.Operations.zone | String | The name of the Google Compute Engine zone in which the operation is taking place. |

### gcp-gke-operation-get

***
Gets the details of a specific GKE operation. Required permissions: container.operations.get.

#### Base Command

`gcp-gke-operation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the operation. | Required |
| operation | The name of the operation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Operations.clusterConditions | Unknown | Which conditions caused the current cluster state. |
| GCP.GKE.Operations.detail | String | Detailed operation progress, if available. |
| GCP.GKE.Operations.endTime | String | The time the operation completed, in RFC3339 text format. |
| GCP.GKE.Operations.error | Unknown | The error result of the operation in case of failure. |
| GCP.GKE.Operations.location | String | The name of the Google Compute Engine zone or region in which the cluster resides. |
| GCP.GKE.Operations.name | String | The server-assigned ID for the operation. |
| GCP.GKE.Operations.nodepoolConditions | Unknown | Which conditions caused the current node pool state. |
| GCP.GKE.Operations.operationType | String | The operation type. |
| GCP.GKE.Operations.progress | Unknown | Progress information for an operation. |
| GCP.GKE.Operations.selfLink | String | Server-defined URI for the operation. |
| GCP.GKE.Operations.startTime | String | The time the operation started, in RFC3339 text format. |
| GCP.GKE.Operations.status | String | The current status of the operation. |
| GCP.GKE.Operations.statusMessage | String | If an error has occurred, a textual description of the error. |
| GCP.GKE.Operations.targetLink | String | Server-defined URI for the target of the operation. |
| GCP.GKE.Operations.zone | String | The name of the Google Compute Engine zone in which the operation is taking place. |

### gcp-gke-operation-cancel

***
Cancels a specific GKE operation. Required permissions: container.operations.get.

#### Base Command

`gcp-gke-operation-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP location (zone or region) of the operation. | Required |
| operation | The name of the operation. | Required |

#### Context Output

There is no context output for this command.

### gcp-storage-bucket-metadata-update

***
Updates Google Cloud Storage (GCS) bucket metadata, including settings such as versioning and Uniform Bucket-Level Access (UBLA). Required permission: storage.buckets.update.

#### Base Command

`gcp-storage-bucket-metadata-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | Name of the bucket. | Required |
| enable_versioning | Enable versioning. Possible values are: true, false. | Optional |
| enable_uniform_access | Enable uniform bucket-level access. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.name | String | The name of the GCP bucket. |
| GCP.Storage.Buckets.id | String | The ID of the GCP bucket. |
| GCP.Storage.Buckets.location | String | The location of the bucket. |
| GCP.Storage.Buckets.storageClass | String | The storage class of the bucket \(e.g., STANDARD, NEARLINE\). |
| GCP.Storage.Buckets.created | Date | The creation timestamp of the bucket \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Storage.Buckets.updated | Date | The last update timestamp of the bucket. |
| GCP.Storage.Buckets.metageneration | Number | The metadata generation of the bucket. |
| GCP.Storage.Buckets.labels | Unknown | The labels attached to the bucket. |
| GCP.Storage.Buckets.defaultEventBasedHold | Boolean | Whether a default event-based hold is enabled on the bucket. |
| GCP.Storage.Buckets.retentionPolicy.retentionPeriod | Number | The duration in seconds that objects in the bucket must be retained. |
| GCP.Storage.Buckets.retentionPolicy.effectiveTime | Date | The time from which the retention policy is effective. |
| GCP.Storage.Buckets.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.Storage.Buckets.versioning.enabled | Boolean | Whether object versioning is enabled. |
| GCP.Storage.Buckets.logging.logBucket | String | The destination bucket where access logs are stored. |
| GCP.Storage.Buckets.logging.logObjectPrefix | String | The object prefix used for logging. |
| GCP.Storage.Buckets.lifecycle.rule | Unknown | A list of lifecycle management rules for the bucket. |
| GCP.Storage.Buckets.iamConfiguration.uniformBucketLevelAccess | Boolean | Whether uniform bucket-level access is enabled. |
| GCP.Storage.Buckets.cors | Unknown | CORS configuration for the bucket. |
| GCP.Storage.Buckets.customPlacementConfig | Unknown | Custom placement configuration for multi-region buckets. |
| GCP.Storage.Buckets.encryption.defaultKmsKeyName | String | The default Cloud KMS key used to encrypt objects. |
| GCP.Storage.Buckets.billing.requesterPays | Boolean | Whether requester pays is enabled. |
| GCP.Storage.Buckets.website.mainPageSuffix | String | Suffix appended to requests for the bucket's website configuration. |
| GCP.Storage.Buckets.website.notFoundPage | String | The path to the custom 404 page for the bucket website. |

### gcp-iam-project-policy-binding-remove

***
Removes a specified IAM role binding from a GCP project. Required permissions: resourcemanager.projects.getIamPolicy, resourcemanager.projects.setIamPolicy.

#### Base Command

`gcp-iam-project-policy-binding-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| member | Member to remove (e.g., user:test@example.com). | Required |
| role | Role to remove (e.g., roles/viewer). | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-instance-service-account-set

***
Sets the service account for a GCP Compute Engine VM instance. The instance must be stopped before the service account can be changed. Required permissions: compute.instances.setServiceAccount, compute.instances.get.

#### Base Command

`gcp-compute-instance-service-account-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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

### gcp-storage-bucket-list

***
Retrieves the list of buckets in the project associated with the client. The command is deprecated, please use gcp-storage-buckets-list. Required permission: storage.buckets.list.

#### Base Command

`gcp-storage-bucket-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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

### gcp-storage-bucket-get

***
Retrieves information about a specific bucket. Required permission: storage.buckets.get.

#### Base Command

`gcp-storage-bucket-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.id | String | The unique identifier for the bucket. |
| GCP.Storage.Buckets.name | String | The name of the bucket. |
| GCP.Storage.Buckets.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Buckets.location | String | The location of the bucket. |
| GCP.Storage.Buckets.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Buckets.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Buckets.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Buckets.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Buckets.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Buckets.generation | String | The generation number of the bucket. |
| GCP.Storage.Buckets.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Buckets.timeCreated | Date | The time the bucket was created \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Storage.Buckets.timeUpdated | Date | The time the bucket was last updated. |
| GCP.Storage.Buckets.selfLink | String | The link to the bucket resource on the GCP API. |

### gcp-storage-bucket-objects-list

***
Retrieves the list of objects in a bucket. Required permission: storage.objects.list.

#### Base Command

`gcp-storage-bucket-objects-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to list objects from. | Required |
| prefix | Filter results to objects whose names begin with this prefix. | Optional |
| delimiter | Delimiter to use for grouping objects. For example delimiter="/" Returns results in a directory-like mode, with / being a common value for the delimiter. | Optional |
| limit | Maximum number of objects to return. | Optional |
| page_token | The token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.Objects.id | String | The unique identifier for the object. |
| GCP.Storage.Buckets.Objects.name | String | The name of the object. |
| GCP.Storage.Buckets.Objects.kind | String | The type of resource \(for example, storage\#object\). |
| GCP.Storage.Buckets.Objects.bucket | String | The name of the bucket containing the object. |
| GCP.Storage.Buckets.Objects.contentType | String | The MIME type of the object. |
| GCP.Storage.Buckets.Objects.size | Number | The size of the object in bytes. |
| GCP.Storage.Buckets.Objects.crc32c | String | The CRC32C checksum of the object. |
| GCP.Storage.Buckets.Objects.md5Hash | String | The MD5 hash of the object. |
| GCP.Storage.Buckets.Objects.etag | String | The HTTP entity tag of the object. |
| GCP.Storage.Buckets.Objects.generation | String | The generation number of the object. |
| GCP.Storage.Buckets.Objects.metageneration | String | The metageneration number of the object. |
| GCP.Storage.Buckets.Objects.storageClass | String | The storage class of the object. |
| GCP.Storage.Buckets.Objects.mediaLink | String | The link for downloading the object content. |
| GCP.Storage.Buckets.Objects.selfLink | String | The link to the object resource in the GCP API. |
| GCP.Storage.Buckets.Objects.timeCreated | Date | The time when the object was created. |
| GCP.Storage.Buckets.Objects.timeFinalized | Date | The time when the object was finalized. |
| GCP.Storage.Buckets.Objects.timeStorageClassUpdated | Date | The time when the object's storage class was last updated. |
| GCP.Storage.Buckets.Objects.updated | Date | The time when the object was last modified. |
| GCP.Storage.Buckets.ObjectsNextToken | String | The continuation token. Provide this value as the page_token of a subsequent request in order to return the next page of results. |
| GCP.Storage.Buckets.name | String | The name of the bucket containing the object. |

### gcp-storage-bucket-policy-list

***
Retrieves the IAM policy for a bucket. The command is deprecated, please use gcp-storage-bucket-policies-list. Required permissions: storage.buckets.getIamPolicy, storage.buckets.get.

#### Base Command

`gcp-storage-bucket-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to retrieve IAM policy from. | Required |
| requested_policy_version | The IAM policy version to be returned. If the optionsRequestedPolicyVersion is for an older version that doesn't support part of the requested IAM policy, the request fails. Required to be 3 or greater for buckets with IAM Conditions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketPolicy.version | Number | IAM policy version. |
| GCP.Storage.BucketPolicy.etag | String | ETag of the IAM policy. |
| GCP.Storage.BucketPolicy.bindings | List | List of role bindings for the bucket. |
| GCP.Storage.BucketPolicy.resourceId | String | Resource ID of the updated IAM policy. e.g. projects/_/buckets/BUCKET_NAME. |

#### Usage

- **add=false**: Replaces the entire bucket IAM policy with the JSON provided in `policy`.
- **add=true**: Reads the current bucket policy (getIamPolicy), merges the provided `bindings` per role (deduplicates members), and updates the bucket policy (setIamPolicy) while preserving other top-level fields.

### gcp-storage-bucket-policy-set

***
Sets the IAM policy for a bucket. Required permission: storage.buckets.setIamPolicy.

#### Base Command

`gcp-storage-bucket-policy-set`

#### Usage

- **add=false**: Replaces the entire bucket IAM policy with the JSON provided in `policy`.
- **add=true**: Reads the current bucket policy (getIamPolicy), merges the provided `bindings` per role (deduplicates members), and updates the bucket policy (setIamPolicy) while preserving other top-level fields.

> Warning: Use this command with extreme caution. Running it without explicitly merging (i.e., with `add=false`) will overwrite the bucket's existing IAM policy with the provided `policy`. If you intend to keep current bindings and add new ones, use `add=true`.

#### Policy structure

- **bindings**: Array of binding objects. Each binding:
  - **role**: String. For example, `roles/storage.objectViewer`, `roles/storage.admin`.
  - **members**: Array of strings. Allowed formats:
    - `user:<email>` (e.g., `user:alice@example.com`)
    - `group:<email>`
    - `serviceAccount:<email>`
    - `domain:<domain>` (e.g., `domain:example.com`)
    - `allUsers` | `allAuthenticatedUsers`
- **version**: Number. Required to be `3` or greater if any binding includes `condition`.
- **etag**: String. Recommended for replace flow (`add=false`) to avoid overwriting concurrent updates.
- Optional fields like `kind`, `resourceId` may appear in responses but are not required in requests.

Notes:

- For `add=true` (merge), only a valid `bindings` array is required; other top-level fields are taken from the existing policy.
- For `add=false` (replace), the provided object becomes the entire policy on the bucket.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket to set IAM policy on. | Required |
| policy | JSON string representing the IAM policy to set. | Required |
| add | When true, merges the provided policy bindings into the current bucket policy (per role, deduplicating members) by first calling getIamPolicy and then setIamPolicy with the merged result. When false, replaces the entire policy with the provided JSON via setIamPolicy.<br/>. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketPolicies.version | Number | IAM policy version after update. |
| GCP.Storage.BucketPolicies.etag | String | ETag of the updated IAM policy. |
| GCP.Storage.BucketPolicies.bindings | Unknown | List of role bindings for the bucket. |

### gcp-storage-bucket-object-policy-list

***
Retrieves the IAM policy for a specific object in a bucket. The command is deprecated, please use gcp-storage-bucket-object-policies-list. Required permission: storage.objects.getIamPolicy.

#### Base Command

`gcp-storage-bucket-object-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | Name of the bucket containing the object. | Required |
| object_name | Name of the object to set IAM policy on. | Required |
| policy | JSON string representing the IAM policy to set. | Required |
| generation | The generation of the object (e.g., a positive integer). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObjectPolicies.version | Number | IAM policy version after update. |
| GCP.Storage.BucketObjectPolicies.etag | String | ETag of the updated IAM policy. |
| GCP.Storage.BucketObjectPolicies.bindings | Unknown | List of role bindings for the object. |

### gcp-compute-snapshot-get

***
Retrieves details for a specific snapshot. Required permission: compute.snapshots.get.

#### Base Command

`gcp-compute-snapshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | Snapshot name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Snapshots.id | String | Unique identifier for the snapshot resource. |
| GCP.Compute.Snapshots.name | String | Name of the snapshot resource. |
| GCP.Compute.Snapshots.kind | String | Type of the resource, for example compute\#snapshot. |
| GCP.Compute.Snapshots.status | String | Current status of the snapshot, such as READY or FAILED. |
| GCP.Compute.Snapshots.autoCreated | Boolean | Indicates whether the snapshot was automatically created. |
| GCP.Compute.Snapshots.architecture | String | CPU architecture of the source disk, for example X86_64. |
| GCP.Compute.Snapshots.creationTimestamp | Date | The time when the snapshot was created. |
| GCP.Compute.Snapshots.creationSizeBytes | Number | Total size of the snapshot in bytes at creation time. |
| GCP.Compute.Snapshots.diskSizeGb | Number | Size of the snapshot in gigabytes. |
| GCP.Compute.Snapshots.downloadBytes | Number | Total bytes downloaded to create the snapshot. |
| GCP.Compute.Snapshots.enableConfidentialCompute | Boolean | Indicates if confidential compute is enabled for this snapshot. |
| GCP.Compute.Snapshots.labelFingerprint | String | Fingerprint for the labels applied to the snapshot. |
| GCP.Compute.Snapshots.licenseCodes | Unknown | List of license code identifiers attached to the snapshot. |
| GCP.Compute.Snapshots.licenses | Unknown | List of license URLs associated with the snapshot. |
| GCP.Compute.Snapshots.selfLink | String | Server-defined URL for the snapshot resource. |
| GCP.Compute.Snapshots.sourceDisk | String | URL of the source disk used to create the snapshot. |
| GCP.Compute.Snapshots.sourceDiskId | String | Unique ID of the source disk used to create the snapshot. |
| GCP.Compute.Snapshots.sourceSnapshotSchedulePolicy | String | URL of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshots.sourceSnapshotSchedulePolicyId | String | Unique ID of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshots.storageBytes | Number | Total storage size of the snapshot in bytes. |
| GCP.Compute.Snapshots.storageBytesStatus | String | Status of the storage bytes usage, for example UP_TO_DATE. |
| GCP.Compute.Snapshots.storageLocations | Unknown | List of storage locations for the snapshot. |

### gcp-compute-snapshot-delete

***
Deletes the specified snapshot. Deleting a single snapshot might not delete all data on that snapshot. If any data on the snapshot marked for deletion is needed for subsequent snapshots, the data is moved to the next corresponding snapshot. Required permission: compute.snapshots.delete.

#### Base Command

`gcp-compute-snapshot-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | The name of the snapshot to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The current status of the operation. |
| GCP.Compute.Operations.progress | Number | The progress of the operation as a percentage between 0 and 100. |
| GCP.Compute.Operations.targetId | String | The unique target ID of the resource affected by the operation. |
| GCP.Compute.Operations.targetLink | String | The URL of the target resource modified by the operation. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The date and time when the operation resource was created. |
| GCP.Compute.Operations.startTime | Date | The date and time when the operation started running. |
| GCP.Compute.Operations.user | String | The user account that performed the operation. |

### gcp-compute-snapshot-labels-set

***
Sets the labels on a snapshot. Required permissions: compute.snapshots.setLabels, compute.snapshots.get.

#### Base Command

`gcp-compute-snapshot-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | The name of the snapshot for this request. | Required |
| labels | The labels to apply for this resource. Each label key and value must comply with RFC1035. Example: key=abc,value=123;key=def,value=456. | Required |
| label_fingerprint | The fingerprint of the previous set of labels for this resource, used to detect conflicts. Run gcp-compute-snapshot-get to retrieve the latest fingerprint. Ignored when add_labels is true, since the fingerprint of the fetched snapshot is used instead. When add_labels is false, a label_fingerprint must be provided. | Optional |
| add_labels | Whether to add the new labels to the existing ones or override the previous labels with the new ones. True - add, False - override. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The current status of the operation. |
| GCP.Compute.Operations.progress | Number | The progress of the operation as a percentage between 0 and 100. |
| GCP.Compute.Operations.targetId | String | The unique target ID of the resource affected by the operation. |
| GCP.Compute.Operations.targetLink | String | The URL of the target resource modified by the operation. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The date and time when the operation resource was created. |
| GCP.Compute.Operations.startTime | Date | The date and time when the operation started running. |
| GCP.Compute.Operations.user | String | The user account that performed the operation. |

### gcp-compute-instances-aggregated-list-by-ip

***
Returns an aggregated list of instances across all zones that can be filtered by internal or external IP. Required permission: cloudasset.assets.searchAllResources.

#### Base Command

`gcp-compute-instances-aggregated-list-by-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| ip_address | The IP address to search for. | Required |
| match_external | If true, match against external NAT IPs; otherwise internal NIC IPs. Possible values are: true, false. | Optional |
| limit | The maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
| page_token | The token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Instances.name | string | Instance name. |
| GCP.Compute.Instances.id | string | Instance ID. |
| GCP.Compute.Instances.zone | string | Instance zone URL. |
| GCP.Compute.Instances.status | string | Instance status. |
| GCP.Compute.Instances.networkInterfaces | Unknown | Network interfaces of the instance. |
| GCP.Compute.AggregatedByIPInstancesNextToken | string | This token allows you to get the next page of results for list requests. If the number of results is larger than limit, use the next_token as a value for the query parameter page_token in the next list request. |

### gcp-compute-network-tag-set

***
Adds a network tag to a VM instance (merges with existing tags). Required permission: compute.instances.setTags.

#### Base Command

`gcp-compute-network-tag-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The project ID for this request. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |

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

### gcp-compute-regions-list

***
Retrieves the list of region resources available to the specified project. Required permission: compute.regions.list.

#### Base Command

`gcp-compute-regions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results per page to return, ranging from 1 to 500. If the number of available results is larger than the limit, a token is returned in the nextPageToken field to retrieve the next page of results in subsequent list requests. Default is 50. | Optional |
| filter | The filter expression to use for filtering resources listed in the response. Must specify the field name, a comparison operator, and the filtering value. The value can be a string, a number, or a boolean. The comparison operator must be "=", "!=", "&gt;", or "&lt;". For example, to exclude a region named "example-region", specify name != example-region. | Optional |
| order_by | The order in which to sort the list results. Can be "alphanumerical" (default, based on the resource name) or "creationTimestamp desc" (reverse chronological order, latest result first). | Optional |
| next_token | The page token to use. Set next_token to the nextPageToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Regions.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Regions.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56.000-07:00\). |
| GCP.Compute.Regions.name | string | The name of the resource. |
| GCP.Compute.Regions.description | string | The textual description of the resource. |
| GCP.Compute.Regions.status | string | The status of the region, either UP or DOWN. |
| GCP.Compute.Regions.zones | string | The list of zones available in this region, in the form of resource URLs. |
| GCP.Compute.Regions.quotas | string | The quotas assigned to this region. |
| GCP.Compute.Regions.quotas.metric | string | The name of the quota metric. |
| GCP.Compute.Regions.quotas.limit | number | The quota limit for this metric. |
| GCP.Compute.Regions.quotas.usage | number | The current usage of this metric. |
| GCP.Compute.Regions.quotas.owner | string | The resource to which this quota applies. |
| GCP.Compute.Regions.deprecated | string | The deprecation status associated with this region. |
| GCP.Compute.Regions.deprecated.state | string | The deprecation state of this resource. Can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Regions.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The replacement resource must be the same type of resource as the deprecated resource. |
| GCP.Compute.Regions.deprecated.deprecated | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.obsolete | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.deprecated.deleted | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Regions.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Regions.supportsPzs | boolean | Whether the region supports physical zone separation. Reserved for future use. |
| GCP.Compute.Regions.quotaStatusWarning | string | The warning raised while fetching the quotas field for this region. This field is populated only if fetching of the quotas field fails. |
| GCP.Compute.Regions.quotaStatusWarning.code | string | The warning code, if applicable. For example, Compute Engine returns NO_RESULTS_ON_PAGE if there are no results in the response. |
| GCP.Compute.Regions.quotaStatusWarning.message | string | The human-readable description of the warning code. |
| GCP.Compute.Regions.quotaStatusWarning.data | string | The metadata about this warning, in key-value format. |
| GCP.Compute.Regions.kind | string | The type of the resource. Always compute\#region for regions. |
| GCP.Compute.RegionsNextToken | string | The next page token to use for retrieving the next page of regions. |

#### Command example

```!gcp-compute-regions-list project_id=project-id limit=2```

#### Context Example

```json
{
    "GCP": {
        "Compute": {
            "Regions": [
                {
                    "creationTimestamp": "1969-12-31T16:00:00.000-08:00",
                    "id": "1220",
                    "kind": "compute#region",
                    "name": "us-central1",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project-id/regions/us-central1",
                    "status": "UP",
                    "zones": [
                        "https://www.googleapis.com/compute/v1/projects/project-id/zones/us-central1-a",
                        "https://www.googleapis.com/compute/v1/projects/project-id/zones/us-central1-b"
                    ]
                },
                {
                    "creationTimestamp": "1969-12-31T16:00:00.000-08:00",
                    "id": "1230",
                    "kind": "compute#region",
                    "name": "us-east1",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project-id/regions/us-east1",
                    "status": "UP",
                    "zones": [
                        "https://www.googleapis.com/compute/v1/projects/project-id/zones/us-east1-b"
                    ]
                }
            ],
            "RegionsNextToken": "CAIQAA=="
        }
    }
}
```

#### Human Readable Output

>### GCP Compute Regions
>
>|Id|Name|Status|Creation Timestamp|
>|---|---|---|---|
>| 1220 | us-central1 | UP | 1969-12-31T16:00:00.000-08:00 |
>| 1230 | us-east1 | UP | 1969-12-31T16:00:00.000-08:00 |

### gcp-compute-zone-get

***
Returns a specific zone resource. Required permission: compute.zones.get.

#### Base Command

`gcp-compute-zone-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zone | Name of the zone resource to return. | Required |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |

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

### gcp-compute-zones-list

***
Retrieves the list of zone resources available to the specified project. Required permission: compute.zones.list.

#### Base Command

`gcp-compute-zones-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results per page to return, ranging from 1 to 500. If the number of available results is larger than the limit, a token is returned in the nextPageToken field to retrieve the next page of results in subsequent list requests. Default is 50. | Optional |
| filter | The filter expression to use for filtering resources listed in the response. Must specify the field name, a comparison operator, and the filtering value. The value can be a string, a number, or a boolean. The comparison operator must be "=", "!=", "&gt;", or "&lt;". For example, to exclude a zone named "example-zone", specify name != example-zone. | Optional |
| order_by | The order in which to sort the list results. Can be "alphanumerical" (default, based on the resource name) or "creationTimestamp desc" (reverse chronological order, latest result first). | Optional |
| next_token | The page token to use. Set next_token to the nextPageToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Zones.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.Zones.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56.000-07:00\). |
| GCP.Compute.Zones.name | string | The name of the resource. |
| GCP.Compute.Zones.description | string | The textual description of the resource. |
| GCP.Compute.Zones.status | string | The status of the zone, either UP or DOWN. |
| GCP.Compute.Zones.deprecated | string | The deprecation status associated with this zone. |
| GCP.Compute.Zones.deprecated.state | string | The deprecation state of this resource. Can be ACTIVE DEPRECATED, OBSOLETE, or DELETED. Operations which communicate the end of life date for an image can use ACTIVE. Operations which create a new resource using a DEPRECATED resource will return successfully, but with a warning indicating the deprecated resource and recommending its replacement. Operations which use OBSOLETE or DELETED resources will be rejected and result in an error. |
| GCP.Compute.Zones.deprecated.replacement | string | The URL of the suggested replacement for a deprecated resource. The replacement resource must be the same type of resource as the deprecated resource. |
| GCP.Compute.Zones.deprecated.deprecated | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to DEPRECATED \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.deprecated.obsolete | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to OBSOLETE \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.deprecated.deleted | string | The optional RFC3339 timestamp on or after which the state of this resource is intended to change to DELETED \(for example, 2024-01-15T12:34:56.000-07:00\). This is only informational and the status will not change unless the client explicitly changes it. |
| GCP.Compute.Zones.region | string | The full URL reference to the region which hosts the zone. |
| GCP.Compute.Zones.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Zones.availableCpuPlatforms | string | The available CPU platform selections for the zone. |
| GCP.Compute.Zones.supportsPzs | boolean | Whether the zone supports physical zone separation. Reserved for future use. |
| GCP.Compute.Zones.resourceStatus | Unknown | The additional status details of the zone. |
| GCP.Compute.Zones.resourceStatus.upcomingMaintenances | Unknown | The list of upcoming maintenances scheduled for this zone. |
| GCP.Compute.Zones.kind | string | The type of the resource. Always compute\#zone for zones. |
| GCP.Compute.ZonesNextToken | string | The next page token to use for retrieving the next page of zones. |

#### Command example

```!gcp-compute-zones-list project_id=project-id limit=2```

#### Context Example

```json
{
    "GCP": {
        "Compute": {
            "Zones": [
                {
                    "availableCpuPlatforms": [
                        "Intel Broadwell",
                        "Intel Cascade Lake"
                    ],
                    "creationTimestamp": "1969-12-31T16:00:00.000-08:00",
                    "id": "2231",
                    "kind": "compute#zone",
                    "name": "us-central1-a",
                    "region": "https://www.googleapis.com/compute/v1/projects/project-id/regions/us-central1",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project-id/zones/us-central1-a",
                    "status": "UP"
                },
                {
                    "availableCpuPlatforms": [
                        "Intel Broadwell"
                    ],
                    "creationTimestamp": "1969-12-31T16:00:00.000-08:00",
                    "id": "2232",
                    "kind": "compute#zone",
                    "name": "us-central1-b",
                    "region": "https://www.googleapis.com/compute/v1/projects/project-id/regions/us-central1",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project-id/zones/us-central1-b",
                    "status": "UP"
                }
            ],
            "ZonesNextToken": "CAIQAA=="
        }
    }
}
```

#### Human Readable Output

>### GCP Compute Zones
>
>|Id|Name|Status|Region|Creation Timestamp|
>|---|---|---|---|---|
>| 2231 | us-central1-a | UP | https://www.googleapis.com/compute/v1/projects/project-id/regions/us-central1 | 1969-12-31T16:00:00.000-08:00 |
>| 2232 | us-central1-b | UP | https://www.googleapis.com/compute/v1/projects/project-id/regions/us-central1 | 1969-12-31T16:00:00.000-08:00 |

### gcp-compute-zone-operation-wait

***
Polls a zonal Compute Engine operation until it reaches the DONE status. Required permission: compute.zoneOperations.get.

#### Base Command

`gcp-compute-zone-operation-wait`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| operation_name | The name of the Operation resource to wait for. | Required |
| interval_in_seconds | The interval, in seconds, between polling attempts. Must be a positive number. Default is 30. | Optional |
| polling_timeout | The timeout, in seconds, until polling ends. Must be a positive number. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId field provided when the operation was created. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error.errors | unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | string | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | string | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | unknown | The metadata about this warning, in key: value format. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP status code returned if the operation fails. For example, 404 indicates that the resource is not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | string | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-region-operation-wait

***
Polls a regional Compute Engine operation until it reaches the DONE status. Required permission: compute.regionOperations.get.

#### Base Command

`gcp-compute-region-operation-wait`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| operation_name | The name of the Operation resource to wait for. | Required |
| interval_in_seconds | The interval, in seconds, between polling attempts. Must be a positive number. Default is 30. | Optional |
| polling_timeout | The timeout, in seconds, until polling ends. Must be a positive number. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId field provided when the operation was created. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error.errors | unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | string | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | string | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | unknown | The metadata about this warning, in key: value format. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP status code returned if the operation fails. For example, 404 indicates that the resource is not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | string | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-global-operation-wait

***
Polls a global Compute Engine operation until it reaches the DONE status. Required permission: compute.globalOperations.get.

#### Base Command

`gcp-compute-global-operation-wait`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| operation_name | The name of the Operation resource to wait for. | Required |
| interval_in_seconds | The interval, in seconds, between polling attempts. Must be a positive number. Default is 30. | Optional |
| polling_timeout | The timeout, in seconds, until polling ends. Must be a positive number. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId field provided when the operation was created. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error.errors | unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | string | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | string | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | unknown | The metadata about this warning, in key: value format. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP status code returned if the operation fails. For example, 404 indicates that the resource is not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | string | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-networks-list

***
Retrieves a list of networks available for the specified project. Required permission: compute.networks.list.

#### Base Command

`gcp-compute-networks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
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
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |

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

### gcp-compute-firewall-insert

***
Creates a new firewall rule in a specific project. Required permission: compute.firewalls.create.

#### Base Command

`gcp-compute-firewall-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | Name of the firewall rule to create. | Required |
| description | An optional description for the firewall rule. | Optional |
| network | URL of the network, e.g., global/networks/default. | Optional |
| priority | Priority 0-65535. Default 1000. | Optional |
| direction | Direction of traffic to which this firewall applies. Default INGRESS. Possible values are: INGRESS, EGRESS. Default is INGRESS. | Optional |
| allowed | ALLOW rules in tuples, e.g., ipprotocol=tcp,ports=443;ipprotocol=tcp,ports=80. | Optional |
| denied | DENY rules in tuples, e.g., ipprotocol=tcp,ports=22,443. | Optional |
| source_ranges | Comma-separated CIDRs for INGRESS. | Optional |
| destination_ranges | Comma-separated CIDRs for EGRESS. | Optional |
| source_tags | Comma-separated instance tags to match as source. | Optional |
| target_tags | Comma-separated tags to apply this rule to. | Optional |
| source_service_accounts | Comma-separated service accounts for source. | Optional |
| target_service_accounts | Comma-separated service accounts to target. | Optional |
| log_config_enable | Enable firewall logging. Possible values are: true, false. | Optional |
| disabled | Whether this firewall rule is disabled. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | Unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | Name of the operation resource. |
| GCP.Compute.Operations.kind | String | Type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | Type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | Current status of the operation. |
| GCP.Compute.Operations.progress | Number | Progress of the operation as a percentage between 0 and 100. |
| GCP.Compute.Operations.targetId | String | Unique target ID of the resource affected by the operation. |
| GCP.Compute.Operations.targetLink | String | URL of the target resource modified by the operation. |
| GCP.Compute.Operations.selfLink | String | Server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time when the operation resource was created. |
| GCP.Compute.Operations.startTime | Date | The time when the operation started running. |
| GCP.Compute.Operations.user | String | The user account that performed the operation. |

### gcp-compute-firewall-list

***
Lists the firewall rules in a specific project. The command is deprecated, please use gcp-compute-firewalls-list. Required permission: compute.firewalls.list.

#### Base Command

`gcp-compute-firewall-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | Maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
| page_token | Token for pagination. | Optional |
| filter | A filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance.<br/>For more options and details, see:<br/>https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list#:~:text=page%20of%20results.-,filter,-string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Firewall.id | String | Unique identifier for the firewall rule. |
| GCP.Compute.Firewall.name | String | Name of the firewall rule. |
| GCP.Compute.Firewall.kind | String | Type of the resource \(for example, compute\#firewall\). |
| GCP.Compute.Firewall.description | String | Description of the firewall rule. |
| GCP.Compute.Firewall.direction | String | Direction of traffic for the rule \(INGRESS or EGRESS\). |
| GCP.Compute.Firewall.disabled | Boolean | Indicates whether the firewall rule is disabled. |
| GCP.Compute.Firewall.priority | Number | Priority value of the firewall rule. |
| GCP.Compute.Firewall.network | String | The network URL this firewall rule applies to. |
| GCP.Compute.Firewall.selfLink | String | Server-defined URL for the resource. |
| GCP.Compute.Firewall.creationTimestamp | Date | The creation timestamp of the firewall rule. |
| GCP.Compute.Firewall.logConfig.enable | Boolean | Indicates whether logging is enabled for the firewall rule. |
| GCP.Compute.Firewall.sourceRanges | Unknown | List of source IP ranges that the rule applies to. |
| GCP.Compute.Firewall.targetTags | Unknown | List of target instance tags to which the rule applies. |
| GCP.Compute.FirewallNextToken | String | Next page token for pagination. |

### gcp-compute-firewall-get

***
Retrieves a specific firewall rule by name. Required permission: compute.firewalls.get.

#### Base Command

`gcp-compute-firewall-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | Firewall rule name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Firewalls.name | string | Firewall rule name. |
| GCP.Compute.Firewalls.network | string | Network URL for the firewall rule. |
| GCP.Compute.Firewalls.direction | string | Direction of traffic \(INGRESS/EGRESS\). |
| GCP.Compute.Firewalls.priority | number | Priority of the rule. |
| GCP.Compute.Firewalls.allowed | Unknown | Allowed tuples. |
| GCP.Compute.Firewalls.denied | Unknown | Denied tuples. |
| GCP.Compute.Firewalls.targetTags | Unknown | Target instance tags. |

### gcp-compute-firewall-delete

***
Deletes the specified firewall rule. Required permission: compute.firewalls.delete.

#### Base Command

`gcp-compute-firewall-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| resource_name | The name of the firewall rule to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The current status of the operation. |
| GCP.Compute.Operations.progress | Number | The progress of the operation as a percentage between 0 and 100. |
| GCP.Compute.Operations.targetId | String | The unique target ID of the resource affected by the operation. |
| GCP.Compute.Operations.targetLink | String | The URL of the target resource modified by the operation. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The date and time when the operation resource was created. |
| GCP.Compute.Operations.startTime | Date | The date and time when the operation started running. |
| GCP.Compute.Operations.user | String | The user account that performed the operation. |

### gcp-compute-snapshots-list

***
Lists snapshots in a specific project. Required permission: compute.snapshots.list.

#### Base Command

`gcp-compute-snapshots-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
| page_token | The token for pagination. | Optional |
| filter | A filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance.<br/>For more options and details, see:<br/>https://cloud.google.com/compute/docs/reference/rest/v1/snapshots/list#:~:text=page%20of%20results.-,filter,-string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Snapshots.id | String | Unique identifier for the snapshot resource. |
| GCP.Compute.Snapshots.name | String | Name of the snapshot resource. |
| GCP.Compute.Snapshots.kind | String | Type of the resource, for example compute\#snapshot. |
| GCP.Compute.Snapshots.status | String | Current status of the snapshot, such as READY or FAILED. |
| GCP.Compute.Snapshots.autoCreated | Boolean | Indicates whether the snapshot was automatically created. |
| GCP.Compute.Snapshots.architecture | String | CPU architecture of the source disk, for example X86_64. |
| GCP.Compute.Snapshots.creationTimestamp | Date | The time when the snapshot was created. |
| GCP.Compute.Snapshots.creationSizeBytes | Number | Total size of the snapshot in bytes at creation time. |
| GCP.Compute.Snapshots.diskSizeGb | Number | Size of the snapshot in gigabytes. |
| GCP.Compute.Snapshots.downloadBytes | Number | Total bytes downloaded to create the snapshot. |
| GCP.Compute.Snapshots.enableConfidentialCompute | Boolean | Indicates if confidential compute is enabled for this snapshot. |
| GCP.Compute.Snapshots.labelFingerprint | String | Fingerprint for the labels applied to the snapshot. |
| GCP.Compute.Snapshots.licenseCodes | Unknown | List of license code identifiers attached to the snapshot. |
| GCP.Compute.Snapshots.licenses | Unknown | List of license URLs associated with the snapshot. |
| GCP.Compute.Snapshots.selfLink | String | Server-defined URL for the snapshot resource. |
| GCP.Compute.Snapshots.sourceDisk | String | URL of the source disk used to create the snapshot. |
| GCP.Compute.Snapshots.sourceDiskId | String | Unique ID of the source disk used to create the snapshot. |
| GCP.Compute.Snapshots.sourceSnapshotSchedulePolicy | String | URL of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshots.sourceSnapshotSchedulePolicyId | String | Unique ID of the snapshot schedule policy used to create this snapshot. |
| GCP.Compute.Snapshots.storageBytes | Number | Total storage size of the snapshot in bytes. |
| GCP.Compute.Snapshots.storageBytesStatus | String | Status of the storage bytes usage, for example UP_TO_DATE. |
| GCP.Compute.Snapshots.storageLocations | Unknown | List of storage locations for the snapshot. |
| GCP.Compute.SnapshotsNextToken | String | Next page token for pagination. |

### gcp-bq-dataset-policy-remove

***
Removes an email from the BigQuery dataset policy. Required Permissions: bigquery.datasets.update, bigquery.datasets.get, bigquery.datasets.getIamPolicy, bigquery.datasets.setIamPolicy.

#### Base Command

`gcp-bq-dataset-policy-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| dataset_id | The dataset ID of the requested dataset. | Required |
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

### gcp-compute-firewalls-list

***
Lists the firewall rules in a specific project. Required permission: compute.firewalls.list.

#### Base Command

`gcp-compute-firewalls-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return. Acceptable values are 0 to 500, inclusive. Default is 50. | Optional |
| page_token | The token for pagination. | Optional |
| filter | A filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance.<br/>For more options and details, see:<br/>https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list#:~:text=page%20of%20results.-,filter,-string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Firewalls.id | String | The unique identifier for the firewall rule. |
| GCP.Compute.Firewalls.name | String | Name of the firewall rule. |
| GCP.Compute.Firewalls.kind | String | Type of the resource \(for example, compute\#firewall\). |
| GCP.Compute.Firewalls.description | String | Description of the firewall rule. |
| GCP.Compute.Firewalls.direction | String | Direction of traffic for the rule \(INGRESS or EGRESS\). |
| GCP.Compute.Firewalls.disabled | Boolean | Indicates whether the firewall rule is disabled. |
| GCP.Compute.Firewalls.priority | Number | Priority value of the firewall rule. |
| GCP.Compute.Firewalls.network | String | The network URL this firewall rule applies to. |
| GCP.Compute.Firewalls.selfLink | String | Server-defined URL for the resource. |
| GCP.Compute.Firewalls.creationTimestamp | Date | The creation timestamp of the firewall rule in ISO 8601 format \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Compute.Firewalls.logConfig.enable | Boolean | Indicates whether logging is enabled for the firewall rule. |
| GCP.Compute.Firewalls.sourceRanges | Unknown | List of source IP ranges that the rule applies to. |
| GCP.Compute.Firewalls.targetTags | Unknown | List of target instance tags to which the rule applies. |
| GCP.Compute.FirewallsNextToken | String | Next page token for pagination. |

### gcp-storage-buckets-list

***
Retrieves the list of buckets in the project associated with the client. Required permission: storage.buckets.list.

#### Base Command

`gcp-storage-buckets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | Maximum number of buckets to return. | Optional |
| prefix | Filter results to buckets whose names begin with this prefix. | Optional |
| page_token | The token for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.id | String | The unique identifier for the bucket. |
| GCP.Storage.Buckets.name | String | The name of the bucket. |
| GCP.Storage.Buckets.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Buckets.location | String | The location of the bucket. |
| GCP.Storage.Buckets.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Buckets.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Buckets.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Buckets.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Buckets.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Buckets.generation | String | The generation number of the bucket. |
| GCP.Storage.Buckets.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Buckets.timeCreated | Date | The time the bucket was created. |
| GCP.Storage.Buckets.timeUpdated | Date | The time the bucket was last updated. |
| GCP.Storage.Buckets.selfLink | String | The link to the bucket resource on the GCP API. |
| GCP.Storage.BucketsNextToken | String | The continuation token. Provide this value as the page_token of a subsequent request in order to return the next page of results. |

### gcp-storage-bucket-policies-list

***
Retrieves the IAM policy for a bucket. Required permissions: storage.buckets.getIamPolicy, storage.buckets.get.

#### Base Command

`gcp-storage-bucket-policies-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket to retrieve IAM policy from. | Required |
| requested_policy_version | The IAM policy version to be returned. If the optionsRequestedPolicyVersion is for an older version that doesn't support part of the requested IAM policy, the request fails. Required to be 3 or greater for buckets with IAM Conditions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketPolicies.version | Number | IAM policy version. |
| GCP.Storage.BucketPolicies.etag | String | ETag of the IAM policy. |
| GCP.Storage.BucketPolicies.bindings | Unknown | List of role bindings for the bucket. |
| GCP.Storage.BucketPolicies.resourceId | String | Resource ID of the updated IAM policy. e.g. projects/_/buckets/BUCKET_NAME. |

### gcp-storage-bucket-object-policies-list

***
Retrieves the IAM policy for a specific object in a bucket. Required permission: storage.objects.getIamPolicy.

#### Base Command

`gcp-storage-bucket-object-policies-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket containing the object. | Required |
| object_name | Name of the object to retrieve IAM policy from. | Required |
| generation | The generation of the object (e.g., a positive integer). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.BucketObjectPolicies.bucketName | String | The name of the bucket containing the object. |
| GCP.Storage.BucketObjectPolicies.objectName | String | Name of the object. |
| GCP.Storage.BucketObjectPolicies.bindings | Unknown | List of role bindings for the object. |

### gcp-gke-cluster-security-update

***
Configures security settings for GKE clusters, including access controls and visibility. Only one update may be applied to a cluster per request. Provide exactly one of the supported security flags. Required permissions: container.clusters.update, container.clusters.get, container.clusters.list.

#### Base Command

`gcp-gke-cluster-security-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The GCP region. | Required |
| resource_name | Name of the GKE cluster. | Required |
| enable_intra_node_visibility | Whether to enable intra-node visibility. Possible values are: true, false. | Optional |
| enable_master_authorized_networks | Whether to enable Master Authorized Networks. Possible values are: true, false. | Optional |
| cidrs | A comma-separated list of up to 50 CIDR blocks (for example, "192.168.0.0/24,10.0.0.0/32") that are allowed to access the Kubernetes master via HTTPS.<br/>If enable_master_authorized_networks is true and no CIDRs are provided, all access will be blocked.<br/>. | Optional |
| enable_binary_authorization | Whether to enable Binary Authorization on the cluster. Possible values are: true, false. | Optional |
| enable_http_load_balancing | Whether to enable the HTTP load balancing add-on on the cluster. Possible values are: true, false. | Optional |
| enable_kubernetes_dashboard | Whether to enable the Kubernetes dashboard add-on on the cluster. Possible values are: true, false. | Optional |
| enable_network_policy | Whether to enable the network policy add-on on the cluster. Possible values are: true, false. | Optional |
| enable_stackdriver_kubernetes | Whether to enable Stackdriver Kubernetes monitoring and logging on the cluster. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.GKE.Operations.name | String | The name of the GKE cluster. |
| GCP.GKE.Operations.zone | String | The zone of the GKE cluster. |
| GCP.GKE.Operations.enableStackdriverLogging | Boolean | Whether Stackdriver Logging is enabled for the cluster. |
| GCP.GKE.Operations.enableStackdriverMonitoring | Boolean | Whether Stackdriver Monitoring is enabled for the cluster. |
| GCP.GKE.Operations.enablePrivateNodes | Boolean | Whether private nodes are enabled for the GKE cluster. |
| GCP.GKE.Operations.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the GKE cluster control plane. |
| GCP.GKE.Operations.enableHttpsOnly | Boolean | Whether HTTPS-only traffic is enforced for the cluster. |
| GCP.GKE.Operations.enableNetworkPolicy | Boolean | Whether network policies are enabled for the cluster. |
| GCP.GKE.Operations.enableAutoscaling | Boolean | Whether autoscaling is enabled for the cluster nodes. |
| GCP.GKE.Operations.enableIstio | Boolean | Whether Istio is enabled for the GKE cluster. |
| GCP.GKE.Operations.enablePodSecurityPolicy | Boolean | Whether PodSecurityPolicy is enabled for the GKE cluster. |
| GCP.GKE.Operations.enableBinaryAuthorization | Boolean | Whether Binary Authorization is enabled for the cluster. |
| GCP.GKE.Operations.enableLegacyABAC | Boolean | Whether legacy ABAC is enabled for the cluster. |
| GCP.GKE.Operations.clusterIpv4Cidr | String | The cluster’s IPv4 CIDR block. |
| GCP.GKE.Operations.masterAuthorizedNetworksConfig.cidrBlocks | Unknown | List of authorized CIDR blocks that can access the GKE cluster master. |
| GCP.GKE.Operations.masterAuthorizedNetworksConfig.enabled | Boolean | Whether master authorized networks are enabled for the cluster. |
| GCP.GKE.Operations.network | String | The network to which the GKE cluster belongs. |
| GCP.GKE.Operations.subnetwork | String | The subnetwork to which the GKE cluster belongs. |
| GCP.GKE.Operations.loggingService | String | The logging service used for the cluster \(e.g., "logging.googleapis.com"\). |
| GCP.GKE.Operations.monitoringService | String | The monitoring service used for the cluster \(e.g., "monitoring.googleapis.com"\). |
| GCP.GKE.Operations.nodePools | Unknown | A list of node pools in the cluster, with their configuration and security settings. |
| GCP.GKE.Operations.privateClusterConfig.enablePrivateNodes | Boolean | Whether private nodes are enabled in the cluster. |
| GCP.GKE.Operations.privateClusterConfig.enablePrivateEndpoint | Boolean | Whether private endpoint is enabled for the cluster control plane. |
| GCP.GKE.Operations.masterVersion | String | The current version of the Kubernetes master in the GKE cluster. |

### gcp-storage-bucket-create

***
Creates a new Google Cloud Storage (GCS) bucket in the specified project. Required permission: storage.buckets.create.

#### Base Command

`gcp-storage-bucket-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket to create. | Required |
| location | The location of the bucket (for example, US, EU, ASIA, us-central1). If not provided, the GCS API default (US) is used. | Optional |
| bucket_acl | The predefined ACL to apply to the bucket. Possible values are: authenticatedRead, private, projectPrivate, publicRead, publicReadWrite. | Optional |
| default_object_acl | The predefined default object ACL to apply to objects added to the bucket. Possible values are: authenticatedRead, bucketOwnerFullControl, bucketOwnerRead, private, projectPrivate, publicRead. | Optional |
| uniform_bucket_level_access | Whether to enable Uniform Bucket-Level Access (UBLA) on the bucket. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.id | String | The unique identifier for the bucket. |
| GCP.Storage.Buckets.name | String | The name of the bucket. |
| GCP.Storage.Buckets.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Buckets.selfLink | String | The link to the bucket resource on the GCP API. |
| GCP.Storage.Buckets.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Buckets.location | String | The location of the bucket. |
| GCP.Storage.Buckets.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Buckets.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Buckets.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Buckets.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Buckets.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Buckets.timeCreated | Date | The time the bucket was created. |
| GCP.Storage.Buckets.updated | Date | The time the bucket was last updated. |
| GCP.Storage.Buckets.iamConfiguration.publicAccessPrevention | String | The public access prevention setting of the bucket. |
| GCP.Storage.Buckets.iamConfiguration.uniformBucketLevelAccess | Object | The Uniform Bucket-Level Access \(UBLA\) configuration, including whether it is enabled and the deadline for disabling it. |
| GCP.Storage.Buckets.versioning.enabled | Boolean | Whether object versioning is enabled for the bucket. |
| GCP.Storage.Buckets.defaultEventBasedHold | Boolean | The default value for the event-based hold on newly created objects in the bucket. |
| GCP.Storage.Buckets.generation | String | The generation \(version\) number of the bucket. |
| GCP.Storage.Buckets.softDeleteTime | Date | The date and time when the bucket was soft-deleted. |
| GCP.Storage.Buckets.hardDeleteTime | Date | The time the bucket will be permanently deleted. |
| GCP.Storage.Buckets.hierarchicalNamespace.enabled | Boolean | Whether hierarchical namespace is enabled for the bucket. |
| GCP.Storage.Buckets.encryption.defaultKmsKeyName | String | The Cloud KMS key used to encrypt objects written to the bucket when no encryption method is specified. |
| GCP.Storage.Buckets.acl | Unknown | The access controls on the bucket \(bucketAccessControls resources\). Omitted when Uniform Bucket-Level Access is enabled. |
| GCP.Storage.Buckets.defaultObjectAcl | Unknown | The default access controls applied to new objects when no ACL is provided. Omitted when Uniform Bucket-Level Access is enabled. |
| GCP.Storage.Buckets.website.mainPageSuffix | String | The suffix appended to requests for a directory-like URL, used for static website hosting. |
| GCP.Storage.Buckets.website.notFoundPage | String | The object served when a requested resource is not found, used for static website hosting. |
| GCP.Storage.Buckets.owner.entity | String | The entity that owns the bucket, in the form project-owner-projectId. |
| GCP.Storage.Buckets.owner.entityId | String | The ID of the entity that owns the bucket. |
| GCP.Storage.Buckets.logging.logBucket | String | The destination bucket where the bucket's logs are placed. |
| GCP.Storage.Buckets.logging.logObjectPrefix | String | The prefix for log object names. |
| GCP.Storage.Buckets.cors | Unknown | The bucket's Cross-Origin Resource Sharing \(CORS\) configuration. |
| GCP.Storage.Buckets.lifecycle.rule | Unknown | The bucket's lifecycle management rules. |
| GCP.Storage.Buckets.autoclass.enabled | Boolean | Whether Autoclass is enabled for the bucket. |
| GCP.Storage.Buckets.autoclass.toggleTime | Date | The date and time when Autoclass was last enabled or disabled for the bucket. |
| GCP.Storage.Buckets.autoclass.terminalStorageClass | String | The coldest storage class that an object transitions to in an Autoclass-enabled bucket. |
| GCP.Storage.Buckets.autoclass.terminalStorageClassUpdateTime | Date | The date and time when the terminal storage class was last updated for the bucket. |
| GCP.Storage.Buckets.labels | Unknown | The user-provided bucket labels, as key-value pairs. |
| GCP.Storage.Buckets.retentionPolicy.retentionPeriod | String | The minimum age in seconds that objects must reach before they can be deleted or replaced. |
| GCP.Storage.Buckets.retentionPolicy.effectiveTime | Date | The date and time from which the retention policy was effective. |
| GCP.Storage.Buckets.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.Storage.Buckets.objectRetention.mode | String | The bucket's object retention mode. When enabled, retention configurations can be set on objects. |
| GCP.Storage.Buckets.billing.requesterPays | Boolean | Whether Requester Pays is enabled for the bucket. |
| GCP.Storage.Buckets.softDeletePolicy.retentionDurationSeconds | String | The period in seconds during which a soft-deleted object is retained and cannot be permanently deleted. |
| GCP.Storage.Buckets.softDeletePolicy.effectiveTime | Date | The date and time when the soft delete policy becomes effective. |
| GCP.Storage.Buckets.customPlacementConfig.dataLocations | Unknown | The list of individual regions that comprise a configurable dual-region bucket. |
| GCP.Storage.Buckets.ipFilter.mode | String | The state of the IP filter configuration \(Enabled or Disabled\). |

### gcp-storage-bucket-delete

***
Deletes a Google Cloud Storage (GCS) bucket. The bucket must be empty unless the force argument is set to true. Required permissions: storage.buckets.delete, storage.objects.list, storage.objects.delete.

#### Base Command

`gcp-storage-bucket-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket to delete. | Required |
| force | Whether to delete all objects in the bucket before deleting the bucket itself. When false, deleting a non-empty bucket fails. Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

### gcp-storage-bucket-public-access-block

***
Sets the public access prevention configuration on a GCS bucket. Required permissions: storage.buckets.update, storage.buckets.setIamPolicy.

#### Base Command

`gcp-storage-bucket-public-access-block`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket. | Required |
| public_access_prevention | The public access prevention setting to apply. "enforced" blocks all public access; "inherited" defers to the organization policy. Possible values are: enforced, inherited. Default is enforced. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.id | String | The unique identifier for the bucket. |
| GCP.Storage.Buckets.name | String | The name of the bucket. |
| GCP.Storage.Buckets.kind | String | The type of resource \(for example, storage\#bucket\). |
| GCP.Storage.Buckets.selfLink | String | The link to the bucket resource on the GCP API. |
| GCP.Storage.Buckets.projectNumber | String | The GCP project number associated with the bucket. |
| GCP.Storage.Buckets.location | String | The location of the bucket. |
| GCP.Storage.Buckets.locationType | String | The type of location \(for example, multi-region\). |
| GCP.Storage.Buckets.storageClass | String | The storage class of the bucket. |
| GCP.Storage.Buckets.rpo | String | The recovery point objective setting of the bucket. |
| GCP.Storage.Buckets.etag | String | The HTTP entity tag of the bucket. |
| GCP.Storage.Buckets.metageneration | String | The metageneration number of the bucket. |
| GCP.Storage.Buckets.timeCreated | Date | The time the bucket was created. |
| GCP.Storage.Buckets.updated | Date | The time the bucket was last updated. |
| GCP.Storage.Buckets.iamConfiguration.publicAccessPrevention | String | The public access prevention setting of the bucket. |
| GCP.Storage.Buckets.iamConfiguration.uniformBucketLevelAccess | Object | The Uniform Bucket-Level Access \(UBLA\) configuration, including whether it is enabled and the deadline for disabling it. |
| GCP.Storage.Buckets.versioning.enabled | Boolean | Whether object versioning is enabled for the bucket. |
| GCP.Storage.Buckets.defaultEventBasedHold | Boolean | The default value for the event-based hold on newly created objects in the bucket. |
| GCP.Storage.Buckets.generation | String | The generation \(version\) number of the bucket. |
| GCP.Storage.Buckets.softDeleteTime | Date | The date and time when the bucket was soft-deleted. |
| GCP.Storage.Buckets.hardDeleteTime | Date | The time the bucket will be permanently deleted. |
| GCP.Storage.Buckets.hierarchicalNamespace.enabled | Boolean | Whether hierarchical namespace is enabled for the bucket. |
| GCP.Storage.Buckets.encryption.defaultKmsKeyName | String | The Cloud KMS key used to encrypt objects written to the bucket when no encryption method is specified. |
| GCP.Storage.Buckets.acl | Unknown | The access controls on the bucket \(bucketAccessControls resources\). Omitted when Uniform Bucket-Level Access is enabled. |
| GCP.Storage.Buckets.defaultObjectAcl | Unknown | The default access controls applied to new objects when no ACL is provided. Omitted when Uniform Bucket-Level Access is enabled. |
| GCP.Storage.Buckets.website.mainPageSuffix | String | The suffix appended to requests for a directory-like URL, used for static website hosting. |
| GCP.Storage.Buckets.website.notFoundPage | String | The object served when a requested resource is not found, used for static website hosting. |
| GCP.Storage.Buckets.owner.entity | String | The entity that owns the bucket, in the form project-owner-projectId. |
| GCP.Storage.Buckets.owner.entityId | String | The ID of the entity that owns the bucket. |
| GCP.Storage.Buckets.logging.logBucket | String | The destination bucket where the bucket's logs are placed. |
| GCP.Storage.Buckets.logging.logObjectPrefix | String | The prefix for log object names. |
| GCP.Storage.Buckets.cors | Unknown | The bucket's Cross-Origin Resource Sharing \(CORS\) configuration. |
| GCP.Storage.Buckets.lifecycle.rule | Unknown | The bucket's lifecycle management rules. |
| GCP.Storage.Buckets.autoclass.enabled | Boolean | Whether Autoclass is enabled for the bucket. |
| GCP.Storage.Buckets.autoclass.toggleTime | Date | The date and time when Autoclass was last enabled or disabled for the bucket. |
| GCP.Storage.Buckets.autoclass.terminalStorageClass | String | The coldest storage class that an object transitions to in an Autoclass-enabled bucket. |
| GCP.Storage.Buckets.autoclass.terminalStorageClassUpdateTime | Date | The date and time when the terminal storage class was last updated for the bucket. |
| GCP.Storage.Buckets.labels | Unknown | The user-provided bucket labels, as key-value pairs. |
| GCP.Storage.Buckets.retentionPolicy.retentionPeriod | String | The minimum age in seconds that objects must reach before they can be deleted or replaced. |
| GCP.Storage.Buckets.retentionPolicy.effectiveTime | Date | The date and time from which the retention policy was effective. |
| GCP.Storage.Buckets.retentionPolicy.isLocked | Boolean | Whether the retention policy is locked. |
| GCP.Storage.Buckets.objectRetention.mode | String | The bucket's object retention mode. When enabled, retention configurations can be set on objects. |
| GCP.Storage.Buckets.billing.requesterPays | Boolean | Whether Requester Pays is enabled for the bucket. |
| GCP.Storage.Buckets.softDeletePolicy.retentionDurationSeconds | String | The period in seconds during which a soft-deleted object is retained and cannot be permanently deleted. |
| GCP.Storage.Buckets.softDeletePolicy.effectiveTime | Date | The date and time when the soft delete policy becomes effective. |
| GCP.Storage.Buckets.customPlacementConfig.dataLocations | Unknown | The list of individual regions that comprise a configurable dual-region bucket. |
| GCP.Storage.Buckets.ipFilter.mode | String | The state of the IP filter configuration \(Enabled or Disabled\). |

### gcp-storage-bucket-object-upload

***
Uploads a War Room file (by entry ID) to a GCS bucket as an object. Required permission: storage.objects.create.

#### Base Command

`gcp-storage-bucket-object-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket to upload the object to. | Required |
| object_name | The name to give the uploaded object in the bucket. | Required |
| entry_id | The War Room entry ID of the file to upload. | Required |
| object_acl | The predefined ACL to apply to the uploaded object. Cannot be used when Uniform Bucket-Level Access is enabled on the bucket. Possible values are: authenticatedRead, bucketOwnerFullControl, bucketOwnerRead, private, projectPrivate, publicRead. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.name | String | The name of the bucket containing the uploaded object. |
| GCP.Storage.Buckets.Objects.kind | String | The kind of item this is. For objects, this is always storage\#object. |
| GCP.Storage.Buckets.Objects.id | String | The ID of the uploaded object, including the bucket name, object name, and generation number. |
| GCP.Storage.Buckets.Objects.selfLink | String | The link to the uploaded object. |
| GCP.Storage.Buckets.Objects.mediaLink | String | The media download link for the uploaded object. |
| GCP.Storage.Buckets.Objects.name | String | The name of the uploaded object. |
| GCP.Storage.Buckets.Objects.bucket | String | The name of the bucket containing the object. |
| GCP.Storage.Buckets.Objects.generation | String | The content generation of the uploaded object. Used for object versioning. |
| GCP.Storage.Buckets.Objects.metageneration | String | The version of the metadata for the object at this generation. |
| GCP.Storage.Buckets.Objects.contentType | String | The content type of the uploaded object. |
| GCP.Storage.Buckets.Objects.storageClass | String | The storage class of the uploaded object. |
| GCP.Storage.Buckets.Objects.size | String | The content length of the uploaded object in bytes. |
| GCP.Storage.Buckets.Objects.md5Hash | String | The MD5 hash of the uploaded object. |
| GCP.Storage.Buckets.Objects.crc32c | String | The CRC32c checksum of the uploaded object. |
| GCP.Storage.Buckets.Objects.etag | String | The HTTP 1.1 Entity tag for the uploaded object. |
| GCP.Storage.Buckets.Objects.timeCreated | Date | The creation time of the uploaded object in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.updated | Date | The modification time of the uploaded object metadata in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.timeStorageClassUpdated | Date | The date and time when the object's storage class was last changed, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.contentEncoding | String | The content encoding of the uploaded object. |
| GCP.Storage.Buckets.Objects.contentDisposition | String | The content disposition of the uploaded object. |
| GCP.Storage.Buckets.Objects.contentLanguage | String | The content language of the uploaded object. |
| GCP.Storage.Buckets.Objects.cacheControl | String | The cache control directive for the uploaded object. |
| GCP.Storage.Buckets.Objects.metadata | Unknown | The user-provided metadata, in key/value pairs. |
| GCP.Storage.Buckets.Objects.acl | Unknown | The access control list for the uploaded object. |
| GCP.Storage.Buckets.Objects.owner | Object | The owner of the object, including the owner entity and entity ID. |
| GCP.Storage.Buckets.Objects.componentCount | Number | The number of component objects that make up a composite object. |
| GCP.Storage.Buckets.Objects.customTime | Date | The user-specified timestamp for the uploaded object, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.eventBasedHold | Boolean | Whether an event-based hold is active on the uploaded object. |
| GCP.Storage.Buckets.Objects.temporaryHold | Boolean | Whether a temporary hold is active on the uploaded object. |
| GCP.Storage.Buckets.Objects.retentionExpirationTime | Date | The earliest date and time when the object can be deleted based on the bucket's retention policy, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.kmsKeyName | String | The Cloud KMS key used to encrypt the uploaded object, if any. |
| GCP.Storage.Buckets.Objects.customerEncryption | Object | The customer-supplied encryption key information, including the algorithm and the SHA256 hash of the key. |

### gcp-storage-bucket-object-download

***
Downloads an object from a GCS bucket and returns it as a War Room file. Required permission: storage.objects.get.

#### Base Command

`gcp-storage-bucket-object-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket containing the object. | Required |
| object_name | The name of the object to download. | Required |
| saved_file_name | The name to give the downloaded file in the War Room. Defaults to the last path segment of the object name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The name of the downloaded file. |
| File.EntryID | String | The War Room entry ID of the downloaded file. |
| File.Size | Number | The size of the downloaded file in bytes. |
| File.MD5 | String | The MD5 hash of the downloaded file. |
| File.SHA1 | String | The SHA1 hash of the downloaded file. |
| File.SHA256 | String | The SHA256 hash of the downloaded file. |

### gcp-storage-bucket-object-copy

***
Copies an object from a source bucket to a destination bucket. Required permissions: storage.objects.get, storage.objects.create.

#### Base Command

`gcp-storage-bucket-object-copy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| source_bucket_name | The name of the source bucket containing the object to copy. | Required |
| source_object_name | The name of the object to copy. | Required |
| destination_bucket_name | The name of the destination bucket to copy the object to. | Required |
| destination_object_name | The name to give the copied object in the destination bucket. Defaults to the source object name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Storage.Buckets.name | String | The name of the destination bucket containing the copied object. |
| GCP.Storage.Buckets.Objects.kind | String | The kind of item this is. For objects, this is always storage\#object. |
| GCP.Storage.Buckets.Objects.id | String | The ID of the copied object, including the bucket name, object name, and generation number. |
| GCP.Storage.Buckets.Objects.selfLink | String | The link to the copied object. |
| GCP.Storage.Buckets.Objects.mediaLink | String | The media download link for the copied object. |
| GCP.Storage.Buckets.Objects.name | String | The name of the copied object. |
| GCP.Storage.Buckets.Objects.bucket | String | The name of the bucket containing the object. |
| GCP.Storage.Buckets.Objects.generation | String | The content generation of the copied object. Used for object versioning. |
| GCP.Storage.Buckets.Objects.metageneration | String | The version of the metadata for the object at this generation. |
| GCP.Storage.Buckets.Objects.contentType | String | The content type of the copied object. |
| GCP.Storage.Buckets.Objects.storageClass | String | The storage class of the copied object. |
| GCP.Storage.Buckets.Objects.size | String | The content length of the copied object in bytes. |
| GCP.Storage.Buckets.Objects.md5Hash | String | The MD5 hash of the copied object. |
| GCP.Storage.Buckets.Objects.crc32c | String | The CRC32c checksum of the copied object. |
| GCP.Storage.Buckets.Objects.etag | String | The HTTP 1.1 Entity tag for the copied object. |
| GCP.Storage.Buckets.Objects.timeCreated | Date | The creation date and time of the copied object, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.updated | Date | The modification time of the copied object metadata, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.timeStorageClassUpdated | Date | The date and time when the object's storage class was last changed, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.contentEncoding | String | The content encoding of the copied object. |
| GCP.Storage.Buckets.Objects.contentDisposition | String | The content disposition of the copied object. |
| GCP.Storage.Buckets.Objects.contentLanguage | String | The content language of the copied object. |
| GCP.Storage.Buckets.Objects.cacheControl | String | The cache control directive for the copied object. |
| GCP.Storage.Buckets.Objects.metadata | Unknown | The user-provided metadata, in key/value pairs. |
| GCP.Storage.Buckets.Objects.acl | Unknown | The access control list for the copied object. |
| GCP.Storage.Buckets.Objects.owner | Object | The owner of the object, including the owner entity and entity ID. |
| GCP.Storage.Buckets.Objects.componentCount | Number | The number of component objects that make up a composite object. |
| GCP.Storage.Buckets.Objects.customTime | Date | The user-specified timestamp for the copied object, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.eventBasedHold | Boolean | Whether an event-based hold is active on the copied object. |
| GCP.Storage.Buckets.Objects.temporaryHold | Boolean | Whether a temporary hold is active on the copied object. |
| GCP.Storage.Buckets.Objects.retentionExpirationTime | Date | The earliest date and time when the object can be deleted based on the bucket's retention policy, in RFC 3339 format. |
| GCP.Storage.Buckets.Objects.kmsKeyName | String | The Cloud KMS key used to encrypt the copied object, if any. |
| GCP.Storage.Buckets.Objects.customerEncryption | Object | The customer-supplied encryption key information, including the algorithm and the SHA256 hash of the key. |

### gcp-storage-bucket-object-delete

***
Deletes an object from a GCS bucket. Required permission: storage.objects.delete.

#### Base Command

`gcp-storage-bucket-object-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket containing the object. | Required |
| object_name | The name of the object to delete. | Required |
| generation | The specific revision of the object to permanently delete instead of the latest version. | Optional |

#### Context Output

There is no context output for this command.

### gcp-storage-bucket-object-policy-delete

***
Removes an ACL entry (entity) from a GCS object's access control list. If Uniform Bucket-Level Access is enabled on the bucket, use gcp-storage-bucket-policy-delete instead. Required permissions: storage.objects.get, storage.objects.update.

#### Base Command

`gcp-storage-bucket-object-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| bucket_name | The name of the bucket containing the object. | Required |
| object_name | The name of the object to remove the ACL entry from. | Required |
| entity | The entity to remove from the object's ACL (for example, allUsers, allAuthenticatedUsers, user-test@example.com). | Required |
| generation | The specific revision of the object to target. | Optional |

#### Context Output

There is no context output for this command.

### gcp-kms-key-rings-list

***
Lists the Cloud KMS key rings in a given location, or across all locations. Required Permissions: cloudkms.keyRings.list.

#### Base Command

`gcp-kms-key-rings-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| all_locations | Whether to return the key rings from all supported locations. When set to true, the location argument is ignored. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of key rings to return per location. Valid range 1-500. Default is 50. | Optional |
| page_token | The token for the next page of results, used for pagination. Ignored when all_locations is set to true, because a page token is bound to a single location. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.KeyRings.Name | String | The ID of the key ring. |
| GCP.KMS.KeyRings.ResourceName | String | The full resource name of the key ring. |
| GCP.KMS.KeyRings.Project | String | The project that holds the key ring. |
| GCP.KMS.KeyRings.Location | String | The location of the key ring. |
| GCP.KMS.KeyRings.createTime | Date | The time at which the key ring was created. |
| GCP.KMS.KeyRingsNextToken | String | The token to pass as the page_token argument to retrieve the next page of key rings. |

### gcp-kms-keys-list

***
Lists the crypto keys of a given Cloud KMS key ring. Required Permissions: cloudkms.cryptoKeys.list.

#### Base Command

`gcp-kms-keys-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto keys. | Required |
| key_state | Returns only keys whose primary crypto key version is in this state. Leave empty to return all keys. Possible values are: ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_GENERATION, PENDING_IMPORT, IMPORT_FAILED. | Optional |
| limit | The maximum number of crypto keys to return. Valid range 1-500. Default is 50. | Optional |
| page_token | The token for the next page of results, used for pagination. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeys.Name | String | The ID of the crypto key. |
| GCP.KMS.CryptoKeys.ResourceName | String | The full resource name of the crypto key. |
| GCP.KMS.CryptoKeys.Project | String | The project that holds the crypto key. |
| GCP.KMS.CryptoKeys.Location | String | The location of the crypto key. |
| GCP.KMS.CryptoKeys.KeyRing | String | The key ring that holds the crypto key. |
| GCP.KMS.CryptoKeys.purpose | String | The immutable purpose of the crypto key. |
| GCP.KMS.CryptoKeys.createTime | Date | The time at which the crypto key was created. |
| GCP.KMS.CryptoKeys.nextRotationTime | Date | The time at which the next scheduled rotation is due to run. |
| GCP.KMS.CryptoKeys.rotationPeriod | String | The period between automatic key rotations. |
| GCP.KMS.CryptoKeys.labels | Unknown | The labels with user-defined metadata. |
| GCP.KMS.CryptoKeys.versionTemplate | Unknown | The version template of the crypto key, containing the protectionLevel and algorithm fields. |
| GCP.KMS.CryptoKeys.primary | Unknown | The primary crypto key version, containing the name, state, createTime, protectionLevel, algorithm, and generateTime fields. |
| GCP.KMS.CryptoKeysNextToken | String | The token to use when requesting the next set of crypto keys. |

### gcp-kms-keys-list-all

***
Lists every crypto key across all key rings in a location, or across all locations. Required Permissions: cloudkms.keyRings.list, cloudkms.cryptoKeys.list.

#### Base Command

`gcp-kms-keys-list-all`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| all_locations | Whether to return the crypto keys from all supported locations. When set to true, the location argument is ignored. Possible values are: true, false. Default is false. | Optional |
| key_state | Returns only keys whose primary crypto key version is in this state. Leave empty to return all keys. Possible values are: ENABLED, DISABLED, DESTROYED, DESTROY_SCHEDULED, PENDING_GENERATION, PENDING_IMPORT, IMPORT_FAILED. | Optional |
| limit | The maximum number of crypto keys to return per key ring. Valid range 1-500. This command aggregates results across key rings and cannot be paged. If any key ring holds more keys than this limit, a truncation notice is returned. Use gcp-kms-keys-list to page through a single key ring. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeys.Name | String | The ID of the crypto key. |
| GCP.KMS.CryptoKeys.ResourceName | String | The full resource name of the crypto key. |
| GCP.KMS.CryptoKeys.Project | String | The project that holds the crypto key. |
| GCP.KMS.CryptoKeys.Location | String | The location of the crypto key. |
| GCP.KMS.CryptoKeys.KeyRing | String | The key ring that holds the crypto key. |
| GCP.KMS.CryptoKeys.purpose | String | The immutable purpose of the crypto key. |
| GCP.KMS.CryptoKeys.createTime | Date | The time at which the crypto key was created. |
| GCP.KMS.CryptoKeys.nextRotationTime | Date | The time at which the next scheduled rotation is due to run. |
| GCP.KMS.CryptoKeys.rotationPeriod | String | The period between automatic key rotations. |
| GCP.KMS.CryptoKeys.labels | Unknown | The labels with user-defined metadata. |
| GCP.KMS.CryptoKeys.versionTemplate | Unknown | The version template of the crypto key, containing the protectionLevel and algorithm fields. |
| GCP.KMS.CryptoKeys.primary | Unknown | The primary crypto key version, containing the name, state, createTime, protectionLevel, algorithm, and generateTime fields. |

### gcp-kms-key-get

***
Returns the metadata of a given crypto key and its primary crypto key version. Required Permissions: cloudkms.cryptoKeys.get.

#### Base Command

`gcp-kms-key-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to fetch. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeys.Name | String | The ID of the crypto key. |
| GCP.KMS.CryptoKeys.ResourceName | String | The full resource name of the crypto key. |
| GCP.KMS.CryptoKeys.Project | String | The project that holds the crypto key. |
| GCP.KMS.CryptoKeys.Location | String | The location of the crypto key. |
| GCP.KMS.CryptoKeys.KeyRing | String | The key ring that holds the crypto key. |
| GCP.KMS.CryptoKeys.purpose | String | The immutable purpose of the crypto key. |
| GCP.KMS.CryptoKeys.createTime | Date | The time at which the crypto key was created. |
| GCP.KMS.CryptoKeys.nextRotationTime | Date | The time at which the next scheduled rotation is due to run. |
| GCP.KMS.CryptoKeys.rotationPeriod | String | The period between automatic key rotations. |
| GCP.KMS.CryptoKeys.labels | Unknown | The labels with user-defined metadata. |
| GCP.KMS.CryptoKeys.versionTemplate | Unknown | The version template of the crypto key, containing the protectionLevel and algorithm fields. |
| GCP.KMS.CryptoKeys.primary | Unknown | The primary crypto key version, containing the name, state, createTime, protectionLevel, algorithm, and generateTime fields. |

### gcp-kms-key-create

***
Creates a new crypto key within a given key ring. Required Permissions: cloudkms.cryptoKeys.create.

#### Base Command

`gcp-kms-key-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring in which to create the crypto key. | Required |
| crypto_key | The ID of the crypto key to create. Must be unique within the key ring and match the regular expression [a-zA-Z0-9_-]{1,63}. | Required |
| purpose | The immutable cryptographic capability of the crypto key. Possible values are: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT. Default is ENCRYPT_DECRYPT. | Optional |
| algorithm | The algorithm to use when creating a crypto key version based on this template. Possible values are: GOOGLE_SYMMETRIC_ENCRYPTION, RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PSS_3072_SHA256, RSA_SIGN_PSS_4096_SHA256, RSA_SIGN_PSS_4096_SHA512, RSA_SIGN_PKCS1_2048_SHA256, RSA_SIGN_PKCS1_3072_SHA256, RSA_SIGN_PKCS1_4096_SHA256, RSA_SIGN_PKCS1_4096_SHA512, RSA_DECRYPT_OAEP_2048_SHA256, RSA_DECRYPT_OAEP_3072_SHA256, RSA_DECRYPT_OAEP_4096_SHA256, RSA_DECRYPT_OAEP_4096_SHA512, EC_SIGN_P256_SHA256, EC_SIGN_P384_SHA384. Default is GOOGLE_SYMMETRIC_ENCRYPTION. | Optional |
| protection_level | The protection level to use when creating a crypto key version based on this template. Possible values are: SOFTWARE, HSM. Default is SOFTWARE. | Optional |
| rotation_period | The period between automatic key rotations, as a duration in seconds (for example, 7776000s). Must be between 24 hours and 876,000 hours. Supported only for keys whose purpose is ENCRYPT_DECRYPT. | Optional |
| next_rotation_time | The time of the next scheduled rotation. Accepts an absolute timestamp in RFC3339 UTC "Zulu" format (for example, 2024-10-02T15:01:23Z) or a relative expression (for example, "in 30 days"). Supported only for keys whose purpose is ENCRYPT_DECRYPT. | Optional |
| labels | The labels with user-defined metadata, in the format key=abc,value=123;key=def,value=456. | Optional |
| skip_initial_version_creation | Whether to create the crypto key without an initial crypto key version. When set to true, a crypto key version must be created before the key can be used. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeys.Name | String | The ID of the crypto key. |
| GCP.KMS.CryptoKeys.ResourceName | String | The full resource name of the crypto key. |
| GCP.KMS.CryptoKeys.Project | String | The project that holds the crypto key. |
| GCP.KMS.CryptoKeys.Location | String | The location of the crypto key. |
| GCP.KMS.CryptoKeys.KeyRing | String | The key ring that holds the crypto key. |
| GCP.KMS.CryptoKeys.purpose | String | The immutable purpose of the crypto key. |
| GCP.KMS.CryptoKeys.createTime | Date | The time at which the crypto key was created. |
| GCP.KMS.CryptoKeys.nextRotationTime | Date | The time at which the next scheduled rotation is due to run. |
| GCP.KMS.CryptoKeys.rotationPeriod | String | The period between automatic key rotations. |
| GCP.KMS.CryptoKeys.labels | Unknown | The labels with user-defined metadata. |
| GCP.KMS.CryptoKeys.versionTemplate | Unknown | The version template of the crypto key, containing the protectionLevel and algorithm fields. |
| GCP.KMS.CryptoKeys.primary | Unknown | The primary crypto key version, containing the name, state, createTime, protectionLevel, algorithm, and generateTime fields. |

### gcp-kms-key-update

***
Updates the mutable fields of a given crypto key. Only the supplied fields are updated. Required Permissions: cloudkms.cryptoKeys.update.

#### Base Command

`gcp-kms-key-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to update. | Required |
| labels | The labels with user-defined metadata, in the format key=abc,value=123;key=def,value=456. | Optional |
| next_rotation_time | The time of the next scheduled rotation. Accepts an absolute timestamp in RFC3339 UTC "Zulu" format (for example, 2024-10-02T15:01:23Z) or a relative expression (for example, "in 30 days"). | Optional |
| rotation_period | The period between automatic key rotations, as a duration in seconds (for example, 7776000s). Must be between 24 hours and 876,000 hours. | Optional |
| algorithm | The algorithm to use when creating a crypto key version based on this template. Possible values are: GOOGLE_SYMMETRIC_ENCRYPTION, RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PSS_3072_SHA256, RSA_SIGN_PSS_4096_SHA256, RSA_SIGN_PSS_4096_SHA512, RSA_SIGN_PKCS1_2048_SHA256, RSA_SIGN_PKCS1_3072_SHA256, RSA_SIGN_PKCS1_4096_SHA256, RSA_SIGN_PKCS1_4096_SHA512, RSA_DECRYPT_OAEP_2048_SHA256, RSA_DECRYPT_OAEP_3072_SHA256, RSA_DECRYPT_OAEP_4096_SHA256, RSA_DECRYPT_OAEP_4096_SHA512, EC_SIGN_P256_SHA256, EC_SIGN_P384_SHA384. | Optional |
| protection_level | The protection level to use when creating a crypto key version based on this template. Possible values are: SOFTWARE, HSM. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeys.Name | String | The ID of the crypto key. |
| GCP.KMS.CryptoKeys.ResourceName | String | The full resource name of the crypto key. |
| GCP.KMS.CryptoKeys.Project | String | The project that holds the crypto key. |
| GCP.KMS.CryptoKeys.Location | String | The location of the crypto key. |
| GCP.KMS.CryptoKeys.KeyRing | String | The key ring that holds the crypto key. |
| GCP.KMS.CryptoKeys.purpose | String | The immutable purpose of the crypto key. |
| GCP.KMS.CryptoKeys.createTime | Date | The time at which the crypto key was created. |
| GCP.KMS.CryptoKeys.nextRotationTime | Date | The time at which the next scheduled rotation is due to run. |
| GCP.KMS.CryptoKeys.rotationPeriod | String | The period between automatic key rotations. |
| GCP.KMS.CryptoKeys.labels | Unknown | The labels with user-defined metadata. |
| GCP.KMS.CryptoKeys.versionTemplate | Unknown | The version template of the crypto key, containing the protectionLevel and algorithm fields. |
| GCP.KMS.CryptoKeys.primary | Unknown | The primary crypto key version, containing the name, state, createTime, protectionLevel, algorithm, and generateTime fields. |

### gcp-kms-key-version-enable

***
Enables a crypto key version of a given crypto key. Required Permissions: cloudkms.cryptoKeyVersions.update, cloudkms.cryptoKeys.get.

#### Base Command

`gcp-kms-key-version-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to enable. | Required |
| crypto_key_version | The ID of the crypto key version to enable. Use the keyword default to target the primary crypto key version of the given crypto key. Default is default. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeyVersions.name | String | The resource name of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.state | String | The current state of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.protectionLevel | String | The protection level describing how cryptographic operations are performed. |
| GCP.KMS.CryptoKeyVersions.algorithm | String | The algorithm that the crypto key version supports. |
| GCP.KMS.CryptoKeyVersions.createTime | Date | The time at which the crypto key version was created. The value is an RFC 3339 UTC timestamp (for example, 2024-01-15T12:34:56.789012Z). |

### gcp-kms-key-version-disable

***
Disables a crypto key version of a given crypto key. Required Permissions: cloudkms.cryptoKeyVersions.update, cloudkms.cryptoKeys.get.

#### Base Command

`gcp-kms-key-version-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to disable. | Required |
| crypto_key_version | The ID of the crypto key version to disable. Use the keyword default to target the primary crypto key version of the given crypto key. Default is default. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeyVersions.name | String | The resource name of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.state | String | The current state of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.protectionLevel | String | The protection level describing how cryptographic operations are performed. |
| GCP.KMS.CryptoKeyVersions.algorithm | String | The algorithm that the crypto key version supports. |
| GCP.KMS.CryptoKeyVersions.createTime | Date | The time at which the crypto key version was created. The value is an RFC 3339 UTC timestamp (for example, 2024-01-15T12:34:56.789012Z). |

### gcp-kms-key-version-destroy

***
Schedules a crypto key version for destruction. The key material is destroyed 24 hours later. Required Permissions: cloudkms.cryptoKeyVersions.destroy, cloudkms.cryptoKeys.get.

#### Base Command

`gcp-kms-key-version-destroy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to destroy. | Required |
| crypto_key_version | The ID of the crypto key version to destroy. Use the keyword default to target the primary crypto key version of the given crypto key. Default is default. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeyVersions.name | String | The resource name of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.state | String | The current state of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.destroyTime | Date | The time at which the crypto key version material is scheduled to be destroyed. The value is an RFC 3339 UTC timestamp (for example, 2024-01-15T12:34:56.789012Z). |

### gcp-kms-key-version-restore

***
Restores a crypto key version that is scheduled for destruction. Required Permissions: cloudkms.cryptoKeyVersions.restore, cloudkms.cryptoKeys.get.

#### Base Command

`gcp-kms-key-version-restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to restore. | Required |
| crypto_key_version | The ID of the crypto key version to restore. Use the keyword default to target the primary crypto key version of the given crypto key. Default is default. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.CryptoKeyVersions.name | String | The resource name of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.state | String | The current state of the crypto key version. |
| GCP.KMS.CryptoKeyVersions.protectionLevel | String | The protection level describing how cryptographic operations are performed. |
| GCP.KMS.CryptoKeyVersions.algorithm | String | The algorithm that the crypto key version supports. |

### gcp-kms-public-key-get

***
Returns the public key of a given asymmetric crypto key version. Required Permissions: cloudkms.cryptoKeyVersions.viewPublicKey.

#### Base Command

`gcp-kms-public-key-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the asymmetric crypto key. | Required |
| crypto_key_version | The ID of the crypto key version whose public key is returned. Default is 1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.PublicKey.CryptoKey | String | The crypto key to which the public key belongs. |
| GCP.KMS.PublicKey.CryptoKeyVersion | String | The resource name of the crypto key version. |
| GCP.KMS.PublicKey.pem | String | The public key in PEM format. |
| GCP.KMS.PublicKey.pemCrc32c | String | The CRC32C checksum of the returned PEM public key. |
| GCP.KMS.PublicKey.algorithm | String | The algorithm of the public key. |
| GCP.KMS.PublicKey.name | String | The resource name of the crypto key version returned by the API. |
| GCP.KMS.PublicKey.protectionLevel | String | The protection level of the crypto key version. |

### gcp-kms-symmetric-encrypt

***
Encrypts data using a symmetric crypto key. Required Permissions: cloudkms.cryptoKeyVersions.useToEncrypt.

#### Base Command

`gcp-kms-symmetric-encrypt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to encrypt with. | Required |
| plaintext | The plaintext to encrypt. Must be no larger than 64KiB. Mutually exclusive with base64_plaintext and entry_id. | Optional |
| base64_plaintext | The Base64-encoded plaintext to encrypt. Mutually exclusive with plaintext and entry_id. | Optional |
| entry_id | The War Room entry ID of the file to encrypt. Mutually exclusive with plaintext and base64_plaintext. | Optional |
| additional_authenticated_data | The Base64-encoded additional authenticated data (AAD). The same value must be supplied when decrypting. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.SymmetricEncrypt.CryptoKey | String | The crypto key used for the encryption. |
| GCP.KMS.SymmetricEncrypt.ResourceName | String | The full resource name of the crypto key used for the encryption. |
| GCP.KMS.SymmetricEncrypt.ciphertext | String | The Base64-encoded encrypted ciphertext. |
| GCP.KMS.SymmetricEncrypt.ciphertextCrc32c | String | The CRC32C checksum of the returned ciphertext. |
| GCP.KMS.SymmetricEncrypt.verifiedPlaintextCrc32c | Boolean | Whether the API verified the CRC32C checksum of the supplied plaintext. |
| GCP.KMS.SymmetricEncrypt.name | String | The resource name of the crypto key version used for the encryption. |
| GCP.KMS.SymmetricEncrypt.protectionLevel | String | The protection level of the crypto key version used for the encryption. |

### gcp-kms-symmetric-decrypt

***
Decrypts data that was encrypted with a symmetric crypto key. Required Permissions: cloudkms.cryptoKeyVersions.useToDecrypt.

#### Base Command

`gcp-kms-symmetric-decrypt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the crypto key to decrypt with. | Required |
| ciphertext | The Base64-encoded ciphertext to decrypt. Mutually exclusive with entry_id. | Optional |
| entry_id | The War Room entry ID of the file holding the raw ciphertext bytes to decrypt. Mutually exclusive with ciphertext. | Optional |
| additional_authenticated_data | The Base64-encoded additional authenticated data (AAD) that was supplied during encryption. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.SymmetricDecrypt.CryptoKey | String | The crypto key used for the decryption. |
| GCP.KMS.SymmetricDecrypt.ResourceName | String | The full resource name of the crypto key used for the decryption. |
| GCP.KMS.SymmetricDecrypt.Plaintext | String | The decrypted plaintext. Omitted when the decrypted data is binary, in which case it is returned as a file instead. |
| GCP.KMS.SymmetricDecrypt.FullResponse | Unknown | The full API response returned by the decrypt operation. |

### gcp-kms-asymmetric-encrypt

***
Encrypts data with the public key of an asymmetric crypto key version. The encryption is performed locally using the retrieved public key. Required Permissions: cloudkms.cryptoKeyVersions.viewPublicKey.

#### Base Command

`gcp-kms-asymmetric-encrypt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the asymmetric crypto key to encrypt with. | Required |
| crypto_key_version | The ID of the crypto key version to encrypt with. Default is 1. | Optional |
| plaintext | The plaintext to encrypt. Mutually exclusive with base64_plaintext and entry_id. | Optional |
| base64_plaintext | The Base64-encoded plaintext to encrypt. Mutually exclusive with plaintext and entry_id. | Optional |
| entry_id | The War Room entry ID of the file to encrypt. Mutually exclusive with plaintext and base64_plaintext. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.AsymmetricEncrypt.CryptoKey | String | The crypto key used for the encryption. |
| GCP.KMS.AsymmetricEncrypt.CryptoKeyVersion | String | The resource name of the crypto key version used for the encryption. |
| GCP.KMS.AsymmetricEncrypt.Ciphertext | String | The Base64-encoded encrypted ciphertext. |
| GCP.KMS.AsymmetricEncrypt.pem | String | The public key, in PEM format, that was used for the encryption. |
| GCP.KMS.AsymmetricEncrypt.algorithm | String | The algorithm of the public key that was used for the encryption. |
| GCP.KMS.AsymmetricEncrypt.name | String | The resource name of the crypto key version returned by the API. |
| GCP.KMS.AsymmetricEncrypt.protectionLevel | String | The protection level of the crypto key version used for the encryption. |

### gcp-kms-asymmetric-decrypt

***
Decrypts data using an asymmetric crypto key version. Required Permissions: cloudkms.cryptoKeyVersions.useToDecrypt.

#### Base Command

`gcp-kms-asymmetric-decrypt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| location | The geographical region where the Cloud KMS resources are handled. For more information, see https://cloud.google.com/kms/docs/locations. Default is global. | Optional |
| key_ring | The ID of the key ring that holds the crypto key. | Required |
| crypto_key | The ID of the asymmetric crypto key to decrypt with. | Required |
| crypto_key_version | The ID of the crypto key version to decrypt with. Default is 1. | Optional |
| ciphertext | The Base64-encoded ciphertext to decrypt. Mutually exclusive with entry_id. | Optional |
| entry_id | The War Room entry ID of the file holding the raw ciphertext bytes to decrypt. Mutually exclusive with ciphertext. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.KMS.AsymmetricDecrypt.CryptoKey | String | The crypto key used for the decryption. |
| GCP.KMS.AsymmetricDecrypt.CryptoKeyVersion | String | The resource name of the crypto key version used for the decryption. |
| GCP.KMS.AsymmetricDecrypt.Plaintext | String | The decrypted plaintext. Omitted when the decrypted data is binary, in which case it is returned as a file instead. |
| GCP.KMS.AsymmetricDecrypt.plaintextCrc32c | String | The CRC32C checksum of the returned plaintext. |
| GCP.KMS.AsymmetricDecrypt.verifiedCiphertextCrc32c | Boolean | Whether the API verified the CRC32C checksum of the supplied ciphertext. |
| GCP.KMS.AsymmetricDecrypt.protectionLevel | String | The protection level of the crypto key version used for the decryption. |

### gcp-compute-instance-insert

***
Creates a Compute Engine VM instance in the specified project and zone. Returns a zone Operation resource describing the asynchronous creation. Required permission: compute.instances.create.

#### Base Command

`gcp-compute-instance-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| name | The name of the instance to create. | Required |
| machine_type | The machine type. Can be a bare name (for example, n1-standard-1), in which case the zone-qualified URL is built automatically, or a full/partial URL (for example, zones/zone/machineTypes/n1-standard-1). | Required |
| description | The optional description for the instance. | Optional |
| tags | The comma-separated list of network tags to apply to the instance. | Optional |
| tags_fingerprint | The fingerprint hash of the tags contents, used for optimistic locking. | Optional |
| can_ip_forward | Whether the instance is allowed to send and receive packets with non-matching destination or source IPs. Possible values are: true, false. | Optional |
| network | The URL of the network resource for this instance. | Optional |
| subnetwork | The URL of the subnetwork resource for this instance. | Optional |
| network_ip | The IPv4 internal IP address to assign to the instance. | Optional |
| external_internet_access | Whether to grant the instance external internet access by adding a ONE_TO_ONE_NAT access config. Possible values are: true, false. | Optional |
| external_nat_ip | The static external IP address to assign to the instance. Requires the external_internet_access argument. | Optional |
| disk_source | The URL of an existing persistent disk to attach to the instance. | Optional |
| disk_device_name | The unique device name for the attached disk, reflected in the /dev/disk/by-id/google-\* tree. | Optional |
| disk_boot | Whether this is a boot disk. Only one boot disk can be attached to an instance. Possible values are: true, false. | Optional |
| disk_auto_delete | Whether the disk is deleted automatically when the instance is deleted. Possible values are: true, false. | Optional |
| source_image | The source image URL from which to create the boot disk. For example, projects/debian-cloud/global/images/family/debian-11. | Optional |
| disk_size_gb | The size of the boot disk to create, in GB. | Optional |
| disk_type | The disk type URL for the created boot disk, for example zones/zone/diskTypes/pd-standard. | Optional |
| metadata_items | The metadata key/value pairs to assign to the instance, in the format: key=abc,value=123;key=fed,value=456. | Optional |
| service_account_email | The email address of the service account to associate with the instance. Must be provided together with the service_account_scopes argument. | Optional |
| service_account_scopes | A comma-separated list of OAuth2 scopes for the service account. Must be provided together with service_account_email. | Optional |
| labels | The labels to apply to the instance, in the format: key=abc,value=123;key=fed,value=456. | Optional |
| deletion_protection | Whether the instance should be protected against deletion. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The server-defined unique identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides, available only for per-zone operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId if provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation. For example: insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation. Can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. The number monotonically increases as the operation progresses, but is not linear, does not support specific granularity, and should not be used to estimate completion time. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | string | The errors generated during the operation. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails (for example, 404 if the resource is not found). |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails (for example, NOT FOUND). |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides, available only for regional operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-delete

***
Deletes the specified Compute Engine VM instance. Returns a zone Operation resource describing the asynchronous deletion. Required permission: compute.instances.delete.

#### Base Command

`gcp-compute-instance-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the instance resource to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The server-defined unique identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides, available only for per-zone operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId, if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource modified by the operation. For snapshot creation operations, this points to the source persistent disk. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. The number monotonically increases as the operation progresses, but is not linear, does not guarantee specific operation granularity, and should not be used to estimate completion time. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | string | The errors generated during the operation. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails (for example, 404 if the resource is not found). |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails (for example, NOT FOUND). |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides, available only for regional operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-reset

***
Performs a hard reset on the specified Compute Engine VM instance. Returns a zone Operation resource describing the asynchronous reset. Required permission: compute.instances.reset.

#### Base Command

`gcp-compute-instance-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the instance resource to reset. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The server-defined unique identifier for the resource. |
| GCP.Compute.Operations.name | string | The resource name. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides, available only for per-zone operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId, if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource modified by the operation. For snapshot creation operations, this points to the source persistent disk. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. The number monotonically increases as the operation progresses, but is not linear, does not support specific granularity, and should not be used to estimate completion time. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | string | The errors generated during the operation. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails (for example, 404 if the resource is not found). |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails (for example, NOT FOUND). |
| GCP.Compute.Operations.selfLink | string | The server-defined resource URL. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides, available only for regional operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-metadata-set

***
Sets metadata for the specified Compute Engine VM instance. Returns a zone Operation resource describing the asynchronous update. Required permission: compute.instances.setMetadata.

#### Base Command

`gcp-compute-instance-metadata-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the instance resource for which to set metadata. | Required |
| metadata_fingerprint | A fingerprint hash of the metadata's contents, used for optimistic locking. If not provided, the current fingerprint is fetched automatically from the instance (requires the compute.instances.get permission). | Optional |
| metadata_items | The metadata key/value pairs to set on the instance, in the format: key=abc,value=123;key=fed,value=456. This replaces the instance metadata in full rather than merging, so any key that is not listed is removed, including keys such as ssh-keys and startup-script. Pass an empty value to clear all metadata. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The server-defined unique identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides, available only for per-zone operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId, if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource modified by the operation. For snapshot creation operations, this points to the source persistent disk. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | An optional textual description of the current operation status. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. The number monotonically increases as the operation progresses, but is not linear, does not support specific granularity, and should not be used to estimate completion time. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | string | The errors generated during the operation. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails (for example, 404 if the resource is not found). |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails (for example, NOT FOUND). |
| GCP.Compute.Operations.selfLink | string | Server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides, available only for regional operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instances-aggregated-list

***
Retrieves an aggregated list of all Compute Engine VM instances across every zone in the project. Required permission: compute.instances.list.

#### Base Command

`gcp-compute-instances-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| filter | The filter expression for resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value, which can be a string, number, or boolean. For example, to exclude a Compute Engine instance named example-instance, use name != example-instance. | Optional |
| limit | The maximum number of results per page that should be returned. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| order_by | The sort order for list results, defaulting to alphanumerical order by resource name. To sort by creation timestamp in descending order, use order_by=creationTimestamp desc. | Optional |
| next_token | The page token used to retrieve the next page of results. Set next_token to the AggregatedInstancesNextToken value returned from a previous request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Instances.kind | String | Type of the resource. Always compute\#instance for instances. |
| GCP.Compute.Instances.id | String | The unique identifier of the resource. |
| GCP.Compute.Instances.creationTimestamp | String | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Instances.name | String | The name of the resource, provided by the client when the resource is first created. |
| GCP.Compute.Instances.description | String | The optional description for this resource. |
| GCP.Compute.Instances.machineType | String | The full or partial URL of the machine type resource for this instance, in the format: zones/zone/machineTypes/machine-type. |
| GCP.Compute.Instances.status | String | The status of the instance. |
| GCP.Compute.Instances.zone | String | The URL of the zone where the instance resides. |
| GCP.Compute.Instances.tags | String | The tags to apply to this instance. |
| GCP.Compute.Instances.statusMessage | String | The optional, human-readable explanation of the status. |
| GCP.Compute.Instances.canIpForward | String | Allows this instance to send and receive packets with non-matching destination or source IPs. |
| GCP.Compute.Instances.networkInterfaces | Object | The array of network configurations for the instance. |
| GCP.Compute.Instances.disks | Object | The array of disks associated with the instance. |
| GCP.Compute.Instances.metadata | Object | The metadata key/value pairs assigned to the instance. |
| GCP.Compute.Instances.serviceAccounts | Object | The list of service accounts, with their specified scopes, authorized for the instance. |
| GCP.Compute.Instances.selfLink | String | The server-defined resource URL. |
| GCP.Compute.Instances.scheduling | Object | Sets the scheduling options for the instance. |
| GCP.Compute.Instances.cpuPlatform | String | The CPU platform used by the instance. |
| GCP.Compute.Instances.labels | String | The labels to apply to the instance. |
| GCP.Compute.Instances.labelFingerprint | String | The fingerprint for this request, which is a hash of the label's contents and used for optimistic locking. |
| GCP.Compute.Instances.instanceEncryptionKey | Object | Encrypts suspended data for an instance with a customer-managed encryption key. |
| GCP.Compute.Instances.minCpuPlatform | String | Specifies a minimum CPU platform for the VM instance. |
| GCP.Compute.Instances.guestAccelerators | Object | The list of the type and count of accelerator cards attached to the instance. |
| GCP.Compute.Instances.startRestricted | Boolean | Whether a VM has been restricted from starting because Compute Engine detected suspicious activity. |
| GCP.Compute.Instances.deletionProtection | Boolean | Whether the resource should be protected against deletion. |
| GCP.Compute.Instances.resourcePolicies | String | The resource policies applied to this instance. |
| GCP.Compute.Instances.sourceMachineImage | String | The source machine image. |
| GCP.Compute.Instances.reservationAffinity | Object | The reservations that the instance can consume. |
| GCP.Compute.Instances.hostname | String | The hostname of the instance. |
| GCP.Compute.Instances.displayDevice | Object | The display device configuration for the instance. |
| GCP.Compute.Instances.shieldedInstanceConfig | Object | The Shielded VM configuration for the instance. |
| GCP.Compute.Instances.sourceMachineImageEncryptionKey | Object | The source machine image encryption key used when creating an instance from a machine image. |
| GCP.Compute.Instances.confidentialInstanceConfig | Object | The confidential computing configuration for the instance. |
| GCP.Compute.Instances.fingerprint | String | The fingerprint for the resource, which is a hash of the instance contents used for optimistic locking. |
| GCP.Compute.Instances.privateIpv6GoogleAccess | String | The private IPv6 Google access type for the VM. |
| GCP.Compute.Instances.advancedMachineFeatures | Object | The controls for the advanced machine-related behavior features. |
| GCP.Compute.Instances.lastStartTimestamp | String | Last start timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Instances.lastStopTimestamp | String | Last stop timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Instances.lastSuspendedTimestamp | String | Last suspended timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Instances.satisfiesPzs | String | Indicates whether the instance satisfies physical zone separation requirements. |
| GCP.Compute.Instances.satisfiesPzi | String | Indicates whether the instance satisfies physical zone isolation requirements. |
| GCP.Compute.Instances.resourceStatus | Object | The resource status. |
| GCP.Compute.Instances.networkPerformanceConfig | Object | The network performance configuration. |
| GCP.Compute.Instances.keyRevocationActionType | String | The KeyRevocationActionType of the instance. |
| GCP.Compute.AggregatedInstancesNextToken | String | The token to use to retrieve the next page of aggregated instances results. |

### gcp-compute-instance-machine-type-set

***
Changes the machine type of a stopped Compute Engine VM instance. Returns a zone Operation resource describing the asynchronous update. Required permission: compute.instances.setMachineType.

#### Base Command

`gcp-compute-instance-machine-type-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the instance resource for which to set the machine type. | Required |
| machine_type | The machine type. Can be a bare name (for example, n1-standard-1), in which case the zone-qualified URL is built automatically, or a full/partial URL (for example, zones/zone/machineTypes/n1-standard-1). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The server-defined unique identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides, available only for per-zone operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of requestId, if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete, and so on. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | An optional progress indicator that ranges from 0 to 100. There is no requirement that this be linear or support any granularity of operations. This should not be used to guess when the operation will be complete. This number should monotonically increase as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed. This value is in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | string | The errors generated during the operation. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails (for example, 404 if the resource is not found). |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails (for example, NOT FOUND). |
| GCP.Compute.Operations.selfLink | string | The server-defined resource URL. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides, available only for regional operations. This must be specified in the HTTP request URL and is not configurable in the request body. |
| GCP.Compute.Operations.description | string | A textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | Type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-image-delete

***
Deletes the specified image. Required permission: compute.images.delete.

#### Base Command

`gcp-compute-image-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version >=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version < 3.0, where it can be retrieved from the integration configuration. | Optional |
| image | The name of the image resource to delete. | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-images-list

***
Lists images in a specific project. Required permission: compute.images.list.

#### Base Command

`gcp-compute-images-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version >=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version < 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return. Can be 1 to 500. Default is 50. | Optional |
| next_token | The token for the next set of items to return, used for pagination. | Optional |
| filter | The filter expression for resources listed in the response. Must specify a field name, a comparison operator (=, !=, >, or <), and a value. | Optional |
| order_by | The order used to sort list results. By default, results are returned in alphanumeric order based on the resource name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Images.kind | String | The type of the resource. Always set to compute#image for images. |
| GCP.Compute.Images.id | String | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Images.creationTimestamp | Date | The creation timestamp in RFC3339 format. |
| GCP.Compute.Images.name | String | The name of the resource, provided by the client when the resource is created. |
| GCP.Compute.Images.description | String | The optional description of this resource. |
| GCP.Compute.Images.sourceType | String | The type of image used to create this disk. The default and only value is RAW. |
| GCP.Compute.Images.rawDisk.source | String | The full Google Cloud Storage URL where the disk image is stored. |
| GCP.Compute.Images.rawDisk.sha1Checksum | String | The optional SHA1 checksum of the disk image before unpackaging, provided by the client when the disk image is created. |
| GCP.Compute.Images.rawDisk.containerType | String | The format used to encode and transmit the block device, which should be TAR. |
| GCP.Compute.Images.deprecated.state | String | The deprecation state of this resource. Can be ACTIVE, DEPRECATED, OBSOLETE, or DELETED. |
| GCP.Compute.Images.deprecated.replacement | String | The URL of the suggested replacement for a deprecated resource. |
| GCP.Compute.Images.deprecated.deprecated | Date | The RFC3339 timestamp on or after which the state of this resource changes to DEPRECATED. |
| GCP.Compute.Images.deprecated.obsolete | Date | The RFC3339 timestamp on or after which the state of this resource changes to OBSOLETE. |
| GCP.Compute.Images.deprecated.deleted | Date | The RFC3339 timestamp on or after which the state of this resource changes to DELETED. |
| GCP.Compute.Images.status | String | The status of the image. Can be FAILED, PENDING, or READY. |
| GCP.Compute.Images.archiveSizeBytes | String | The size, in bytes, of the image tar.gz archive stored in Google Cloud Storage. |
| GCP.Compute.Images.diskSizeGb | String | The size, in GB, of the image when restored onto a persistent disk. |
| GCP.Compute.Images.sourceDisk | String | The URL of the source disk used to create this image. |
| GCP.Compute.Images.sourceDiskId | String | The ID value of the disk used to create this image. |
| GCP.Compute.Images.sourceDiskEncryptionKey.kmsKeyName | String | The name of the encryption key of the source disk that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceDiskEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source disk. |
| GCP.Compute.Images.sourceImage | String | The URL of the source image used to create this image. |
| GCP.Compute.Images.sourceImageId | String | The ID value of the image used to create this image. |
| GCP.Compute.Images.sourceImageEncryptionKey.kmsKeyName | String | The name of the encryption key of the source image that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceImageEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source image. |
| GCP.Compute.Images.sourceSnapshot | String | The URL of the source snapshot used to create this image. |
| GCP.Compute.Images.sourceSnapshotId | String | The ID value of the snapshot used to create this image. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.kmsKeyName | String | The name of the encryption key of the source snapshot that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source snapshot. |
| GCP.Compute.Images.imageEncryptionKey.kmsKeyName | String | The name of the encryption key of the image that is stored in Google Cloud KMS. |
| GCP.Compute.Images.imageEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the image. |
| GCP.Compute.Images.licenses | String | The applicable license URIs. |
| GCP.Compute.Images.licenseCodes | String | The integer license codes indicating which licenses are attached to this image. |
| GCP.Compute.Images.family | String | The name of the image family to which this image belongs. |
| GCP.Compute.Images.labels | Unknown | The labels applied to this image. |
| GCP.Compute.Images.labelFingerprint | String | The fingerprint of the labels applied to this image, which is used for optimistic locking. |
| GCP.Compute.Images.guestOsFeatures.type | String | The ID of the supported guest operating system feature. |
| GCP.Compute.Images.shieldedInstanceInitialState | Unknown | The initial state for the image, which is used by Shielded VM instances on boot. |
| GCP.Compute.Images.storageLocations | String | The Cloud Storage location, either regional or multi-regional, where the image content is stored. |
| GCP.Compute.Images.architecture | String | The architecture of the image. Can be ARM64 or X86_64. |
| GCP.Compute.Images.enableConfidentialCompute | Boolean | Whether the image is created from a confidential compute mode disk. |
| GCP.Compute.Images.satisfiesPzs | Boolean | Whether the resource satisfies physical zone separation. |
| GCP.Compute.Images.satisfiesPzi | Boolean | Whether the resource satisfies physical zone isolation. |
| GCP.Compute.Images.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.ImagesNextToken | String | The token to use as the next_token argument to retrieve the next page of results. |

### gcp-compute-image-insert

***
Creates an image in the specified project using the data included in the request. Required permission: compute.images.create.

#### Base Command

`gcp-compute-image-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version >=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version < 3.0, where it can be retrieved from the integration configuration. | Optional |
| name | The name of the resource; provided by the client when the resource is created. | Required |
| force_create | Whether to attempt to create the image even if OS features or license validation fails. Possible values are: true, false. | Optional |
| description | The optional description of this resource. | Optional |
| raw_disk_source | The full Google Cloud Storage URL where the disk image is stored. | Optional |
| raw_disk_sha1_checksum | The optional SHA1 checksum of the disk image before unpackaging. | Optional |
| raw_disk_container_type | The format used to encode and transmit the block device, which should be TAR. Possible values are: TAR. | Optional |
| deprecated_state | The deprecation state of this resource. Can be ACTIVE, DEPRECATED, OBSOLETE, or DELETED. Possible values are: ACTIVE, DEPRECATED, OBSOLETE, DELETED. | Optional |
| deprecated_replacement | The URL of the suggested replacement for a deprecated resource. | Optional |
| archive_size_bytes | The size, in bytes, of the image tar.gz archive stored in Google Cloud Storage. | Optional |
| disk_size_gb | The size, in GB, of the image when restored onto a persistent disk. | Optional |
| source_disk | The URL of the source disk used to create this image. This property or the raw_disk_source property must be provided, but not both. | Optional |
| licenses | A comma-separated list of applicable license URIs. | Optional |
| family | The name of the image family to which this image belongs. | Optional |
| image_encryption_key_raw_key | The 256-bit customer-supplied encryption key (RFC 4648 base64) for the image. | Optional |
| image_encryption_key_kms_key_name | The name of the encryption key that is stored in Google Cloud KMS for the image. | Optional |
| source_disk_encryption_key_raw_key | The 256-bit customer-supplied encryption key (RFC 4648 base64) of the source disk. | Optional |
| source_disk_encryption_key_kms_key_name | The name of the encryption key stored in Google Cloud KMS of the source disk. | Optional |
| labels | The list of labels to apply for this resource, in tuples, for example, key=abc,value=123;key=def,value=456. | Optional |
| label_fingerprint | The fingerprint of the previous set of labels for this resource. | Optional |
| guest_os_features | The comma-separated list of guest OS features to enable on the image. | Optional |
| license_codes | The comma-separated list of integer license codes indicating which licenses are attached to this image. | Optional |
| source_image | The URL of the source image used to create this image. | Optional |
| source_image_encryption_key_kms_key_name | The name of the encryption key stored in Google Cloud KMS of the source image. | Optional |
| source_snapshot | The URL of the source snapshot used to create this image. | Optional |
| source_snapshot_encryption_key_raw_key | The 256-bit customer-supplied encryption key (RFC 4648 base64) of the source snapshot. | Optional |
| source_snapshot_encryption_key_kms_key_name | The name of the encryption key stored in Google Cloud KMS of the source snapshot. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.kind | String | The type of the resource. Always set to compute#operation for operation resources. |
| GCP.Compute.Operations.id | String | The unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. Only available when performing per-zone operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of requestId if it was provided in the request. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Can be PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example EMAILADDRESS. |
| GCP.Compute.Operations.progress | Number | The progress of the operation as a percentage from 0 to 100. |
| GCP.Compute.Operations.insertTime | Date | The time the operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | Date | The time the operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | Date | The time the operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during the processing of the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only available when performing regional operations. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |

### gcp-compute-image-labels-set

***
Sets the labels on an image. Required permission: compute.images.setLabels.

#### Base Command

`gcp-compute-image-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version >=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version < 3.0, where it can be retrieved from the integration configuration. | Optional |
| image | The name of the image resource on which to set labels. | Required |
| labels | The list of labels to apply to this resource, formatted as tuples, for example, key=abc,value=123;key=def,value=456. | Required |
| label_fingerprint | The fingerprint of the previous set of labels for this resource, used to detect conflicts. The fingerprint is initially generated by Compute Engine and changes after every request to modify or update labels. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.kind | String | The type of the resource. Always set to compute#operation for operation resources. |
| GCP.Compute.Operations.id | String | The unique identifier for the operation resource, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. Only available when performing per-zone operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of the requestId if provided in the request. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Can be PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example EMAILADDRESS. |
| GCP.Compute.Operations.progress | Number | The progress of the operation as a percentage from 0 to 100. |
| GCP.Compute.Operations.insertTime | Date | The time the operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | Date | The time the operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | Date | The time the operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during the processing of the operation. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only available when performing regional operations. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |

### gcp-compute-image-get-from-family

***
Returns the latest non-deprecated image from an image family. Required permission: compute.images.get.

#### Base Command

`gcp-compute-image-get-from-family`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version >=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version < 3.0, where it can be retrieved from the integration configuration. | Optional |
| family | The name of the image family to search for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Images.kind | String | The type of the resource. Always set to compute#image for images. |
| GCP.Compute.Images.id | String | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Images.creationTimestamp | Date | The creation timestamp in RFC3339 format. |
| GCP.Compute.Images.name | String | The name of the resource, provided by the client when the resource is created. |
| GCP.Compute.Images.description | String | The optional description of this resource. |
| GCP.Compute.Images.sourceType | String | The type of image used to create this disk. The default and only value is RAW. |
| GCP.Compute.Images.rawDisk.source | String | The full Google Cloud Storage URL where the disk image is stored. |
| GCP.Compute.Images.rawDisk.sha1Checksum | String | The optional SHA1 checksum of the disk image before unpackaging, provided by the client when the disk image is created. |
| GCP.Compute.Images.rawDisk.containerType | String | The format used to encode and transmit the block device, which should be TAR. |
| GCP.Compute.Images.deprecated.state | String | The deprecation state of this resource. Can be ACTIVE, DEPRECATED, OBSOLETE, or DELETED. |
| GCP.Compute.Images.deprecated.replacement | String | The URL of the suggested replacement for a deprecated resource. |
| GCP.Compute.Images.deprecated.deprecated | Date | The RFC3339 timestamp on or after which the state of this resource changes to DEPRECATED. |
| GCP.Compute.Images.deprecated.obsolete | Date | The RFC3339 timestamp on or after which the state of this resource changes to OBSOLETE. |
| GCP.Compute.Images.deprecated.deleted | Date | The RFC3339 timestamp on or after which the state of this resource changes to DELETED. |
| GCP.Compute.Images.status | String | The status of the image. Can be FAILED, PENDING, or READY. |
| GCP.Compute.Images.archiveSizeBytes | String | The size, in bytes, of the tar.gz image archive stored in Google Cloud Storage. |
| GCP.Compute.Images.diskSizeGb | String | The size of the image in GB when restored onto a persistent disk. |
| GCP.Compute.Images.sourceDisk | String | The URL of the source disk used to create this image. |
| GCP.Compute.Images.sourceDiskId | String | The ID value of the disk used to create this image. |
| GCP.Compute.Images.sourceDiskEncryptionKey.kmsKeyName | String | The name of the encryption key of the source disk that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceDiskEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source disk. |
| GCP.Compute.Images.sourceImage | String | The URL of the source image used to create this image. |
| GCP.Compute.Images.sourceImageId | String | The ID value of the image used to create this image. |
| GCP.Compute.Images.sourceImageEncryptionKey.kmsKeyName | String | The name of the encryption key of the source image that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceImageEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source image. |
| GCP.Compute.Images.sourceSnapshot | String | The URL of the source snapshot used to create this image. |
| GCP.Compute.Images.sourceSnapshotId | String | The ID value of the snapshot used to create this image. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.kmsKeyName | String | The name of the encryption key of the source snapshot that is stored in Google Cloud KMS. |
| GCP.Compute.Images.sourceSnapshotEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the source snapshot. |
| GCP.Compute.Images.imageEncryptionKey.kmsKeyName | String | The name of the encryption key of the image that is stored in Google Cloud KMS. |
| GCP.Compute.Images.imageEncryptionKey.sha256 | String | The RFC 4648 base64-encoded SHA-256 hash of the customer-supplied encryption key that protects the image. |
| GCP.Compute.Images.licenses | String | The applicable license URIs. |
| GCP.Compute.Images.licenseCodes | String | The integer license codes indicating which licenses are attached to this image. |
| GCP.Compute.Images.family | String | The name of the image family to which this image belongs. |
| GCP.Compute.Images.labels | Unknown | The labels applied to this image. |
| GCP.Compute.Images.labelFingerprint | String | The fingerprint of the labels applied to this image, which is used for optimistic locking. |
| GCP.Compute.Images.guestOsFeatures.type | String | The ID of the supported guest operating system feature. |
| GCP.Compute.Images.shieldedInstanceInitialState | Unknown | The initial state for the image, which is used by Shielded VM instances on boot. |
| GCP.Compute.Images.storageLocations | String | The Cloud Storage location, either regional or multi-regional, where the image content is stored. |
| GCP.Compute.Images.architecture | String | The architecture of the image. Can be ARM64 or X86_64. |
| GCP.Compute.Images.enableConfidentialCompute | Boolean | Whether the image is created from a confidential compute mode disk. |
| GCP.Compute.Images.satisfiesPzs | Boolean | Whether the resource satisfies physical zone separation. |
| GCP.Compute.Images.satisfiesPzi | Boolean | Whether the resource satisfies physical zone isolation. |
| GCP.Compute.Images.selfLink | String | The server-defined URL for the resource. |

### gcp-compute-network-delete

***
Deletes the specified network. Required permission: compute.networks.delete.

#### Base Command

`gcp-compute-network-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| network | The name of the network to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique server-defined identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The progress indicator, ranging from 0 to 100. There is no requirement that this be linear or support any granularity of operations. Must not be used to guess when the operation will be completed. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error | string | The errors generated during processing of the operation, if any. Populated when errors occur. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during processing of the operation, if any. Populated when warnings occur. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-network-peering-add

***
Adds a peering connection to the specified network. Required permission: compute.networks.addPeering.

#### Base Command

`gcp-compute-network-peering-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| network | The name of the network resource to which to add a peering connection. | Required |
| name | The name of the peering connection. The name must comply with RFC1035 (the Internet standard for domain name syntax and conventions). Specifically, the name must be 1-63 characters long and match the regular expression [a-z]([-a-z0-9]*[a-z0-9])? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. | Required |
| peer_network | The URL of the peer network. Can be a full URL or a partial URL. The peer network can belong to a different project. If the partial URL does not contain a project, the peer network is assumed to be in the same project as the current network. | Required |
| exchange_subnet_routes | Whether full mesh connectivity is created and managed automatically between peered networks. Currently, this field should always be set to true because Google Compute Engine automatically creates and manages subnetwork routes between two networks when the peering state is ACTIVE. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique server-defined identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The progress indicator, ranging from 0 to 100. There is no requirement that this be linear or support any granularity of operations. Must not be used to guess when the operation will be completed. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The date and time when the operation was requested, in RFC3339 format; for example, 2024-01-15T12:34:56Z. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error | string | The errors generated during processing of the operation, if any. Populated when errors occur. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during processing of the operation, if any. Populated when warnings occur. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-network-peering-remove

***
Removes a peering connection from the specified network. Required permission: compute.networks.removePeering.

#### Base Command

`gcp-compute-network-peering-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| network | The name of the network resource from which to remove the peering connection. | Required |
| name | The name of the peering connection to remove. The name must comply with RFC1035 (the Internet standard for domain name syntax and conventions). Specifically, the name must be 1-63 characters long and match the regular expression [a-z]([-a-z0-9]*[a-z0-9])? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique server-defined identifier for the resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. Only available when performing per-zone operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.clientOperationId | string | The value of the requestId if provided in the request. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the persistent disk from which the snapshot was created. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING RUNNING or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The progress indicator, ranging from 0 to 100. There is no requirement that this be linear or support any granularity of operations. Must not be used to guess when the operation will be completed. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | string | The time that this operation was requested, in RFC3339 format. |
| GCP.Compute.Operations.startTime | string | The time that this operation was started by the server, in RFC3339 format. |
| GCP.Compute.Operations.endTime | string | The time that this operation was completed, in RFC3339 format. |
| GCP.Compute.Operations.error | string | The errors generated during processing of the operation, if any. Populated when errors occur. |
| GCP.Compute.Operations.warnings | string | The warning messages generated during processing of the operation, if any. Populated when warnings occur. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. For example, a 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. Must be specified as part of the HTTP request URL and cannot be set as a field in the request body. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource, which is always compute\#operation for Operation resources. |

### gcp-compute-global-address-get

***
Returns the specified global address resource. Required permission: compute.globalAddresses.get.

#### Base Command

`gcp-compute-global-address-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| address | The name of the address resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Addresses.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Addresses.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Addresses.name | string | The name of the resource. |
| GCP.Compute.Addresses.description | string | The optional description of this resource. |
| GCP.Compute.Addresses.address | string | The static IP address represented by this resource. |
| GCP.Compute.Addresses.prefixLength | number | The prefix length if the resource represents an IP range. |
| GCP.Compute.Addresses.status | string | The status of the address. Possible values are RESERVING, RESERVED, or IN_USE. |
| GCP.Compute.Addresses.users | string | The URLs of the resources that are using this address. |
| GCP.Compute.Addresses.networkTier | string | The networking tier used for configuring this address. Possible values are PREMIUM or STANDARD. |
| GCP.Compute.Addresses.addressType | string | The type of address to reserve. Possible values are INTERNAL or EXTERNAL. |
| GCP.Compute.Addresses.purpose | string | The purpose of this resource, which can be used for network load balancing or other purposes. |
| GCP.Compute.Addresses.subnetwork | string | The URL of the subnetwork in which to reserve the address. |
| GCP.Compute.Addresses.ipv6EndpointType | string | The endpoint type of this address, which can be VM or NETLB. Used to decide which type of endpoint this address can be used for after the external IPv6 address reservation. |
| GCP.Compute.Addresses.labels | Unknown | The labels applied to this resource. These can only be added or modified by the setLabels method. |
| GCP.Compute.Addresses.labelFingerprint | string | The fingerprint for the labels applied to this address, used for optimistic locking. Provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Addresses.network | string | The URL of the network in which to reserve the address. |
| GCP.Compute.Addresses.ipCollection | string | The URL of the source of external IPv4 addresses, such as a public delegated prefix \(PDP\) used for bring your own IP \(BYOIP\). |
| GCP.Compute.Addresses.ipVersion | string | The IP version that will be used by this address. |
| GCP.Compute.Addresses.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Addresses.kind | string | The type of the resource. Always compute\#address for addresses. |

### gcp-compute-global-address-list

***
Retrieves the list of global address resources. Required permission: compute.globalAddresses.list.

#### Base Command

`gcp-compute-global-address-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| filter | The filter expression that filters resources listed in the response. | Optional |
| order_by | The order by which to sort list results. By default, results are returned in alphanumerical order based on the resource name. | Optional |
| next_token | The token for the next set of items to return, used for pagination. Set this to the value of GCP.Compute.GlobalAddressesNextToken returned by a previous list request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Addresses.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Addresses.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Addresses.name | string | The name of the resource. |
| GCP.Compute.Addresses.description | string | The optional description of this resource. |
| GCP.Compute.Addresses.address | string | The static IP address represented by this resource. |
| GCP.Compute.Addresses.prefixLength | number | The prefix length if the resource represents an IP range. |
| GCP.Compute.Addresses.status | string | The status of the address. Possible values are RESERVING, RESERVED, or IN_USE. |
| GCP.Compute.Addresses.users | string | The URLs of the resources that are using this address. |
| GCP.Compute.Addresses.networkTier | string | The networking tier used for configuring this address. Possible values are PREMIUM or STANDARD. |
| GCP.Compute.Addresses.addressType | string | The type of address to reserve. Possible values are INTERNAL or EXTERNAL. |
| GCP.Compute.Addresses.purpose | string | The purpose of this resource, which can be used for network load balancing or other purposes. |
| GCP.Compute.Addresses.subnetwork | string | The URL of the subnetwork in which to reserve the address. |
| GCP.Compute.Addresses.ipVersion | string | The IP version used by this address. Possible values are IPV4 or IPV6. |
| GCP.Compute.Addresses.ipv6EndpointType | string | The endpoint type of this address, which can be VM or NETLB. Used to decide which type of endpoint this address can be used for after the external IPv6 address reservation. |
| GCP.Compute.Addresses.labels | Unknown | The labels applied to this resource. These can only be added or modified by the setLabels method. |
| GCP.Compute.Addresses.labelFingerprint | string | The fingerprint for the labels applied to this address, used for optimistic locking. Provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Addresses.network | string | The URL of the network in which to reserve the address. |
| GCP.Compute.Addresses.ipCollection | string | The URL of the source of external IPv4 addresses, such as a public delegated prefix \(PDP\) used for bring your own IP \(BYOIP\). |
| GCP.Compute.Addresses.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Addresses.kind | string | The type of the resource. Always compute\#address for addresses. |
| GCP.Compute.GlobalAddressesNextToken | string | The token used to retrieve the next page of results for list requests. |

### gcp-compute-address-insert

***
Creates a regional address resource in the specified project using the data included in the request. Required permission: compute.addresses.create.

#### Base Command

`gcp-compute-address-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| name | The name of the address resource to create. | Required |
| description | The optional description of this resource. | Optional |
| address | The static IP address to reserve. If not specified, an unused ephemeral IP address is assigned. | Optional |
| prefix_length | The prefix length if the resource represents an IP range. | Optional |
| network_tier | The networking tier used for configuring this address. Possible values are: PREMIUM, STANDARD. | Optional |
| address_type | The type of address to reserve. Possible values are: INTERNAL, EXTERNAL. | Optional |
| purpose | The purpose of this resource, such as GCE_ENDPOINT, SHARED_LOADBALANCER_VIP, or VPC_PEERING. | Optional |
| subnetwork | The URL of the subnetwork in which to reserve the address. Required if the address type is INTERNAL. | Optional |
| network | The URL of the network in which to reserve the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.clientOperationId | string | The value of the request ID if provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, if any. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, if any. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails. For example, 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-global-address-insert

***
Creates a global address resource in the specified project using the data included in the request. Required permission: compute.globalAddresses.create.

#### Base Command

`gcp-compute-global-address-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| name | The name of the address resource to create. | Required |
| description | The optional description of this resource. | Optional |
| address | The static IP address to reserve. If not specified, an unused ephemeral IP address is assigned. | Optional |
| prefix_length | The prefix length if the resource represents an IP range. | Optional |
| network_tier | The networking tier used for configuring this address. Possible values are: PREMIUM, STANDARD. | Optional |
| ip_version | The IP version that will be used by this address. Possible values are: IPV4, IPV6. | Optional |
| address_type | The type of address to reserve. Possible values are: INTERNAL, EXTERNAL. | Optional |
| purpose | The purpose of this resource, such as GCE_ENDPOINT, SHARED_LOADBALANCER_VIP, or VPC_PEERING. | Optional |
| subnetwork | The URL of the subnetwork in which to reserve the address. Required if the address type is INTERNAL. | Optional |
| network | The URL of the network in which to reserve the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.clientOperationId | string | The value of the request ID if provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, if any. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, if any. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails. For example, 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-address-aggregated-list

***
Retrieves an aggregated list of regional address resources across all regions. Required permission: compute.addresses.list.

#### Base Command

`gcp-compute-address-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| filter | The filter expression that filters resources listed in the response. | Optional |
| order_by | The order by which to sort list results. By default, results are returned in alphanumerical order based on the resource name. | Optional |
| next_token | The token for the next set of items to return, used for pagination. Set this to the value of GCP.Compute.AggregatedAddressesNextToken returned by a previous list request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Addresses.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Addresses.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Addresses.name | string | The name of the resource. |
| GCP.Compute.Addresses.description | string | The optional description of this resource. |
| GCP.Compute.Addresses.address | string | The static IP address represented by this resource. |
| GCP.Compute.Addresses.prefixLength | number | The prefix length if the resource represents an IP range. |
| GCP.Compute.Addresses.status | string | The status of the address. Possible values are RESERVING, RESERVED, or IN_USE. |
| GCP.Compute.Addresses.region | string | The URL of the region where a regional address resides. |
| GCP.Compute.Addresses.users | string | The URLs of the resources that are using this address. |
| GCP.Compute.Addresses.networkTier | string | The networking tier used for configuring this address. Possible values are PREMIUM or STANDARD. |
| GCP.Compute.Addresses.addressType | string | The type of address to reserve. Possible values are INTERNAL or EXTERNAL. |
| GCP.Compute.Addresses.purpose | string | The purpose of this resource, which can be used for network load balancing or other purposes. |
| GCP.Compute.Addresses.subnetwork | string | The URL of the subnetwork in which to reserve the address. |
| GCP.Compute.Addresses.ipVersion | string | The IP version used by this address. Possible values are IPV4 or IPV6. |
| GCP.Compute.Addresses.ipv6EndpointType | string | The endpoint type of this address, which can be VM or NETLB. Used to decide which type of endpoint this address can be used for after the external IPv6 address reservation. |
| GCP.Compute.Addresses.labels | Unknown | The labels applied to this resource. These can only be added or modified by the setLabels method. |
| GCP.Compute.Addresses.labelFingerprint | string | The fingerprint for the labels applied to this address, used for optimistic locking. Provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Addresses.network | string | The URL of the network in which to reserve the address. |
| GCP.Compute.Addresses.ipCollection | string | The URL of the source of external IPv4 addresses, such as a public delegated prefix \(PDP\) used for bring your own IP \(BYOIP\). |
| GCP.Compute.Addresses.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Addresses.kind | string | The type of the resource. Always compute\#address for addresses. |
| GCP.Compute.AggregatedAddressesNextToken | string | The token used to retrieve the next page of results for list requests. |

### gcp-compute-address-delete

***
Deletes the specified regional address resource. Required permission: compute.addresses.delete.

#### Base Command

`gcp-compute-address-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| address | The name of the address resource to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.clientOperationId | string | The value of the request ID if provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, if any. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, if any. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails. For example, 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.region | string | The URL of the region where the operation resides. Only available when performing regional operations. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-address-get

***
Returns the specified regional address resource. Required permission: compute.addresses.get.

#### Base Command

`gcp-compute-address-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| address | The name of the address resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Addresses.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Addresses.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Addresses.name | string | The name of the resource. |
| GCP.Compute.Addresses.description | string | The optional description of this resource. |
| GCP.Compute.Addresses.address | string | The static IP address represented by this resource. |
| GCP.Compute.Addresses.prefixLength | number | The prefix length if the resource represents an IP range. |
| GCP.Compute.Addresses.status | string | The status of the address. Possible values are RESERVING, RESERVED, or IN_USE. |
| GCP.Compute.Addresses.region | string | The URL of the region where a regional address resides. |
| GCP.Compute.Addresses.users | string | The URLs of the resources that are using this address. |
| GCP.Compute.Addresses.networkTier | string | The networking tier used for configuring this address. Possible values are PREMIUM or STANDARD. |
| GCP.Compute.Addresses.addressType | string | The type of address to reserve. Possible values are INTERNAL or EXTERNAL. |
| GCP.Compute.Addresses.purpose | string | The purpose of this resource, which can be used for network load balancing or other purposes. |
| GCP.Compute.Addresses.subnetwork | string | The URL of the subnetwork in which to reserve the address. |
| GCP.Compute.Addresses.ipv6EndpointType | string | The endpoint type of this address, which can be VM or NETLB. Used to decide which type of endpoint this address can be used for after the external IPv6 address reservation. |
| GCP.Compute.Addresses.labels | Unknown | The labels applied to this resource. These can only be added or modified by the setLabels method. |
| GCP.Compute.Addresses.labelFingerprint | string | The fingerprint for the labels applied to this address, used for optimistic locking. Provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Addresses.network | string | The URL of the network in which to reserve the address. |
| GCP.Compute.Addresses.ipCollection | string | The URL of the source of external IPv4 addresses, such as a public delegated prefix \(PDP\) used for bring your own IP \(BYOIP\). |
| GCP.Compute.Addresses.ipVersion | string | The IP version that will be used by this address. |
| GCP.Compute.Addresses.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Addresses.kind | string | The type of the resource. Always compute\#address for addresses. |

### gcp-compute-address-list

***
Retrieves the list of regional address resources in the specified region. Required permission: compute.addresses.list.

#### Base Command

`gcp-compute-address-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| filter | The filter expression that filters resources listed in the response. | Optional |
| order_by | The order by which to sort list results. By default, results are returned in alphanumerical order based on the resource name. | Optional |
| next_token | The token for the next set of items to return, used for pagination. Set this to the value of GCP.Compute.AddressesNextToken returned by a previous list request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Addresses.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Addresses.creationTimestamp | string | The creation timestamp in RFC3339 text format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Addresses.name | string | The name of the resource. |
| GCP.Compute.Addresses.description | string | The optional description of this resource. |
| GCP.Compute.Addresses.address | string | The static IP address represented by this resource. |
| GCP.Compute.Addresses.prefixLength | number | The prefix length if the resource represents an IP range. |
| GCP.Compute.Addresses.status | string | The status of the address. Possible values are RESERVING, RESERVED, or IN_USE. |
| GCP.Compute.Addresses.region | string | The URL of the region where a regional address resides. |
| GCP.Compute.Addresses.users | string | The URLs of the resources that are using this address. |
| GCP.Compute.Addresses.networkTier | string | The networking tier used for configuring this address. Possible values are PREMIUM or STANDARD. |
| GCP.Compute.Addresses.addressType | string | The type of address to reserve. Possible values are INTERNAL or EXTERNAL. |
| GCP.Compute.Addresses.purpose | string | The purpose of this resource, which can be used for network load balancing or other purposes. |
| GCP.Compute.Addresses.subnetwork | string | The URL of the subnetwork in which to reserve the address. |
| GCP.Compute.Addresses.ipVersion | string | The IP version used by this address. Possible values are IPV4 or IPV6. |
| GCP.Compute.Addresses.ipv6EndpointType | string | The endpoint type of this address, which can be VM or NETLB. Used to decide which type of endpoint this address can be used for after the external IPv6 address reservation. |
| GCP.Compute.Addresses.labels | Unknown | The labels applied to this resource. These can only be added or modified by the setLabels method. |
| GCP.Compute.Addresses.labelFingerprint | string | The fingerprint for the labels applied to this address, used for optimistic locking. Provide an up-to-date fingerprint hash in order to update or change labels. |
| GCP.Compute.Addresses.network | string | The URL of the network in which to reserve the address. |
| GCP.Compute.Addresses.ipCollection | string | The URL of the source of external IPv4 addresses, such as a public delegated prefix \(PDP\) used for bring your own IP \(BYOIP\). |
| GCP.Compute.Addresses.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Addresses.kind | string | The type of the resource. Always compute\#address for addresses. |
| GCP.Compute.AddressesNextToken | string | The token used to retrieve the next page of results for list requests. |

### gcp-compute-global-address-delete

***
Deletes the specified global address resource. Required permission: compute.globalAddresses.delete.

#### Base Command

`gcp-compute-global-address-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| address | The name of the address resource to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the resource, defined by the server. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.clientOperationId | string | The value of the request ID if provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation, for example, EMAILADDRESS. |
| GCP.Compute.Operations.progress | number | The optional progress indicator, ranging from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | string | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | string | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, if any. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, if any. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code returned if the operation fails. For example, 404 means the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | string | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.kind | string | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-disks-list

***
Retrieves a list of persistent disks contained within the specified zone. Required permission: compute.disks.list.

#### Base Command

`gcp-compute-disks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| next_token | The token for pagination. Set it to the value of GCP.Compute.DisksNextToken returned by a previous request to get the next page of results. | Optional |
| filter | The filter expression for resources listed in the response. The expression must specify a field name, a comparison operator \(=, !=, &gt;, or &lt;\), and a value, which can be a string, number, or boolean. For example, to exclude a disk named example-disk, use name != example-disk. | Optional |
| order_by | The order in which to sort the list results. By default, results are returned in alphanumerical order based on the resource name. Results can also be sorted in descending order based on the creation timestamp using creationTimestamp desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Disks.id | String | The unique identifier for the disk resource. |
| GCP.Compute.Disks.name | String | The name of the disk resource. |
| GCP.Compute.Disks.kind | String | The type of the resource, for example compute\#disk. |
| GCP.Compute.Disks.description | String | The optional description of the disk. |
| GCP.Compute.Disks.status | String | The status of disk creation, such as READY or CREATING. |
| GCP.Compute.Disks.sizeGb | String | The size of the persistent disk, specified in GB. |
| GCP.Compute.Disks.type | String | The URL of the disk type resource describing which disk type is used by this disk. |
| GCP.Compute.Disks.zone | String | The URL of the zone where the disk resides. |
| GCP.Compute.Disks.region | String | The URL of the region where the disk resides. Only applicable for regional resources. |
| GCP.Compute.Disks.creationTimestamp | Date | The creation timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastAttachTimestamp | Date | The last attach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastDetachTimestamp | Date | The last detach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.users | Unknown | The links to the instances to which the disk is attached. |
| GCP.Compute.Disks.licenses | Unknown | The list of publicly visible licenses attached to the disk. |
| GCP.Compute.Disks.licenseCodes | Unknown | The integer license codes indicating which licenses are attached to the disk. |
| GCP.Compute.Disks.guestOsFeatures | Unknown | The list of features to enable on the guest operating system, each containing a type field. |
| GCP.Compute.Disks.labels | Unknown | The labels applied to the disk as key-value pairs. |
| GCP.Compute.Disks.labelFingerprint | String | The fingerprint for the labels applied to the disk, used for optimistic locking. |
| GCP.Compute.Disks.sourceImage | String | The source image used to create this disk. |
| GCP.Compute.Disks.sourceImageId | String | The ID value of the image used to create this disk. |
| GCP.Compute.Disks.sourceSnapshot | String | The source snapshot used to create this disk. |
| GCP.Compute.Disks.sourceSnapshotId | String | The unique ID of the snapshot used to create this disk. |
| GCP.Compute.Disks.diskEncryptionKey | Unknown | The customer-supplied encryption key of the disk, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceImageEncryptionKey | Unknown | The customer-supplied encryption key of the source image, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceSnapshotEncryptionKey | Unknown | The customer-supplied encryption key of the source snapshot, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.replicaZones | Unknown | The URLs of the zones where the disk is replicated. Only applicable for regional resources. |
| GCP.Compute.Disks.physicalBlockSizeBytes | String | The physical block size of the persistent disk, in bytes. |
| GCP.Compute.Disks.selfLink | String | The server-defined URL for the disk resource. |
| GCP.Compute.Disks.accessMode | String | The access mode of the disk, such as READ_WRITE_SINGLE, READ_WRITE_MANY, or READ_ONLY_MANY. |
| GCP.Compute.Disks.architecture | String | The architecture of the disk. Valid values are ARM64 or X86_64. |
| GCP.Compute.Disks.asyncPrimaryDisk | Unknown | The disk that is asynchronously replicated to this disk, containing the consistencyGroupPolicy and disk fields. |
| GCP.Compute.Disks.asyncSecondaryDisks | Unknown | The list of disks to which this disk is asynchronously replicated. |
| GCP.Compute.Disks.enableConfidentialCompute | Boolean | Whether this disk is using confidential compute mode. |
| GCP.Compute.Disks.locationHint | String | The opaque location hint used to place the disk close to other resources. |
| GCP.Compute.Disks.options | String | The field is reserved for internal use only. |
| GCP.Compute.Disks.params | Unknown | The additional parameters used when creating the disk, containing the resourceManagerTags field. |
| GCP.Compute.Disks.provisionedIops | String | The number of I/O operations per second provisioned for the disk. |
| GCP.Compute.Disks.provisionedThroughput | String | The throughput in MB per second provisioned for the disk. |
| GCP.Compute.Disks.resourcePolicies | Unknown | The resource policies applied to this disk for automatic snapshot creations. |
| GCP.Compute.Disks.resourceStatus | Unknown | The status information for the disk resource. |
| GCP.Compute.Disks.satisfiesPzi | Boolean | Whether the disk satisfies physical zone isolation. Reserved for future use. |
| GCP.Compute.Disks.satisfiesPzs | Boolean | Whether the disk satisfies physical zone separation. Reserved for future use. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicy | String | The URL of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicyId | String | The ID of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceDisk | String | The source disk used to create this disk. |
| GCP.Compute.Disks.sourceDiskId | String | The unique ID of the disk used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshot | String | The source instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshotId | String | The unique ID of the instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceStorageObject | String | The full Google Cloud Storage URI where the disk image is stored. |
| GCP.Compute.Disks.storagePool | String | The storage pool in which the disk is created. |
| GCP.Compute.DisksNextToken | String | The token for the next page of results, used for pagination. |
| GCP.Compute.DisksWarning | Unknown | The informational warning returned by the API, containing the code, message, and data fields. For example, NO_RESULTS_ON_PAGE when the page holds no results. |

### gcp-compute-disks-aggregated-list

***
Retrieves an aggregated list of persistent disks across all zones in the project. Required permission: compute.disks.list.

#### Base Command

`gcp-compute-disks-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| next_token | The token for pagination. Set it to the value of GCP.Compute.AggregatedDisksNextToken returned by a previous request to get the next page of results. | Optional |
| filter | The filter expression for resources listed in the response. The expression must specify a field name, a comparison operator \(=, !=, &gt;, or &lt;\), and a value, which can be a string, number, or boolean. For example, to exclude a disk named example-disk, use name != example-disk. | Optional |
| order_by | The order in which to sort the list results. By default, results are returned in alphanumerical order based on the resource name. Results can also be sorted in descending order based on the creation timestamp using creationTimestamp desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Disks.id | String | The unique identifier for the disk resource. |
| GCP.Compute.Disks.name | String | The name of the disk resource. |
| GCP.Compute.Disks.kind | String | The type of the resource, for example compute\#disk. |
| GCP.Compute.Disks.description | String | The optional description of the disk. |
| GCP.Compute.Disks.status | String | The status of disk creation, such as READY or CREATING. |
| GCP.Compute.Disks.sizeGb | String | The size of the persistent disk, specified in GB. |
| GCP.Compute.Disks.type | String | The URL of the disk type resource describing which disk type is used by this disk. |
| GCP.Compute.Disks.zone | String | The URL of the zone where the disk resides. |
| GCP.Compute.Disks.region | String | The URL of the region where the disk resides. Only applicable for regional resources. |
| GCP.Compute.Disks.creationTimestamp | Date | The creation timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastAttachTimestamp | Date | The last attach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastDetachTimestamp | Date | The last detach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.users | Unknown | The links to the instances to which the disk is attached. |
| GCP.Compute.Disks.licenses | Unknown | The list of publicly visible licenses attached to the disk. |
| GCP.Compute.Disks.licenseCodes | Unknown | The integer license codes indicating which licenses are attached to the disk. |
| GCP.Compute.Disks.guestOsFeatures | Unknown | The list of features to enable on the guest operating system, each containing a type field. |
| GCP.Compute.Disks.labels | Unknown | The labels applied to the disk as key-value pairs. |
| GCP.Compute.Disks.labelFingerprint | String | The fingerprint for the labels applied to the disk, used for optimistic locking. |
| GCP.Compute.Disks.sourceImage | String | The source image used to create this disk. |
| GCP.Compute.Disks.sourceImageId | String | The ID value of the image used to create this disk. |
| GCP.Compute.Disks.sourceSnapshot | String | The source snapshot used to create this disk. |
| GCP.Compute.Disks.sourceSnapshotId | String | The unique ID of the snapshot used to create this disk. |
| GCP.Compute.Disks.diskEncryptionKey | Unknown | The customer-supplied encryption key of the disk, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceImageEncryptionKey | Unknown | The customer-supplied encryption key of the source image, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceSnapshotEncryptionKey | Unknown | The customer-supplied encryption key of the source snapshot, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.replicaZones | Unknown | The URLs of the zones where the disk is replicated. Only applicable for regional resources. |
| GCP.Compute.Disks.physicalBlockSizeBytes | String | The physical block size of the persistent disk, in bytes. |
| GCP.Compute.Disks.selfLink | String | The server-defined URL for the disk resource. |
| GCP.Compute.Disks.accessMode | String | The access mode of the disk, such as READ_WRITE_SINGLE, READ_WRITE_MANY, or READ_ONLY_MANY. |
| GCP.Compute.Disks.architecture | String | The architecture of the disk. Valid values are ARM64 or X86_64. |
| GCP.Compute.Disks.asyncPrimaryDisk | Unknown | The disk that is asynchronously replicated to this disk, containing the consistencyGroupPolicy and disk fields. |
| GCP.Compute.Disks.asyncSecondaryDisks | Unknown | The list of disks to which this disk is asynchronously replicated. |
| GCP.Compute.Disks.enableConfidentialCompute | Boolean | Whether this disk is using confidential compute mode. |
| GCP.Compute.Disks.locationHint | String | The opaque location hint used to place the disk close to other resources. |
| GCP.Compute.Disks.options | String | The field is reserved for internal use only. |
| GCP.Compute.Disks.params | Unknown | The additional parameters used when creating the disk, containing the resourceManagerTags field. |
| GCP.Compute.Disks.provisionedIops | String | The number of I/O operations per second provisioned for the disk. |
| GCP.Compute.Disks.provisionedThroughput | String | The throughput in MB per second provisioned for the disk. |
| GCP.Compute.Disks.resourcePolicies | Unknown | The resource policies applied to this disk for automatic snapshot creations. |
| GCP.Compute.Disks.resourceStatus | Unknown | The status information for the disk resource. |
| GCP.Compute.Disks.satisfiesPzi | Boolean | Whether the disk satisfies physical zone isolation. Reserved for future use. |
| GCP.Compute.Disks.satisfiesPzs | Boolean | Whether the disk satisfies physical zone separation. Reserved for future use. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicy | String | The URL of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicyId | String | The ID of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceDisk | String | The source disk used to create this disk. |
| GCP.Compute.Disks.sourceDiskId | String | The unique ID of the disk used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshot | String | The source instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshotId | String | The unique ID of the instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceStorageObject | String | The full Google Cloud Storage URI where the disk image is stored. |
| GCP.Compute.Disks.storagePool | String | The storage pool in which the disk is created. |
| GCP.Compute.AggregatedDisksNextToken | String | The token for the next page of results, used for pagination. |
| GCP.Compute.AggregatedDisksWarning | Unknown | The informational warning returned by the API, containing the code, message, and data fields. For example, NO_RESULTS_ON_PAGE when the page holds no results. |

### gcp-compute-disk-get

***
Returns a specified persistent disk. Required permission: compute.disks.get.

#### Base Command

`gcp-compute-disk-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the persistent disk to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Disks.id | String | The unique identifier for the disk resource. |
| GCP.Compute.Disks.name | String | The name of the disk resource. |
| GCP.Compute.Disks.kind | String | The type of the resource, for example compute\#disk. |
| GCP.Compute.Disks.description | String | The optional description of the disk. |
| GCP.Compute.Disks.status | String | The status of disk creation, such as READY or CREATING. |
| GCP.Compute.Disks.sizeGb | String | The size of the persistent disk, specified in GB. |
| GCP.Compute.Disks.type | String | The URL of the disk type resource describing which disk type is used by this disk. |
| GCP.Compute.Disks.zone | String | The URL of the zone where the disk resides. |
| GCP.Compute.Disks.region | String | The URL of the region where the disk resides. Only applicable for regional resources. |
| GCP.Compute.Disks.creationTimestamp | Date | The creation timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastAttachTimestamp | Date | The last attach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.lastDetachTimestamp | Date | The last detach timestamp of the disk in RFC3339 text format. |
| GCP.Compute.Disks.users | Unknown | The links to the instances to which the disk is attached. |
| GCP.Compute.Disks.licenses | Unknown | The list of publicly visible licenses attached to the disk. |
| GCP.Compute.Disks.licenseCodes | Unknown | The integer license codes indicating which licenses are attached to the disk. |
| GCP.Compute.Disks.guestOsFeatures | Unknown | The list of features to enable on the guest operating system, each containing a type field. |
| GCP.Compute.Disks.labels | Unknown | The labels applied to the disk as key-value pairs. |
| GCP.Compute.Disks.labelFingerprint | String | The fingerprint for the labels applied to the disk, used for optimistic locking. |
| GCP.Compute.Disks.sourceImage | String | The source image used to create this disk. |
| GCP.Compute.Disks.sourceImageId | String | The ID value of the image used to create this disk. |
| GCP.Compute.Disks.sourceSnapshot | String | The source snapshot used to create this disk. |
| GCP.Compute.Disks.sourceSnapshotId | String | The unique ID of the snapshot used to create this disk. |
| GCP.Compute.Disks.diskEncryptionKey | Unknown | The customer-supplied encryption key of the disk, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceImageEncryptionKey | Unknown | The customer-supplied encryption key of the source image, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.sourceSnapshotEncryptionKey | Unknown | The customer-supplied encryption key of the source snapshot, containing the rawKey, kmsKeyName, and sha256 fields. |
| GCP.Compute.Disks.replicaZones | Unknown | The URLs of the zones where the disk is replicated. Only applicable for regional resources. |
| GCP.Compute.Disks.physicalBlockSizeBytes | String | The physical block size of the persistent disk, in bytes. |
| GCP.Compute.Disks.selfLink | String | The server-defined URL for the disk resource. |
| GCP.Compute.Disks.accessMode | String | The access mode of the disk, such as READ_WRITE_SINGLE, READ_WRITE_MANY, or READ_ONLY_MANY. |
| GCP.Compute.Disks.architecture | String | The architecture of the disk. Valid values are ARM64 or X86_64. |
| GCP.Compute.Disks.asyncPrimaryDisk | Unknown | The disk that is asynchronously replicated to this disk, containing the consistencyGroupPolicy and disk fields. |
| GCP.Compute.Disks.asyncSecondaryDisks | Unknown | The list of disks to which this disk is asynchronously replicated. |
| GCP.Compute.Disks.enableConfidentialCompute | Boolean | Whether this disk is using confidential compute mode. |
| GCP.Compute.Disks.locationHint | String | The opaque location hint used to place the disk close to other resources. |
| GCP.Compute.Disks.options | String | The field is reserved for internal use only. |
| GCP.Compute.Disks.params | Unknown | The additional parameters used when creating the disk, containing the resourceManagerTags field. |
| GCP.Compute.Disks.provisionedIops | String | The number of I/O operations per second provisioned for the disk. |
| GCP.Compute.Disks.provisionedThroughput | String | The throughput in MB per second provisioned for the disk. |
| GCP.Compute.Disks.resourcePolicies | Unknown | The resource policies applied to this disk for automatic snapshot creations. |
| GCP.Compute.Disks.resourceStatus | Unknown | The status information for the disk resource. |
| GCP.Compute.Disks.satisfiesPzi | Boolean | Whether the disk satisfies physical zone isolation. Reserved for future use. |
| GCP.Compute.Disks.satisfiesPzs | Boolean | Whether the disk satisfies physical zone separation. Reserved for future use. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicy | String | The URL of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceConsistencyGroupPolicyId | String | The ID of the DiskConsistencyGroupPolicy for a secondary disk that was created using a consistency group. |
| GCP.Compute.Disks.sourceDisk | String | The source disk used to create this disk. |
| GCP.Compute.Disks.sourceDiskId | String | The unique ID of the disk used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshot | String | The source instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceInstantSnapshotId | String | The unique ID of the instant snapshot used to create this disk. |
| GCP.Compute.Disks.sourceStorageObject | String | The full Google Cloud Storage URI where the disk image is stored. |
| GCP.Compute.Disks.storagePool | String | The storage pool in which the disk is created. |

### gcp-compute-disk-insert

***
Creates a persistent disk in the specified project and zone. A disk can be created from a source image, from a source snapshot, or as an empty disk by omitting both. Required permission: compute.disks.create.

#### Base Command

`gcp-compute-disk-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the disk to create. The name must be 1-63 characters long and match the regular expression \[a-z\](\[-a-z0-9\]\*\[a-z0-9\])?, meaning the first character must be a lowercase letter and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash. | Required |
| disk_type | The full or partial URL of the disk type resource describing which disk type to use to create the disk. A bare disk type name is not accepted. For example: projects/project/zones/zone/diskTypes/pd-standard or zones/zone/diskTypes/pd-ssd. If not provided, the project default disk type is used. | Optional |
| size_gb | The size of the persistent disk, specified in GB. Acceptable values are 1 to 65536, inclusive. When specified together with source_image or source_snapshot, the value must not be less than the size of the source. | Optional |
| description | The optional description of the disk. | Optional |
| source_snapshot | The source snapshot used to create this disk, provided as a partial or full URL to the resource. | Optional |
| source_image | The source image used to create this disk, provided as a partial or full URL to the resource. | Optional |
| licenses | The comma-separated list of publicly visible licenses to attach to the disk. | Optional |
| guest_os_features | The comma-separated list of features to enable on the guest operating system. Applicable only for bootable images. | Optional |
| disk_encryption_key_raw_key | The 256-bit customer-supplied encryption key, encoded in RFC 4648 base64, used to encrypt or decrypt this disk. | Optional |
| disk_encryption_key_kms_key_name | The name of the encryption key for this disk that is stored in Google Cloud KMS. | Optional |
| source_image_encryption_key_raw_key | The 256-bit customer-supplied encryption key of the source image, encoded in RFC 4648 base64. | Optional |
| source_image_encryption_key_kms_key_name | The name of the encryption key of the source image that is stored in Google Cloud KMS. | Optional |
| source_snapshot_encryption_key_raw_key | The 256-bit customer-supplied encryption key of the source snapshot, encoded in RFC 4648 base64. | Optional |
| source_snapshot_encryption_key_kms_key_name | The name of the encryption key of the source snapshot that is stored in Google Cloud KMS. | Optional |
| labels | The labels to apply to this disk, in the format key=abc,value=123;key=def,value=456. | Optional |
| label_fingerprint | The fingerprint of the labels being applied to this disk, used for optimistic locking. An up-to-date fingerprint hash must always be provided, otherwise the request fails with error 412 conditionNotMet. | Optional |
| replica_zones | The comma-separated list of URLs of the zones where the disk should be replicated. Only applicable for regional resources. | Optional |
| license_codes | The comma-separated list of integer license codes indicating which licenses are attached to this disk. | Optional |
| physical_block_size_bytes | The physical block size of the persistent disk, in bytes. If not provided, a default value is used. Currently supported sizes are 4096 and 16384. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.progress | Number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time that this operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | Date | The time that this operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | Date | The time that this operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors list with the code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warnings generated during processing of the operation, each containing the code, message, and data fields. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example 404 when the resource was not found. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulk request. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example user@example.com. |

### gcp-compute-disk-delete

***
Deletes the specified persistent disk. Deleting a disk removes its data permanently and is irreversible. Snapshots previously created from the disk are not deleted and must be deleted separately. Required permission: compute.disks.delete.

#### Base Command

`gcp-compute-disk-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the persistent disk to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.progress | Number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time that this operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | Date | The time that this operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | Date | The time that this operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors list with the code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warnings generated during processing of the operation, each containing the code, message, and data fields. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example 404 when the resource was not found. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulk request. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example user@example.com. |

### gcp-compute-disk-resize

***
Resizes the specified persistent disk. The disk size can only be increased. Required permission: compute.disks.resize.

#### Base Command

`gcp-compute-disk-resize`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the persistent disk to resize. | Required |
| size_gb | The new size of the persistent disk, specified in GB. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.progress | Number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time that this operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | Date | The time that this operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | Date | The time that this operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors list with the code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warnings generated during processing of the operation, each containing the code, message, and data fields. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example 404 when the resource was not found. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulk request. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example user@example.com. |

### gcp-compute-disk-labels-set

***
Sets the labels on a persistent disk. Required permission: compute.disks.setLabels.

#### Base Command

`gcp-compute-disk-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the persistent disk to set the labels on. | Required |
| labels | The labels to set for this disk, in the format key=abc,value=123;key=def,value=456. | Required |
| label_fingerprint | The fingerprint of the previous set of labels for this disk, used to detect conflicts. Run gcp-compute-disk-get to retrieve the latest fingerprint. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.progress | Number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time that this operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | Date | The time that this operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | Date | The time that this operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors list with the code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warnings generated during processing of the operation, each containing the code, message, and data fields. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example 404 when the resource was not found. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulk request. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example user@example.com. |

### gcp-compute-disk-snapshot-create

***
Creates a snapshot of a specified persistent disk. Required permissions: compute.disks.createSnapshot, compute.snapshots.create.

#### Base Command

`gcp-compute-disk-snapshot-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the persistent disk to snapshot. | Required |
| snapshot_name | The name of the snapshot to create. | Required |
| description | The optional description of the snapshot. | Optional |
| snapshot_encryption_key_raw_key | The 256-bit customer-supplied encryption key for the snapshot, encoded in RFC 4648 base64. | Optional |
| snapshot_encryption_key_kms_key_name | The name of the encryption key for the snapshot that is stored in Google Cloud KMS. | Optional |
| source_disk_encryption_key_raw_key | The 256-bit customer-supplied encryption key of the source disk, encoded in RFC 4648 base64. | Optional |
| source_disk_encryption_key_kms_key_name | The name of the encryption key of the source disk that is stored in Google Cloud KMS. | Optional |
| labels | The labels to apply to this snapshot, in the format key=abc,value=123;key=def,value=456. | Optional |
| label_fingerprint | The fingerprint of the labels being applied to this snapshot, used for optimistic locking. An up-to-date fingerprint hash must always be provided, otherwise the request fails with error 412 conditionNotMet. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation. |
| GCP.Compute.Operations.name | String | The name of the operation resource. |
| GCP.Compute.Operations.kind | String | The type of the resource, for example compute\#operation. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.status | String | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.progress | Number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For a create snapshot operation, this points to the persistent disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the operation resource. |
| GCP.Compute.Operations.insertTime | Date | The time that this operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | Date | The time that this operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | Date | The time that this operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors list with the code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warnings generated during processing of the operation, each containing the code, message, and data fields. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.description | String | The textual description of the operation, which is set when the operation is created. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example 404 when the resource was not found. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulk request. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example user@example.com. |

### gcp-compute-disk-types-list

***
Retrieves a list of disk types available in the specified zone. Required permission: compute.diskTypes.list.

#### Base Command

`gcp-compute-disk-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| next_token | The token for pagination. Set it to the value of GCP.Compute.DiskTypesNextToken returned by a previous request to get the next page of results. | Optional |
| filter | The filter expression for resources listed in the response. The expression must specify a field name, a comparison operator \(=, !=, &gt;, or &lt;\), and a value, which can be a string, number, or boolean. For example, to exclude a disk type named pd-standard, use name != pd-standard. | Optional |
| order_by | The order in which to sort the list results. By default, results are returned in alphanumerical order based on the resource name. Results can also be sorted in descending order based on the creation timestamp using creationTimestamp desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.DiskTypes.id | String | The unique identifier for the disk type resource. |
| GCP.Compute.DiskTypes.name | String | The name of the disk type resource. |
| GCP.Compute.DiskTypes.kind | String | The type of the resource, for example compute\#diskType. |
| GCP.Compute.DiskTypes.description | String | The optional description of the disk type. |
| GCP.Compute.DiskTypes.validDiskSize | String | The optional textual description of the valid disk size, such as 10GB-10TB. |
| GCP.Compute.DiskTypes.defaultDiskSizeGb | String | The server-defined default disk size in GB. |
| GCP.Compute.DiskTypes.zone | String | The URL of the zone where the disk type resides. |
| GCP.Compute.DiskTypes.region | String | The URL of the region where the disk type resides. Only applicable for regional resources. |
| GCP.Compute.DiskTypes.creationTimestamp | Date | The creation timestamp of the disk type in RFC3339 text format. |
| GCP.Compute.DiskTypes.selfLink | String | The server-defined URL for the disk type resource. |
| GCP.Compute.DiskTypes.deprecated | Unknown | The deprecation status associated with this disk type, containing the state, replacement, deprecated, obsolete, and deleted fields. |
| GCP.Compute.DiskTypesNextToken | String | The token for the next page of results, used for pagination. |
| GCP.Compute.DiskTypesWarning | Unknown | The informational warning returned by the API, containing the code, message, and data fields. For example, NO_RESULTS_ON_PAGE when the page holds no results. |

### gcp-compute-disk-types-aggregated-list

***
Retrieves an aggregated list of disk types across all zones in the project. Required permission: compute.diskTypes.list.

#### Base Command

`gcp-compute-disk-types-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return, ranging from 1 to 500. Default is 50. | Optional |
| next_token | The token for pagination. Set it to the value of GCP.Compute.AggregatedDiskTypesNextToken returned by a previous request to get the next page of results. | Optional |
| filter | The filter expression for resources listed in the response. The expression must specify a field name, a comparison operator \(=, !=, &gt;, or &lt;\), and a value, which can be a string, number, or boolean. For example, to exclude a disk type named pd-standard, use name != pd-standard. | Optional |
| order_by | The order in which to sort the list results. By default, results are returned in alphanumerical order based on the resource name. Results can also be sorted in descending order based on the creation timestamp using creationTimestamp desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.DiskTypes.id | String | The unique identifier for the disk type resource. |
| GCP.Compute.DiskTypes.name | String | The name of the disk type resource. |
| GCP.Compute.DiskTypes.kind | String | The type of the resource, for example compute\#diskType. |
| GCP.Compute.DiskTypes.description | String | The optional description of the disk type. |
| GCP.Compute.DiskTypes.validDiskSize | String | The optional textual description of the valid disk size, such as 10GB-10TB. |
| GCP.Compute.DiskTypes.defaultDiskSizeGb | String | The server-defined default disk size in GB. |
| GCP.Compute.DiskTypes.zone | String | The URL of the zone where the disk type resides. |
| GCP.Compute.DiskTypes.region | String | The URL of the region where the disk type resides. Only applicable for regional resources. |
| GCP.Compute.DiskTypes.creationTimestamp | Date | The creation timestamp of the disk type in RFC3339 text format. |
| GCP.Compute.DiskTypes.selfLink | String | The server-defined URL for the disk type resource. |
| GCP.Compute.DiskTypes.deprecated | Unknown | The deprecation status associated with this disk type, containing the state, replacement, deprecated, obsolete, and deleted fields. |
| GCP.Compute.AggregatedDiskTypesNextToken | String | The token for the next page of results, used for pagination. |
| GCP.Compute.AggregatedDiskTypesWarning | Unknown | The informational warning returned by the API, containing the code, message, and data fields. For example, NO_RESULTS_ON_PAGE when the page holds no results. |

### gcp-compute-disk-type-get

***
Returns the specified disk type. Required permission: compute.diskTypes.get.

#### Base Command

`gcp-compute-disk-type-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| resource_name | The name of the disk type to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.DiskTypes.id | String | The unique identifier for the disk type resource. |
| GCP.Compute.DiskTypes.name | String | The name of the disk type resource. |
| GCP.Compute.DiskTypes.kind | String | The type of the resource, for example compute\#diskType. |
| GCP.Compute.DiskTypes.description | String | The optional description of the disk type. |
| GCP.Compute.DiskTypes.validDiskSize | String | The optional textual description of the valid disk size, such as 10GB-10TB. |
| GCP.Compute.DiskTypes.defaultDiskSizeGb | String | The server-defined default disk size in GB. |
| GCP.Compute.DiskTypes.zone | String | The URL of the zone where the disk type resides. |
| GCP.Compute.DiskTypes.region | String | The URL of the region where the disk type resides. Only applicable for regional resources. |
| GCP.Compute.DiskTypes.creationTimestamp | Date | The creation timestamp of the disk type in RFC3339 text format. |
| GCP.Compute.DiskTypes.selfLink | String | The server-defined URL for the disk type resource. |
| GCP.Compute.DiskTypes.deprecated | Unknown | The deprecation status associated with this disk type, containing the state, replacement, deprecated, obsolete, and deleted fields. |

### gcp-compute-machine-types-aggregated-list

***
Retrieves an aggregated list of machine types across all zones of the specified project. Required permission: compute.machineTypes.list.

#### Base Command

`gcp-compute-machine-types-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results per page to return, ranging from 1 to 500. If the number of available results is larger than the limit, a token is returned in the nextPageToken field to retrieve the next page of results in subsequent list requests. Default is 50. | Optional |
| filter | The filter expression to use for filtering resources listed in the response. Must specify the field name, a comparison operator, and the filtering value. The value can be a string, a number, or a boolean. The comparison operator must be "=", "!=", "&gt;", or "&lt;". For example, to exclude a region named "example-region", specify name != example-region. | Optional |
| order_by | The order in which to sort the list results. Can be "alphanumerical" (default, based on resource name) or "creationTimestamp desc" (reverse chronological order, latest first). | Optional |
| next_token | The page token to use. Set next_token to the value of GCP.Compute.AggregatedMachineTypesNextToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.MachineTypes.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.MachineTypes.creationTimestamp | string | The creation timestamp in RFC3339 text format \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Compute.MachineTypes.name | string | The name of the resource. |
| GCP.Compute.MachineTypes.description | string | The optional textual description of the resource. |
| GCP.Compute.MachineTypes.guestCpus | number | The number of virtual CPUs that are available to the instance. |
| GCP.Compute.MachineTypes.memoryMb | number | The amount of physical memory available to the instance, defined in MB. |
| GCP.Compute.MachineTypes.accelerators | Unknown | The list of accelerator configurations assigned to this machine type, containing the guestAcceleratorCount and guestAcceleratorType fields. |
| GCP.Compute.MachineTypes.scratchDisks | Unknown | The list of extended scratch disks assigned to the instance, containing the diskGb field. |
| GCP.Compute.MachineTypes.maximumPersistentDisks | number | The maximum persistent disks allowed. |
| GCP.Compute.MachineTypes.maximumPersistentDisksSizeGb | string | The maximum total persistent disks size \(GB\) allowed. |
| GCP.Compute.MachineTypes.deprecated | Unknown | The deprecation status associated with this machine type, containing the state, replacement, deprecated, obsolete, and deleted fields. |
| GCP.Compute.MachineTypes.zone | string | The name of the zone where the machine type resides, such as us-central1-a. |
| GCP.Compute.MachineTypes.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.MachineTypes.isSharedCpu | boolean | Whether this machine type has a shared CPU. See Shared-core machine types for more information. |
| GCP.Compute.MachineTypes.kind | string | The type of the resource. Always compute\#machineType for machine types. |
| GCP.Compute.AggregatedMachineTypesNextToken | string | The token to use when requesting the next set of aggregated machine types. |

### gcp-compute-machine-types-list

***
Retrieves a list of machine types available in the specified zone. Required permission: compute.machineTypes.list.

#### Base Command

`gcp-compute-machine-types-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| limit | The maximum number of results per page to return, ranging from 1 to 500. If the number of available results is larger than the limit, a token is returned in the nextPageToken field to retrieve the next page of results in subsequent list requests. Default is 50. | Optional |
| filter | The filter expression to use for filtering resources listed in the response. Must specify the field name, a comparison operator, and the filtering value. The value can be a string, a number, or a boolean. The comparison operator must be "=", "!=", "&gt;", or "&lt;". For example, to exclude a region named "example-region", specify name != example-region. | Optional |
| order_by | The order in which to sort the list results. Can be "alphanumerical" (default, based on resource name) or "creationTimestamp desc" (reverse chronological order, latest first). | Optional |
| next_token | The page token to use. Set next_token to the value of GCP.Compute.MachineTypesNextToken returned by a previous list request to get the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.MachineTypes.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.MachineTypes.creationTimestamp | string | The creation timestamp in RFC3339 text format \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Compute.MachineTypes.name | string | The name of the resource. |
| GCP.Compute.MachineTypes.description | string | The optional textual description of the resource. |
| GCP.Compute.MachineTypes.guestCpus | number | The number of virtual CPUs that are available to the instance. |
| GCP.Compute.MachineTypes.memoryMb | number | The amount of physical memory available to the instance, defined in MB. |
| GCP.Compute.MachineTypes.accelerators | Unknown | The list of accelerator configurations assigned to this machine type, containing the guestAcceleratorCount and guestAcceleratorType fields. |
| GCP.Compute.MachineTypes.scratchDisks | Unknown | The list of extended scratch disks assigned to the instance, containing the diskGb field. |
| GCP.Compute.MachineTypes.maximumPersistentDisks | number | The maximum persistent disks allowed. |
| GCP.Compute.MachineTypes.maximumPersistentDisksSizeGb | string | The maximum total persistent disks size \(GB\) allowed. |
| GCP.Compute.MachineTypes.deprecated | Unknown | The deprecation status associated with this machine type, containing the state, replacement, deprecated, obsolete, and deleted fields. |
| GCP.Compute.MachineTypes.zone | string | The name of the zone where the machine type resides, such as us-central1-a. |
| GCP.Compute.MachineTypes.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.MachineTypes.isSharedCpu | boolean | Whether this machine type has a shared CPU. See Shared-core machine types for more information. |
| GCP.Compute.MachineTypes.kind | string | The type of the resource. Always compute\#machineType for machine types. |
| GCP.Compute.MachineTypesNextToken | string | The token to use when requesting the next set of machine types. |

### gcp-compute-machine-type-get

***
Returns the specified machine type. Required permission: compute.machineTypes.get.

#### Base Command

`gcp-compute-machine-type-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| machine_type | The name of the machine type to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.MachineTypes.id | string | The unique identifier for the resource. This identifier is defined by the server. |
| GCP.Compute.MachineTypes.creationTimestamp | string | The creation timestamp in RFC3339 text format \(e.g., 2024-01-15T12:34:56Z\). |
| GCP.Compute.MachineTypes.name | string | The name of the resource. |
| GCP.Compute.MachineTypes.description | string | The optional textual description of the resource. |
| GCP.Compute.MachineTypes.guestCpus | number | The number of virtual CPUs that are available to the instance. |
| GCP.Compute.MachineTypes.memoryMb | number | The amount of physical memory available to the instance, defined in MB. |
| GCP.Compute.MachineTypes.accelerators | Unknown | The list of accelerator configurations assigned to this machine type, containing the guestAcceleratorCount and guestAcceleratorType fields. |
| GCP.Compute.MachineTypes.scratchDisks | Unknown | The list of extended scratch disks assigned to the instance, containing the diskGb field. |
| GCP.Compute.MachineTypes.maximumPersistentDisks | number | The maximum persistent disks allowed. |
| GCP.Compute.MachineTypes.maximumPersistentDisksSizeGb | string | The maximum total persistent disks size \(GB\) allowed. |
| GCP.Compute.MachineTypes.deprecated | Unknown | The deprecation status associated with this machine type, containing the state, replacement, deprecated, obsolete, and deleted fields. |
| GCP.Compute.MachineTypes.zone | string | The name of the zone where the machine type resides, such as us-central1-a. |
| GCP.Compute.MachineTypes.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.MachineTypes.isSharedCpu | boolean | Whether this machine type has a shared CPU. See Shared-core machine types for more information. |
| GCP.Compute.MachineTypes.kind | string | The type of the resource. Always compute\#machineType for machine types. |

### gcp-compute-region-operation-delete

***
Deletes the specified region-specific Operations resource. Required permission: compute.regionOperations.delete.

#### Base Command

`gcp-compute-region-operation-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| operation | The name of the Operations resource to delete. | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-global-operation-delete

***
Deletes the specified global Operations resource. Required permission: compute.globalOperations.delete.

#### Base Command

`gcp-compute-global-operation-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| operation | The name of the Operations resource to delete. | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-zone-operation-get

***
Retrieves the specified zone-specific Operations resource. Required permission: compute.zoneOperations.get.

#### Base Command

`gcp-compute-zone-operation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| operation | The name of the Operations resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. Only applicable when performing per-zone operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-global-operation-list

***
Lists the global Operations resources in the specified project. Required permission: compute.globalOperations.list.

#### Base Command

`gcp-compute-global-operation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return. Possible values are 1 to 500. Default is 50. | Optional |
| next_token | The token for the next set of results to return, used for pagination. Use the value of GCP.Compute.GlobalOperationsNextToken from the previous response. | Optional |
| filter | The filter expression that filters resources listed in the response. The expression must specify a field name, a comparison operator, and a value (for example, "status = DONE"). | Optional |
| order_by | The order to sort list results by. By default, results are returned in alphanumerical order based on the resource name (for example, "creationTimestamp desc"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |
| GCP.Compute.GlobalOperationsNextToken | String | The token to use as the next_token argument to retrieve the next page of results. |

### gcp-compute-region-operation-list

***
Lists the region-specific Operations resources in the specified project and region. Required permission: compute.regionOperations.list.

#### Base Command

`gcp-compute-region-operation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| limit | The maximum number of results to return. Possible values are 1 to 500. Default is 50. | Optional |
| next_token | The token for the next set of results to return, used for pagination. Use the value of GCP.Compute.RegionOperationsNextToken from the previous response. | Optional |
| filter | The filter expression that filters resources listed in the response. The expression must specify a field name, a comparison operator, and a value (for example, "status = DONE"). | Optional |
| order_by | The order to sort list results by. By default, results are returned in alphanumerical order based on the resource name (for example, "creationTimestamp desc"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |
| GCP.Compute.RegionOperationsNextToken | String | The token to use as the next_token argument to retrieve the next page of results. |

### gcp-compute-zone-operation-delete

***
Deletes the specified zone-specific Operations resource. Required permission: compute.zoneOperations.delete.

#### Base Command

`gcp-compute-zone-operation-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| operation | The name of the Operations resource to delete. | Required |

#### Context Output

There is no context output for this command.

### gcp-compute-zone-operation-list

***
Lists the zone-specific Operations resources in the specified project and zone. Required permission: compute.zoneOperations.list.

#### Base Command

`gcp-compute-zone-operation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone for this request. | Required |
| limit | The maximum number of results to return. Possible values are 1 to 500. Default is 50. | Optional |
| next_token | The token for the next set of results to return, used for pagination. Use the value of GCP.Compute.ZoneOperationsNextToken from the previous response. | Optional |
| filter | The filter expression that filters resources listed in the response. The expression must specify a field name, a comparison operator, and a value (for example, "status = DONE"). | Optional |
| order_by | The order to sort list results by. By default, results are returned in alphanumerical order based on the resource name (for example, "creationTimestamp desc"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.zone | String | The URL of the zone where the operation resides. Only applicable when performing per-zone operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |
| GCP.Compute.ZoneOperationsNextToken | String | The token to use as the next_token argument to retrieve the next page of results. |

### gcp-compute-global-operation-get

***
Retrieves the specified global Operations resource. Required permission: compute.globalOperations.get.

#### Base Command

`gcp-compute-global-operation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| operation | The name of the Operations resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-region-operation-get

***
Retrieves the specified region-specific Operations resource. Required permission: compute.regionOperations.get.

#### Base Command

`gcp-compute-region-operation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The name of the region for this request. | Required |
| operation | The name of the Operations resource to return. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | String | The unique identifier for the operation, defined by the server. |
| GCP.Compute.Operations.name | String | The name of the operation. |
| GCP.Compute.Operations.region | String | The URL of the region where the operation resides. Only applicable when performing regional operations. |
| GCP.Compute.Operations.clientOperationId | String | The value of the request ID if one was provided in the request. Not present otherwise. |
| GCP.Compute.Operations.operationType | String | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | String | The URL of the resource that the operation modifies. For operations related to creating a snapshot, this points to the disk that the snapshot was created from. |
| GCP.Compute.Operations.targetId | String | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | String | The status of the operation. Possible values are PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | String | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | String | The user who requested the operation, for example, "user@example.com". |
| GCP.Compute.Operations.progress | Number | The optional progress indicator, ranging from 0 to 100. This number monotonically increases as the operation progresses. |
| GCP.Compute.Operations.insertTime | String | The time the operation was requested, in RFC3339 text format. |
| GCP.Compute.Operations.startTime | String | The time the operation was started by the server, in RFC3339 text format. |
| GCP.Compute.Operations.endTime | String | The time the operation was completed, in RFC3339 text format. |
| GCP.Compute.Operations.error.errors | Unknown | The array of errors encountered while processing the operation, including the error type identifier, the field in the request that caused the error, the optional human-readable error message, and the optional list of messages that contain the error details. |
| GCP.Compute.Operations.warnings.code | String | The warning code, if applicable. For example, NO_RESULTS_ON_PAGE is returned when there are no results in the response. |
| GCP.Compute.Operations.warnings.message | String | The human-readable description of the warning code. |
| GCP.Compute.Operations.warnings.data | Unknown | The metadata about this warning, in key: value format, where the key provides more detail on the warning being returned and the value is the corresponding warning data value. |
| GCP.Compute.Operations.httpErrorStatusCode | Number | The HTTP error status code that was returned if the operation failed, for example, 404 when the resource was not found. |
| GCP.Compute.Operations.httpErrorMessage | String | The HTTP error message that was returned if the operation failed, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | String | The server-defined URL for the resource. |
| GCP.Compute.Operations.description | String | The textual description of the operation, set when the operation is created. |
| GCP.Compute.Operations.operationGroupId | String | The ID that represents a group of operations, such as when a group of operations results from a bulkInsert API request. |
| GCP.Compute.Operations.setCommonInstanceMetadataOperationMetadata | Unknown | The information on all underlying zonal actions and their state. Populated when the operation is for projects.setCommonInstanceMetadata. |
| GCP.Compute.Operations.instancesBulkInsertOperationMetadata | Unknown | The per-location status of the operation. Populated when the operation is for a bulk insert of instances. |
| GCP.Compute.Operations.getVersionOperationMetadata | Unknown | The inline SBOM information for the operation, containing the current and target component versions. |
| GCP.Compute.Operations.kind | String | The type of the resource. Always compute\#operation for Operation resources. |

### gcp-compute-instance-group-instances-list

***
Lists the instances in the specified instance group. Required permission: compute.instanceGroups.list.

#### Base Command

`gcp-compute-instance-group-instances-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |
| instance_group | The name of the instance group from which to generate the list of included instances. | Required |
| instance_state | The filter for the state of the instances in the instance group. If not specified, the list includes all instances regardless of their state. Possible values are: ALL, RUNNING. | Optional |
| limit | The maximum number of results per page that should be returned. If the number of available results is larger than limit, Compute Engine returns a nextPageToken that can be used to get the next page of results in subsequent list requests. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| filter | The expression to filter resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value (string, number, or boolean). For example, to exclude an instance group named example-group, specify name != example-group. | Optional |
| order_by | The sort order for the results. By default, results are returned in alphanumerical order by resource name. To sort in descending order by creation timestamp, use order_by=creationTimestamp desc. | Optional |
| next_token | The page token to use. Set next_token to the nextPageToken returned by a previous list request to retrieve the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.InstanceGroups.id | string | The name of the instance group whose instances were listed. |
| GCP.Compute.InstanceGroups.Instances.instance | string | The URL of the instance. |
| GCP.Compute.InstanceGroups.Instances.status | string | The status of the instance. |
| GCP.Compute.InstanceGroups.Instances.namedPorts | Unknown | The named ports assigned to the instance. Each named port contains: name - the name of the named port, which must be 1 to 63 characters long and comply with RFC1035; port - the port number, which can be a value between 1 and 65535. |
| GCP.Compute.InstanceGroups.InstanceGroupsInstancesNextToken | string | The token to use to retrieve the next page of instance group instances results. |

### gcp-compute-instance-group-insert

***
Creates an instance group in the specified project and zone. Required permission: compute.instanceGroups.create.

#### Base Command

`gcp-compute-instance-group-insert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is created. | Required |
| name | The name of the instance group. The name must be 1 to 63 characters long and comply with RFC1035. | Required |
| description | The optional description of this resource. | Optional |
| named_ports | The named ports to assign to the instance group. For example: name=http,port=80;name=https,port=443. | Optional |
| network | The URL of the network to which all instances in the instance group belong. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The date and time that this operation was requested in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The date and time that this operation was started by the server, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The date and time that this operation was completed, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors array with code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, containing code, message, and data fields. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.kind | string | The type of the resource. The value is always compute\#operation for Operation resources. |

### gcp-compute-instance-groups-aggregated-list

***
Retrieves the list of instance groups in the specified project across all zones. Required permission: compute.instanceGroups.list.

#### Base Command

`gcp-compute-instance-groups-aggregated-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results per page that should be returned. If the number of available results is larger than limit, Compute Engine returns a nextPageToken that can be used to get the next page of results in subsequent list requests. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| filter | The expression to filter resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value (string, number, or boolean). For example, to exclude an instance group named example-group, specify name != example-group. | Optional |
| order_by | The sort order for the results. By default, results are returned in alphanumerical order by resource name. To sort in descending order by creation timestamp, use order_by=creationTimestamp desc. | Optional |
| next_token | The page token to use. Set next_token to the nextPageToken returned by a previous list request to retrieve the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.InstanceGroups.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.InstanceGroups.creationTimestamp | string | The creation timestamp for this instance group in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.InstanceGroups.name | string | The name of the instance group. The name must be 1 to 63 characters long and comply with RFC1035. |
| GCP.Compute.InstanceGroups.description | string | The optional description of this resource. |
| GCP.Compute.InstanceGroups.namedPorts.name | string | The name of the named port. The name must be 1 to 63 characters long and comply with RFC1035. |
| GCP.Compute.InstanceGroups.namedPorts.port | number | The port number, which can be a value between 1 and 65535. |
| GCP.Compute.InstanceGroups.network | string | The URL of the network to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.fingerprint | string | The fingerprint of the named ports. The system uses this fingerprint to detect conflicts when multiple users change the named ports concurrently. |
| GCP.Compute.InstanceGroups.zone | string | The URL of the zone where the instance group is located \(for zonal resources\). |
| GCP.Compute.InstanceGroups.selfLink | string | The server-generated URL for this instance group. |
| GCP.Compute.InstanceGroups.size | number | The total number of instances in the instance group. |
| GCP.Compute.InstanceGroups.region | string | The URL of the region where the instance group is located \(for regional resources\). |
| GCP.Compute.InstanceGroups.subnetwork | string | The URL of the subnetwork to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.kind | string | The resource type, which is always compute\#instanceGroup for instance groups. |
| GCP.Compute.AggregatedInstanceGroupsNextToken | string | The token to use to retrieve the next page of aggregated instance group results. |
| GCP.Compute.AggregatedInstanceGroupsSelfLink | string | The server-defined URL for the aggregated instance groups list request. |
| GCP.Compute.AggregatedInstanceGroupsWarning | Unknown | The informational warning which replaces the list of instance groups when the list is empty. |

### gcp-compute-instance-groups-list

***
Retrieves the list of instance groups that are located in the specified project and zone. Required permission: compute.instanceGroups.list.

#### Base Command

`gcp-compute-instance-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance groups are located. | Required |
| limit | The maximum number of results per page that should be returned. If the number of available results is larger than limit, Compute Engine returns a nextPageToken that can be used to get the next page of results in subsequent list requests. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| filter | The expression to filter resources listed in the response. The expression must specify a field name, a comparison operator (=, !=, &gt;, or &lt;), and a value (string, number, or boolean). For example, to exclude an instance group named example-group, specify name != example-group. | Optional |
| order_by | The sort order for the results. By default, results are returned in alphanumerical order by resource name. To sort in descending order by creation timestamp, use order_by=creationTimestamp desc. | Optional |
| next_token | The page token to use. Set next_token to the nextPageToken returned by a previous list request to retrieve the next page of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.InstanceGroups.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.InstanceGroups.creationTimestamp | string | The creation timestamp for this instance group in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.InstanceGroups.name | string | The name of the instance group. The name must be 1 to 63 characters long and comply with RFC1035. |
| GCP.Compute.InstanceGroups.description | string | The optional description of this resource. |
| GCP.Compute.InstanceGroups.namedPorts.name | string | The name of the named port. The name must be 1 to 63 characters long and comply with RFC1035. |
| GCP.Compute.InstanceGroups.namedPorts.port | number | The port number, which can be a value between 1 and 65535. |
| GCP.Compute.InstanceGroups.network | string | The URL of the network to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.fingerprint | string | The fingerprint of the named ports. The system uses this fingerprint to detect conflicts when multiple users change the named ports concurrently. |
| GCP.Compute.InstanceGroups.zone | string | The URL of the zone where the instance group is located \(for zonal resources\). |
| GCP.Compute.InstanceGroups.selfLink | string | The server-generated URL for this instance group. |
| GCP.Compute.InstanceGroups.size | number | The total number of instances in the instance group. |
| GCP.Compute.InstanceGroups.region | string | The URL of the region where the instance group is located \(for regional resources\). |
| GCP.Compute.InstanceGroups.subnetwork | string | The URL of the subnetwork to which all instances in the instance group belong. |
| GCP.Compute.InstanceGroups.kind | string | The resource type, which is always compute\#instanceGroup for instance groups. |
| GCP.Compute.InstanceGroupsNextToken | string | The token to use to retrieve the next page of instance group results. |
| GCP.Compute.InstanceGroupsSelfLink | string | The server-defined URL for the instance groups list request. |
| GCP.Compute.InstanceGroupsWarning | Unknown | The informational warning which replaces the list of instance groups when the list is empty. |

### gcp-compute-instance-group-named-ports-set

***
Sets the named ports for the specified instance group. Required permission: compute.instanceGroups.update.

#### Base Command

`gcp-compute-instance-group-named-ports-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |
| instance_group | The name of the instance group where the named ports are updated. | Required |
| named_ports | The list of named ports to set for this instance group. For example: name=http,port=80;name=https,port=443. | Required |
| fingerprint | The fingerprint of the named ports information for this instance group. Use this optional argument to prevent conflicts when multiple users change the named ports settings concurrently. Obtain the fingerprint with the gcp-compute-instance-group-get command. A request with an incorrect fingerprint fails with error 412 conditionNotMet. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The date and time that this operation was requested, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The date and time that this operation was started by the server, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The date and time that this operation was completed, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors array with code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, containing code, message, and data fields. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.kind | string | The type of the resource. The value is always compute\#operation for Operation resources. |

### gcp-compute-instance-group-instances-add

***
Adds a list of instances to the specified instance group. All of the instances in the instance group must be in the same network or subnetwork. Required permission: compute.instanceGroups.update.

#### Base Command

`gcp-compute-instance-group-instances-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |
| instance_group | The name of the instance group where the instances are added. | Required |
| instances | A comma-separated list of URLs of the instances to add to the instance group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The date and time that this operation was requested, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The date and time that this operation was started by the server, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The date and time that this operation was completed, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors array with code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, containing code, message, and data fields. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.kind | string | The type of the resource. The value is always compute\#operation for Operation resources. |

### gcp-compute-instance-group-delete

***
Deletes the specified instance group. The instances in the group are not deleted. The instance group must not belong to a back-end service. Required permission: compute.instanceGroups.delete.

#### Base Command

`gcp-compute-instance-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |
| instance_group | The name of the instance group to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The date and time that this operation was requested, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The date and time that this operation was started by the server, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The date and time that this operation was completed, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors array with code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, containing code, message, and data fields. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.kind | string | The type of the resource. The value is always compute\#operation for Operation resources. |

### gcp-compute-instance-group-instances-remove

***
Removes one or more instances from the specified instance group, but does not delete those instances. If the group is part of a back-end service that has enabled connection draining, it can take up to 60 seconds after the connection draining duration for the VM instance to be removed or deleted. Required permission: compute.instanceGroups.update.

#### Base Command

`gcp-compute-instance-group-instances-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| zone | The name of the zone where the instance group is located. | Required |
| instance_group | The name of the instance group from which the instances are removed. | Required |
| instances | A comma-separated list of URLs of the instances to remove from the instance group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Compute.Operations.id | string | The unique identifier for the server-defined resource. |
| GCP.Compute.Operations.name | string | The name of the resource. |
| GCP.Compute.Operations.zone | string | The URL of the zone where the operation resides. |
| GCP.Compute.Operations.operationType | string | The type of operation, such as insert, update, or delete. |
| GCP.Compute.Operations.targetLink | string | The URL of the resource that the operation modifies. |
| GCP.Compute.Operations.targetId | string | The unique target ID, which identifies a specific incarnation of the target resource. |
| GCP.Compute.Operations.status | string | The status of the operation, which can be one of the following: PENDING, RUNNING, or DONE. |
| GCP.Compute.Operations.statusMessage | string | The optional textual description of the current status of the operation. |
| GCP.Compute.Operations.user | string | The user who requested the operation. |
| GCP.Compute.Operations.progress | number | The optional progress indicator that ranges from 0 to 100. |
| GCP.Compute.Operations.insertTime | string | The date and time that this operation was requested, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.startTime | string | The date and time that this operation was started by the server, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.endTime | string | The date and time that this operation was completed, in RFC3339 format \(for example, 2024-01-15T12:34:56Z\). |
| GCP.Compute.Operations.error | Unknown | The errors generated during processing of the operation, containing an errors array with code, location, and message fields. |
| GCP.Compute.Operations.warnings | Unknown | The warning messages generated during processing of the operation, containing code, message, and data fields. |
| GCP.Compute.Operations.httpErrorStatusCode | number | The HTTP error status code that is returned if the operation fails. |
| GCP.Compute.Operations.httpErrorMessage | string | The HTTP error message that is returned if the operation fails, such as NOT FOUND. |
| GCP.Compute.Operations.selfLink | string | The server-defined URL for the resource. |
| GCP.Compute.Operations.kind | string | The type of the resource. The value is always compute\#operation for Operation resources. |

### gcp-logging-log-entries-list

***
Lists log entries. Use this command to retrieve log entries that originated from a project, organization, billing account, or folder. Required Permissions: logging.logEntries.list.

#### Base Command

`gcp-logging-log-entries-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID to read log entries from. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0 and Cortex Cloud). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| organization_names | A comma-separated list of organization IDs of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional |
| billing_account_names | A comma-separated list of billing account IDs of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional |
| folder_names | A comma-separated list of folder IDs of parent resources from which to retrieve log entries. A maximum of 100 resources may be specified. | Optional |
| filter | The filter to limit results to log entries that match. The maximum length of a filter is 20,000 characters. For example: "protoPayload.requestMetadata.callerIp:1.1.1.1 AND protoPayload.serviceName:name". | Optional |
| order_by | The criteria to use for sorting the results. Can be "timestamp asc" or "timestamp desc". Possible values are: timestamp asc, timestamp desc. Default is timestamp asc. | Optional |
| limit | The maximum number of results to return. Valid range is 1-500. Default is 50. | Optional |
| next_token | The token used to retrieve the next batch of results. Must be the value of LogEntriesNextToken from the previous response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.Logging.LogEntries.logName | String | The resource name of the log to which this log entry belongs. |
| GCP.Logging.LogEntries.resource.type | String | The monitored resource type. |
| GCP.Logging.LogEntries.resource.labels | Unknown | The values for all labels listed in the associated monitored resource descriptor. |
| GCP.Logging.LogEntries.timestamp | String | The time the event described by the log entry occurred, in RFC 3339 UTC "Zulu" format. For example: "2014-10-02T15:01:23Z". |
| GCP.Logging.LogEntries.receiveTimestamp | String | The time the log entry was received by Logging, in RFC 3339 UTC "Zulu" format. For example: "2014-10-02T15:01:23Z". |
| GCP.Logging.LogEntries.severity | String | The severity of the log entry. The default value is LogSeverity.DEFAULT. |
| GCP.Logging.LogEntries.insertId | String | A unique identifier for the log entry. |
| GCP.Logging.LogEntries.httpRequest | Unknown | The HTTP request associated with the log entry, containing requestMethod, requestUrl, status, userAgent, remoteIp, and other fields. |
| GCP.Logging.LogEntries.labels | Unknown | The map of key-value pairs that provides additional information about the log entry. |
| GCP.Logging.LogEntries.operation | Unknown | The information about an operation associated with the log entry, containing the ID, producer, first, and last fields. |
| GCP.Logging.LogEntries.trace | String | The REST resource name of the trace being written to Cloud Trace in association with this log entry. |
| GCP.Logging.LogEntries.spanId | String | The ID of the Cloud Trace span associated with the current operation in which the log is being written. |
| GCP.Logging.LogEntries.traceSampled | Boolean | The sampling decision of the trace associated with the log entry. |
| GCP.Logging.LogEntries.sourceLocation | Unknown | The source code location information associated with the log entry, containing file, line, and function fields. |
| GCP.Logging.LogEntries.split | Unknown | The information indicating this LogEntry is part of a sequence of multiple log entries split from a single LogEntry, containing the UID, index, and totalSplits fields. |
| GCP.Logging.LogEntries.errorGroups | Unknown | The Error Reporting error groups associated with this LogEntry, if any. |
| GCP.Logging.LogEntries.apphub | Unknown | The AppHub application metadata associated with the monitored resource of this log entry. |
| GCP.Logging.LogEntries.apphubDestination | Unknown | The AppHub application metadata associated with the destination of this log entry. |
| GCP.Logging.LogEntries.apphubSource | Unknown | The AppHub application metadata associated with the source of this log entry. |
| GCP.Logging.LogEntries.protoPayload | Unknown | The log entry payload, represented as a protocol buffer. A log entry has exactly one of protoPayload, textPayload, or jsonPayload. |
| GCP.Logging.LogEntries.textPayload | String | The log entry payload, represented as a Unicode string \(UTF-8\). A log entry has exactly one of protoPayload, textPayload, or jsonPayload. |
| GCP.Logging.LogEntries.jsonPayload | Unknown | The log entry payload, represented as a structure that is expressed as a JSON object. A log entry has exactly one of protoPayload, textPayload, or jsonPayload. |
| GCP.Logging.LogEntriesNextToken | String | The nextPageToken included when there are more results than those appearing in this response. To get the next set of results, call this command again using the value of nextPageToken as next_token. |

### gcp-cloudrun-functions-list

***
Lists Google Cloud Functions in the specified project and region. Required Permission: cloudfunctions.functions.list.

#### Base Command

`gcp-cloudrun-functions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The region of the Google Cloud functions. Default is all regions. To get a full list of regions, run the gcp-cloudrun-locations-list command. | Optional |
| limit | The maximum number of results to return. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| next_token | The pagination token used to return the next set of items. | Optional |
| filter | The filter expression for the functions listed in the response. For example, to return only active functions, use state="ACTIVE". | Optional |
| order_by | A comma-separated list of fields by which to sort the returned functions. Append desc to a field to sort it in descending order. For example, name desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.CloudRun.Functions.name | String | The user-defined name of the function, which must be globally unique and match the pattern projects//locations//functions/\*. |
| GCP.CloudRun.Functions.description | String | The user-provided description of the function. |
| GCP.CloudRun.Functions.buildConfig | Unknown | The build step of the function that builds a container from the given source. |
| GCP.CloudRun.Functions.serviceConfig | Unknown | The fully managed Cloud Run service being deployed. |
| GCP.CloudRun.Functions.eventTrigger | Unknown | The source that fires events in response to a condition in another service. |
| GCP.CloudRun.Functions.state | String | The state of the function. Possible values are: STATE_UNSPECIFIED, ACTIVE, FAILED, DEPLOYING, DELETING, UNKNOWN, DETACHING, DETACH_FAILED. |
| GCP.CloudRun.Functions.updateTime | Date | The last update timestamp of the function. For example: "2014-10-02T15:01:23Z". |
| GCP.CloudRun.Functions.labels | Unknown | The labels associated with the function. |
| GCP.CloudRun.Functions.stateMessages | Unknown | The state messages for the function. |
| GCP.CloudRun.Functions.environment | String | The generation of the function. Can be "ENVIRONMENT_UNSPECIFIED", "GEN_1", or "GEN_2". |
| GCP.CloudRun.Functions.upgradeInfo | Unknown | The upgrade information for the function. |
| GCP.CloudRun.Functions.url | String | The deployed URL of the function. |
| GCP.CloudRun.Functions.kmsKeyName | String | The user-managed resource name of a KMS crypto key used to encrypt or decrypt function resources, matching the pattern projects/\{project\}/locations/\{location\}/keyRings/\{key_ring\}/cryptoKeys/\{crypto_key\}. |
| GCP.CloudRun.Functions.createTime | Date | The creation timestamp of the function. Applicable only to 2nd Gen functions. For example: 2014-10-02T15:01:23Z. |
| GCP.CloudRun.FunctionsNextToken | String | The token to retrieve the next page of Google Cloud Run functions. |

### gcp-cloudrun-locations-list

***
Lists all available Google Cloud Functions regions in the project. Required permission: cloudfunctions.locations.list.

#### Base Command

`gcp-cloudrun-locations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| limit | The maximum number of results to return. Acceptable values are 1 to 500, inclusive. Default is 50. | Optional |
| next_token | The pagination token used to return the next set of items. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.CloudRun.Locations.name | String | The resource name for the location, which may vary between implementations. For example: projects/example-project/locations/us-east1. |
| GCP.CloudRun.Locations.locationId | String | The canonical ID for this location. For example: us-east1. |
| GCP.CloudRun.Locations.displayName | String | The friendly name for the location, typically a nearby city name such as Tokyo. |
| GCP.CloudRun.Locations.labels | Unknown | The cross-service attributes for the location, such as \{"cloud.googleapis.com/region": "us-east1"\}. |
| GCP.CloudRun.Locations.metadata | Unknown | The service-specific metadata, such as the available capacity at the given location. |
| GCP.CloudRun.LocationsNextToken | String | The token used to retrieve the next page of locations. |

### gcp-cloudrun-function-get

***
Gets the details of a specific Google Cloud function. Required permission: cloudfunctions.functions.get.

#### Base Command

`gcp-cloudrun-function-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The region of the Google Cloud function. To get a full list of regions, run the gcp-cloudrun-locations-list command. | Required |
| function_name | The name of the function. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.CloudRun.Functions.name | String | The user-defined name of the function, which must be globally unique and match the pattern projects/locations/functions/\*. |
| GCP.CloudRun.Functions.description | String | The user-provided description of the function. |
| GCP.CloudRun.Functions.buildConfig | Unknown | The build step of the function that builds a container from the given source. |
| GCP.CloudRun.Functions.serviceConfig | Unknown | The fully managed Cloud Run service being deployed. |
| GCP.CloudRun.Functions.eventTrigger | Unknown | The source that fires events in response to a condition in another service. |
| GCP.CloudRun.Functions.state | String | The state of the function. Possible values are: STATE_UNSPECIFIED, ACTIVE, FAILED, DEPLOYING, DELETING, UNKNOWN, DETACHING, DETACH_FAILED. |
| GCP.CloudRun.Functions.updateTime | Date | The last update timestamp of the function. For example: "2014-10-02T15:01:23Z". |
| GCP.CloudRun.Functions.labels | Unknown | The labels associated with the function. |
| GCP.CloudRun.Functions.stateMessages | Unknown | The state messages for the function. |
| GCP.CloudRun.Functions.environment | String | The generation of the function. Can be "ENVIRONMENT_UNSPECIFIED", "GEN_1", or "GEN_2". |
| GCP.CloudRun.Functions.upgradeInfo | Unknown | The upgrade information for the function. |
| GCP.CloudRun.Functions.url | String | The deployed URL of the function. |
| GCP.CloudRun.Functions.kmsKeyName | String | The user-managed resource name of a KMS crypto key used to encrypt or decrypt function resources, matching the pattern projects/\{project\}/locations/\{location\}/keyRings/\{key_ring\}/cryptoKeys/\{crypto_key\}. |
| GCP.CloudRun.Functions.createTime | Date | The creation timestamp of the function. Applicable only to 2nd Gen functions. For example: 2014-10-02T15:01:23Z. |

### gcp-cloudfunctions-function-execute

***
Synchronously invokes a deployed Google Cloud (1st Gen) function and returns its execution result. Required permission: cloudfunctions.functions.call.

#### Base Command

`gcp-cloudfunctions-function-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP project ID. Required for Cortex Platform (which includes Cortex XSIAM version &gt;=3.0, Cortex Cloud, and Cortex Agentix). Optional for Cortex XSOAR and Cortex XSIAM version &lt; 3.0, where it can be retrieved from the integration configuration. | Optional |
| region | The region of the Google Cloud function. To get a full list of regions, run the gcp-cloudrun-locations-list command. | Required |
| function_name | The name of the function to invoke. | Required |
| data | The input data passed to the function, such as a JSON-encoded string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCP.CloudFunctions.Execution.executionId | String | The execution ID of the function invocation. |
| GCP.CloudFunctions.Execution.result | String | The result of the function invocation, returned as a string. |
| GCP.CloudFunctions.Execution.error | String | The error message if the function execution resulted in an error. |
