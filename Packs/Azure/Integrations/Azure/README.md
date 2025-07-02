Cloud integrations are installed from the **Data Sources** page. To configure a cloud integration, go to Settings > Data Sources and click "Add Data Source", select Azure, then in Advanced Settings > Security Capabilities, enable "Automation".

## Configure Azure in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Application ID |  |  |
| Default Subscription ID | You can set the value either in the configuration or directly within the commands. If you set it in both places, the value in the command will override the configuration setting. |  |
| Default Resource Group Name | You can set the value either in the configuration or directly within the commands. If you set it in both places, the value in the command will override the configuration setting. |  |
| Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tenant ID |  | False |
| Client Secret |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-nsg-security-rule-update

***
Update a security rule. If one does not exist, it will be created.

#### Base Command

`azure-nsg-security-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The name of the resource group. | Optional |
| security_group_name | The name of the security group. | Required |
| security_rule_name | The name of the rule to be updated. | Required |
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Optional |
| action | Whether to allow the traffic. Possible values are "Allow" and "Deny". Possible values are: Allow, Deny. | Optional |
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP", and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional |
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any". | Optional |
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096". | Optional |
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional |
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional |
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional |
| description | A description to add to the rule. | Optional |
| access | The network traffic is allowed or denied. Possible values are: Allow, Deny. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.NSGRule.name | String | The rule's name. |
| Azure.NSGRule.id | String | The rule's ID. |
| Azure.NSGRule.etag | String | The rule's ETag. |
| Azure.NSGRule.type | String | The rule's type. |
| Azure.NSGRule.provisioningState | String | The rule's provisioning state. |
| Azure.NSGRule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", "\*". |
| Azure.NSGRule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. |
| Azure.NSGRule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. |
| Azure.NSGRule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. |
| Azure.NSGRule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. |
| Azure.NSGRule.sourceAddressPrefix | String | The source address. |
| Azure.NSGRule.destinationAddressPrefix | String | The destination address. |
| Azure.NSGRule.access | String | The rule's access. Can be "Allow" or "Deny". |
| Azure.NSGRule.priority | Number | The rule's priority. Can be from 100 to 4096. |
| Azure.NSGRule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". |

### azure-storage-account-update

***
Updates a specific account storage.

#### Base Command

`azure-storage-account-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | The subscription ID. | Optional |
| account_name | The name of the storage account. | Required |
| sku | Gets or sets the SKU name, Required for account creation; optional for update. Possible values are: Premium_LRS, Premium_ZRS, Standard_GRS, Standard_GZRS, Standard_LRS, Standard_RAGRS, Standard_RAGZRS, Standard_ZRS. | Optional |
| kind | Indicates the type of storage account, Required for account creation; optional for update. Possible values are: Storage, StorageV2, BlobStorage, FileStorage, BlockBlobStorage. | Optional |
| location | Gets or sets the location of the resource. The geo region of a resource cannot be changed once it is created, but if an identical geo region is specified on update, the request will succeed. Required for account creation; optional for update. Possible values are: eastus, eastus2, westus, westeurope, eastasia, southeastasia, japaneast, japanwest, northcentralus, southcentralus, centralus, northeurope, brazilsouth, australiaeast, australiasoutheast, southindia, centralindia, westindia, canadaeast, canadacentral, westus2, westcentralus, uksouth, ukwest, koreacentral, koreasouth, francecentral, australiacentral, southafricanorth, uaenorth, switzerlandnorth, germanywestcentral, norwayeast. | Optional |
| tags | Gets or sets a list of tags that describe the resource. | Optional |
| custom_domain_name | Gets or sets the custom domain name assigned to the storage account. | Optional |
| use_sub_domain_name | Indicates whether indirect CName validation is enabled. Possible values are: true, false. | Optional |
| enc_key_source | The encryption keySource. Possible values are: Microsoft.Storage, Microsoft.Keyvault. | Optional |
| enc_requireInfrastructureEncryption | Indicates whether the service applies a secondary layer of encryption with platform managed keys for data at rest. Possible values are: true, false. | Optional |
| enc_keyvault_key_name | The name of KeyVault key. | Optional |
| enc_keyvault_key_version | The version of KeyVault key. | Optional |
| enc_keyvault_uri | The Uri of KeyVault. | Optional |
| access_tier | The access tier for the account. Required where kind = BlobStorage. Possible values are: Hot, Cool. | Optional |
| supports_https_traffic_only | Allows https traffic only to storage service if sets to true. Possible values are: true, false. | Optional |
| is_hns_enabled | Account HierarchicalNamespace enabled if sets to true. Possible values are: true, false. | Optional |
| large_file_shares_state | If set to Enabled, allows large file shares. Possible values are: Disabled, Enabled. | Optional |
| allow_blob_public_access | If set to true, allows public access to all blobs or containers in the storage account. Possible values are: true, false. | Optional |
| minimum_tls_version | Sets the minimum TLS version to be permitted on requests to storage. Possible values are: TLS1_0, TLS1_1, TLS1_2. | Optional |
| network_ruleset_bypass | Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are: AzureServices, Logging, Metrics, None. | Optional |
| network_ruleset_default_action | Specifies the default action of allow or deny when no other rules match. Possible values are: Allow, Deny. | Optional |
| network_ruleset_ipRules | Sets the IP ACL rules. | Optional |
| virtual_network_rules | Sets the virtual network rules. | Optional |
| allow_cross_tenant_replication | Allow or disallow cross AAD tenant object replication. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.StorageAccount.id | String | Fully qualified resource ID for the resource. |
| Azure.StorageAccount.kind | String | The kind of storage account. |
| Azure.StorageAccount.location | String | The geo-location where the resource lives. |
| Azure.StorageAccount.name | String | The name of the resource. |
| Azure.StorageAccount.properties.isHnsEnabled | Boolean | Account HierarchicalNamespace enabled if sets to true. |
| Azure.StorageAccount.properties.allowBlobPublicAccess | Boolean | If set to true \(default\), allows public access to all blobs or containers in the storage account. |
| Azure.StorageAccount.properties.minimumTlsVersion | String | Sets the minimum TLS version to be permitted on requests to storage. Default is TLS 1.0. |
| Azure.StorageAccount.properties.allowSharedKeyAccess | Boolean | Whether the storage account permits requests to be authorized with the account access key via Shared Key. If false, then all requests \(including shared access signatures\) must be authorized with Azure Active Directory \(Azure AD\). |
| Azure.StorageAccount.properties.creationTime | Date | The creation date and time of the storage account in UTC. |
| Azure.StorageAccount.properties.primaryEndpoints | String | The URLs that are used to retrieve a public blob, queue, or table object. |
| Azure.StorageAccount.properties.primaryLocation | String | The storage account primary data center location. |
| Azure.StorageAccount.properties.provisioningState | String | The status of the storage account at the time the operation was called. |
| Azure.StorageAccount.properties.routingPreference.routingChoice | String | The kind of network routing the user chose. |
| Azure.StorageAccount.properties.routingPreference.publishMicrosoftEndpoints | Boolean | Whether Microsoft routing storage endpoints are to be published. |
| Azure.StorageAccount.properties.routingPreference.publishInternetEndpoints | Boolean | Whether internet routing storage endpoints are to be published. |
| Azure.StorageAccount.properties.encryption | String | Encryption settings to be used for server-side encryption for the storage account. |
| Azure.StorageAccount.properties.secondaryLocation | String | The geo-replicated secondary location for the storage account. Only available if the accountType is Standard_GRS or Standard_RAGRS. |
| Azure.StorageAccount.properties.statusOfPrimary | String | Whether the storage account primary location is available or unavailable. |
| Azure.StorageAccount.properties.statusOfSecondary | String | Whether the storage account secondary location is available or unavailable. Only available if the SKU name is Standard_GRS or Standard_RAGRS. |
| Azure.StorageAccount.properties.supportsHttpsTrafficOnly | Boolean | If set to true, allows https traffic only to storage service. |
| Azure.StorageAccount.sku.name | String | The SKU name. Required for account creation; optional for update. |
| Azure.StorageAccount.sku.tier | String | The SKU tier. This is based on the SKU name. |
| Azure.StorageAccount.tags | unknown | Resource tags. |
| Azure.StorageAccount.type | String | The storage account type. |

### azure-storage-blob-service-properties-set

***
Sets properties for the blob service in a specific account storage.

#### Base Command

`azure-storage-blob-service-properties-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | The subscription ID. | Optional |
| account_name | The name of the storage account. | Required |
| delete_rentention_policy_enabled | Whether DeleteRetentionPolicy is enabled. Possible values are: true, false. | Optional |
| delete_rentention_policy_days | The number of days the deleted item should be retained. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.StorageAccountBlobServiceProperties.id | String | The resource ID. |
| Azure.StorageAccountBlobServiceProperties.name | String | The name of the resource. |
| Azure.StorageAccountBlobServiceProperties.type | String | The type of the resource. |
| Azure.StorageAccountBlobServiceProperties.properties.cors | String | Specifies CORS rules for the Blob service. |
| Azure.StorageAccountBlobServiceProperties.properties.defaultServiceVersion | Date | The default version for requests to the Blob service if an incoming request's version is not specified. Possible values include version 2008-10-27 and all more recent versions. |
| Azure.StorageAccountBlobServiceProperties.properties.deleteRetentionPolicy | unknown | The service properties for soft delete. |
| Azure.StorageAccountBlobServiceProperties.properties.isVersioningEnabled | Boolean | If set to true, enables versioning. |
| Azure.StorageAccountBlobServiceProperties.properties.changeFeed | unknown | The blob service properties for change feed events. |
| Azure.StorageAccountBlobServiceProperties.sku.name | String | The SKU name. |
| Azure.StorageAccountBlobServiceProperties.sku.tier | String | The SKU tier. |

### azure-policy-assignment-create

***
Creates a policy assignment.

#### Base Command

`azure-policy-assignment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy assignment. | Required |
| subscription_id | Subscription ID. | Required |
| scope | The scope of the policy assignment. | Optional |
| policy_definition_id | The ID of the policy definition or policy set definition being assigned. | Optional |
| display_name | The assignment display name. | Optional |
| parameters | The JSON object for policy properties parameters and their values. | Optional |
| description | This message will be part of the response in case of policy violation. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.PolicyAssignment.ID | string | The resource ID of the policy assignment. |
| Azure.PolicyAssignment.Name | string | The name of the policy assignment. |
| Azure.PolicyAssignment.Type | string | The type of the resource \(e.g., 'Microsoft.Authorization/policyAssignments'\). |
| Azure.PolicyAssignment.Location | string | The location of the policy assignment. |
| Azure.PolicyAssignment.Identity | unknown | The managed identity associated with the policy assignment. |
| Azure.PolicyAssignment.Properties.DisplayName | string | The display name of the policy assignment. |
| Azure.PolicyAssignment.Properties.Description | string | The description of the policy assignment. |
| Azure.PolicyAssignment.Properties.PolicyDefinitionId | string | The ID of the policy definition or policy set definition being assigned. |
| Azure.PolicyAssignment.Properties.Scope | string | The scope of the policy assignment. |
| Azure.PolicyAssignment.Properties.NotScopes | unknown | The list of scopes that are excluded from the policy assignment. |
| Azure.PolicyAssignment.Properties.Parameters | unknown | The parameter values for the assigned policy rule. |
| Azure.PolicyAssignment.Properties.Metadata | unknown | The metadata associated with the policy assignment. |
| Azure.PolicyAssignment.Properties.EnforcementMode | string | The policy assignment enforcement mode \(e.g., 'Default' or 'DoNotEnforce'\). |
| Azure.PolicyAssignment.Properties.latestDefinitionVersion | string | The latest version of the policy definition available. This is only present if requested via the $expand query parameter. |
| Azure.PolicyAssignment.Properties.NonComplianceMessages | unknown | The messages that describe why a resource is non-compliant with the policy. |
| Azure.PolicyAssignment.Properties.DefinitionVersion | string | The version of the policy definition to use. |
| Azure.PolicyAssignment.Properties.Overrides | unknown | The policy property value overrides. |
| Azure.PolicyAssignment.Properties.ResourceSelectors | unknown | The resource selectors to filter policies by resource properties. |
| Azure.PolicyAssignment.SystemData | unknown | The system metadata relating to this resource. |

### azure-postgres-config-set

***
Updates a configuration of a server.

#### Base Command

`azure-postgres-config-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| server_name | Name of the PostgreSQL server. | Required |
| configuration_name | The configuration setting name. | Required |
| subscription_id | Subscription ID. | Optional |
| source | Source of the configuration. | Optional |
| value | Value of the configuration. | Optional |

#### Context Output

There is no context output for this command.

### azure-webapp-config-set

***
Updates the configuration settings of an existing Azure Web App.

#### Base Command

`azure-webapp-config-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| name | Name of the Web App. | Required |
| http20_enabled | Configures a web site to allow clients to connect over http2.0. Possible values are: true, false. | Optional |
| remote_debugging_enabled | True if remote debugging is enabled; otherwise, false. Possible values are: true, false. | Optional |
| min_tls_version | Configures the minimum version of TLS required for SSL requests. Possible values are: 1.0, 1.1, 1.2, 1.3. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.WebAppConfig.id | String | Resource ID. |
| Azure.WebAppConfig.name | String | Resource name. |
| Azure.WebAppConfig.type | String | Resource type. |
| Azure.WebAppConfig.location | String | Resource location. |
| Azure.WebAppConfig.properties.numberOfWorkers | Number | Number of workers. |
| Azure.WebAppConfig.properties.defaultDocuments | Unknown | List of default documents. |
| Azure.WebAppConfig.properties.netFrameworkVersion | String | .NET Framework version. |
| Azure.WebAppConfig.properties.phpVersion | String | PHP version. |
| Azure.WebAppConfig.properties.pythonVersion | String | Python version. |
| Azure.WebAppConfig.properties.nodeVersion | String | Node.js version. |
| Azure.WebAppConfig.properties.powerShellVersion | String | PowerShell version. |
| Azure.WebAppConfig.properties.linuxFxVersion | String | Linux app framework and version. |
| Azure.WebAppConfig.properties.windowsFxVersion | String | Windows container image name. |
| Azure.WebAppConfig.properties.requestTracingEnabled | Boolean | Indicates whether request tracing is enabled. |
| Azure.WebAppConfig.properties.remoteDebuggingEnabled | Boolean | Indicates whether remote debugging is enabled. |
| Azure.WebAppConfig.properties.remoteDebuggingVersion | String | Remote debugging version. |
| Azure.WebAppConfig.properties.http20Enabled | Boolean | Indicates whether HTTP/2 is enabled. |
| Azure.WebAppConfig.properties.minTlsVersion | String | Minimum TLS version required. |
| Azure.WebAppConfig.properties.ftpsState | String | State of FTP / FTPS service. |
| Azure.WebAppConfig.properties.webSocketsEnabled | Boolean | Indicates whether WebSockets are enabled. |
| Azure.WebAppConfig.properties.alwaysOn | Boolean | Indicates whether Always On is enabled. |
| Azure.WebAppConfig.properties.managedPipelineMode | String | Managed pipeline mode. |
| Azure.WebAppConfig.properties.loadBalancing | String | Site load balancing mode. |
| Azure.WebAppConfig.properties.autoHealEnabled | Boolean | Indicates whether Auto Heal is enabled. |
| Azure.WebAppConfig.properties.autoHealRules | Unknown | Auto Heal rules configuration. |
| Azure.WebAppConfig.properties.cors.allowedOrigins | Unknown | CORS allowed origins. |
| Azure.WebAppConfig.properties.cors.supportCredentials | Boolean | Indicates whether CORS supports credentials. |
| Azure.WebAppConfig.properties.apiDefinition.url | String | URL of the API definition. |
| Azure.WebAppConfig.properties.apiManagementConfig.id | String | Azure API management integration ID. |

### azure-webapp-auth-update

***
Updates the authentication and authorization settings of an existing Azure Web App.

#### Base Command

`azure-webapp-auth-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| name | Name of the Web App. | Required |
| enabled | True if the Authentication / Authorization feature is enabled for the current app; otherwise, false. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.WebAppAuth.id | String | Resource ID. |
| Azure.WebAppAuth.name | String | Resource Name. |
| Azure.WebAppAuth.type | String | Resource type. |
| Azure.WebAppAuth.properties.enabled | Boolean | Indicates whether Authentication/Authorization is enabled for the app. |
| Azure.WebAppAuth.properties.runtimeVersion | String | The RuntimeVersion of the Authentication/Authorization feature. |
| Azure.WebAppAuth.properties.unauthenticatedClientAction | String | The action to take when an unauthenticated client attempts to access the app. |
| Azure.WebAppAuth.properties.tokenStoreEnabled | Boolean | Indicates whether the Azure App Service Authentication platform’s token store is enabled. |
| Azure.WebAppAuth.properties.allowedExternalRedirectUrls | Unknown | External URLs that are allowed to be redirected to as part of logging in or logging out of the app. |
| Azure.WebAppAuth.properties.defaultProvider | String | The default authentication provider to use when multiple providers are configured. |
| Azure.WebAppAuth.properties.clientId | String | The Client ID of the app used for AAD login. |
| Azure.WebAppAuth.properties.clientSecret | String | The client secret associated with the AAD app. |
| Azure.WebAppAuth.properties.clientSecretSettingName | String | The app setting that contains the client secret. |
| Azure.WebAppAuth.properties.issuer | String | The OpenID Connect Issuer URI that represents the entity that issues access tokens. |
| Azure.WebAppAuth.properties.allowedAudiences | Unknown | The list of audiences that can receive the authentication tokens. |
| Azure.WebAppAuth.properties.additionalLoginParams | Unknown | Additional parameters to send to the authentication provider. |
| Azure.WebAppAuth.properties.isAadAutoProvisioned | Boolean | True if AAD is auto-provisioned; otherwise false. |
| Azure.WebAppAuth.properties.googleClientId | String | The Client ID of the app used for Google login. |
| Azure.WebAppAuth.properties.googleClientSecret | String | The client secret associated with the Google app. |
| Azure.WebAppAuth.properties.googleClientSecretSettingName | String | The app setting that contains the client secret. |
| Azure.WebAppAuth.properties.facebookAppId | String | The App ID of the Facebook app used for login. |
| Azure.WebAppAuth.properties.facebookAppSecret | String | The app secret associated with the Facebook app. |
| Azure.WebAppAuth.properties.facebookAppSecretSettingName | String | The app setting that contains the Facebook app secret. |
| Azure.WebAppAuth.properties.twitterConsumerKey | String | The OAuth 1.0a consumer key of the Twitter application used for login. |
| Azure.WebAppAuth.properties.twitterConsumerSecret | String | The consumer secret associated with the Twitter application. |
| Azure.WebAppAuth.properties.twitterConsumerSecretSettingName | String | The app setting that contains the Twitter consumer secret. |
| Azure.WebAppAuth.properties.microsoftAccountClientId | String | The OAuth 2.0 client ID for the Microsoft account provider. |
| Azure.WebAppAuth.properties.microsoftAccountClientSecret | String | The client secret for the Microsoft account provider. |
| Azure.WebAppAuth.properties.microsoftAccountClientSecretSettingName | String | The app setting that contains the Microsoft account client secret. |
| Azure.WebAppAuth.properties.appleClientId | String | The client ID for the Apple provider. |
| Azure.WebAppAuth.properties.appleClientSecret | String | The client secret for the Apple provider. |
| Azure.WebAppAuth.properties.appleClientSecretSettingName | String | The app setting that contains the Apple provider client secret. |
| Azure.WebAppAuth.properties.authFilePath | String | The path to the authentication configuration file. |

### azure-mysql-flexible-server-param-set

***
Updates a configuration of a server.

#### Base Command

`azure-mysql-flexible-server-param-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| server_name | Name of the MySQL flexible server. | Required |
| configuration_name | The name of the server configuration. | Required |
| source | Source of the configuration. | Optional |
| value | Value of the configuration. | Optional |

#### Context Output

There is no context output for this command.

### azure-monitor-log-profile-update

***
Updates a log profile in Azure Monitoring REST API.

#### Base Command

`azure-monitor-log-profile-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_profile_name | The name of the log profile to update. | Required |
| subscription_id | subscription ID. | Optional |
| location | Resource location. | Optional |
| retention_policy_days | Number of days to retain logs. | Optional |
| retention_policy_enabled | Whether to enable the retention policy. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.LogProfile.id | String | The fully qualified Azure resource ID for the log profile. |
| Azure.LogProfile.name | String | The name of the log profile. |
| Azure.LogProfile.type | String | The type of the resource \(Microsoft.Insights/logProfiles\). |
| Azure.LogProfile.location | String | The location of the log profile. |
| Azure.LogProfile.tags | Object | Resource tags. |
| Azure.LogProfile.properties.storageAccountId | String | The resource ID of the storage account to which diagnostic logs are delivered. |
| Azure.LogProfile.properties.serviceBusRuleId | String | The service bus rule ID to which diagnostic logs are sent. |
| Azure.LogProfile.properties.locations | Array | A list of regions for which events are collected. |
| Azure.LogProfile.properties.categories | Array | A list of categories of logs that are collected. |
| Azure.LogProfile.properties.retentionPolicy.enabled | Boolean | Specifies whether the retention policy is enabled. |
| Azure.LogProfile.properties.retentionPolicy.days | Number | The number of days for the retention policy. |

### azure-disk-update

***
Updates a disk.

#### Base Command

`azure-disk-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| disk_name | The name of the managed disk that is being created. Supported characters for the name are a-z, A-Z, 0-9, _ and -. The maximum name length is 80 characters. | Required |
| public_network_access | Policy for controlling export on the disk. Possible values are: Disabled, Enabled. | Optional |
| network_access_policy | Policy for accessing the disk via network. Possible values are: AllowAll, AllowPrivate, DenyAll. | Optional |
| data_access_auth_mode | Additional authentication requirements when exporting or uploading to a disk or snapshot. Possible values are: AzureActiveDirectory. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Disk.id | String | Resource ID of the disk. |
| Azure.Disk.name | String | Name of the disk. |
| Azure.Disk.type | String | Type of the resource. |
| Azure.Disk.location | String | Location of the disk. |
| Azure.Disk.tags | unknown | Resource tags. |
| Azure.Disk.managedBy | String | ARM ID of the resource that manages the disk. |
| Azure.Disk.sku | unknown | The disk SKU name. |
| Azure.Disk.zones | unknown | A list of availability zones. |
| Azure.Disk.properties.timeCreated | String | The time when the disk was created. |
| Azure.Disk.properties.diskSizeGB | Number | Size of the disk in GB. |
| Azure.Disk.properties.diskIopsReadWrite | Number | The number of IOPS allowed for this disk. |
| Azure.Disk.properties.diskMBpsReadWrite | Number | The bandwidth allowed for this disk in MBps. |
| Azure.Disk.properties.diskIOPSReadOnly | Number | The number of read-only IOPS for this disk. |
| Azure.Disk.properties.diskMBpsReadOnly | Number | The read-only bandwidth for this disk in MBps. |
| Azure.Disk.properties.diskSizeBytes | Number | The size of the disk in bytes. |
| Azure.Disk.properties.networkAccessPolicy | String | Policy for accessing the disk via network. |
| Azure.Disk.properties.publicNetworkAccess | String | Policy for export on the disk. |
| Azure.Disk.properties.burstingEnabled | Boolean | Whether bursting is enabled on the disk. |
| Azure.Disk.properties.optimization | String | The disk optimization setting. |
| Azure.Disk.properties.diskState | String | The current state of the disk. |
| Azure.Disk.properties.supportedCapabilities | unknown | Supported capabilities of the disk. |
| Azure.Disk.properties.supportedPerformanceTiers | unknown | Supported performance tiers of the disk. |
| Azure.Disk.properties.supportedDiskTypes | unknown | Supported disk types for the disk. |
| Azure.Disk.properties.provisioningState | unknown | The provisioning state of the disk. |
| Azure.Disk.properties.timeModified | unknown | The time when the disk was last modified. |
| Azure.Disk.properties.diskAccessId | String | The ARM ID of the DiskAccess resource. |
| Azure.Disk.properties.networkProfile | unknown | The network profile of the disk. |
| Azure.Disk.properties.creationData | unknown | Disk creation data. |
| Azure.Disk.properties.encryption | unknown | Encryption settings for the disk. |
| Azure.Disk.properties.encryptionSettingsCollection | unknown | A collection of encryption settings. |
| Azure.Disk.properties.encryptionType | String | The type of key used to encrypt the data on the disk. |
| Azure.Disk.properties.securityProfile | unknown | Security profile for the disk. |
| Azure.Disk.properties.tieringProfile | unknown | Tiering profile for the disk. |
| Azure.Disk.properties.supportedTierList | unknown | List of supported tiers for the disk. |
| Azure.Disk.properties.availabilityZone | String | Availability zone of the disk. |
| Azure.Disk.properties.dataAccessAuthMode | String | Additional authentication requirements when exporting or uploading to a disk. |
| Azure.Disk.properties.osType | String | The operating system type. |
| Azure.Disk.properties.hyperVGeneration | String | The HyperVGenerationType of the virtual machine. |
| Azure.Disk.properties.lastOwnershipUpdateTime | String | The last time ownership of the disk was updated. |

### azure-webapp-update

***
Updates an Azure Web App.

#### Base Command

`azure-webapp-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| name | Name of the Web App. | Required |
| identity_type | Managed service identity type. Possible values are: None, SystemAssigned. | Optional |
| https_only | Configures the web site to accept only https requests. Possible values are: true, false. | Optional |
| client_cert_enabled | Configures the web site to accept only https requests. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.WebApp.id | String | Fully qualified resource ID for the web app. |
| Azure.WebApp.name | String | The name of the web app. |
| Azure.WebApp.type | String | The resource type, e.g., Microsoft.Web/sites. |
| Azure.WebApp.location | String | Geographic location of the web app. |
| Azure.WebApp.kind | String | The kind of the app, e.g., app, functionapp, etc. |
| Azure.WebApp.tags | unknown | Resource tags as key-value pairs. |
| Azure.WebApp.identity.type | String | The type of managed identity \(SystemAssigned, UserAssigned, etc.\). |
| Azure.WebApp.identity.principalId | String | The principal ID of the system-assigned identity. |
| Azure.WebApp.identity.tenantId | String | The tenant ID of the system-assigned identity. |
| Azure.WebApp.identity.userAssignedIdentities | unknown | The list of user-assigned identities associated with the web app. |
| Azure.WebApp.properties.state | String | Current state of the web app \(Running, Stopped, etc.\). |
| Azure.WebApp.properties.enabled | Boolean | Whether the web app is enabled. |
| Azure.WebApp.properties.defaultHostName | String | Default host name of the web app. |
| Azure.WebApp.properties.hostNames | unknown | List of host names associated with the web app. |
| Azure.WebApp.properties.repositorySiteName | String | Name of the repository site. |
| Azure.WebApp.properties.clientAffinityEnabled | Boolean | Whether client affinity is enabled. |
| Azure.WebApp.properties.clientCertEnabled | Boolean | Whether client certificates are enabled. |
| Azure.WebApp.properties.clientCertExclusionPaths | String | Paths to exclude from client certificate authentication. |
| Azure.WebApp.properties.hostingEnvironment | String | App Service Environment to use for the web app. |
| Azure.WebApp.properties.serverFarmId | String | Resource ID of the associated App Service plan. |
| Azure.WebApp.properties.reserved | Boolean | Whether the web app is on a Linux plan. |
| Azure.WebApp.properties.isXenon | Boolean | Whether the web app is hosted in Xenon. |
| Azure.WebApp.properties.hyperV | Boolean | Whether Hyper-V is enabled for the web app. |
| Azure.WebApp.properties.siteConfig.appSettings | unknown | List of app settings. |
| Azure.WebApp.properties.siteConfig.metadata | unknown | List of metadata settings. |
| Azure.WebApp.properties.siteConfig.connectionStrings | unknown | List of connection strings. |
| Azure.WebApp.properties.siteConfig.localMySqlEnabled | Boolean | Whether local MySQL is enabled. |
| Azure.WebApp.properties.siteConfig.alwaysOn | Boolean | Whether Always On is enabled. |
| Azure.WebApp.properties.siteConfig.http20Enabled | Boolean | Whether HTTP/2 is enabled. |
| Azure.WebApp.properties.siteConfig.minTlsVersion | String | Minimum TLS version required. |
| Azure.WebApp.properties.siteConfig.ftpsState | String | FTPS state \(Disabled, AllAllowed, etc.\). |
| Azure.WebApp.properties.siteConfig.linuxFxVersion | String | Runtime stack for Linux apps. |
| Azure.WebApp.properties.siteConfig.windowsFxVersion | String | Runtime stack for Windows apps. |
| Azure.WebApp.properties.siteConfig.numberOfWorkers | Number | Number of workers allocated. |
| Azure.WebApp.properties.siteConfig.webSocketsEnabled | Boolean | Whether WebSockets are enabled. |
| Azure.WebApp.properties.siteConfig.preWarmedInstanceCount | Number | Number of pre-warmed instances. |
| Azure.WebApp.properties.siteConfig.acrUseManagedIdentityCreds | Boolean | Whether ACR uses managed identity credentials. |
| Azure.WebApp.properties.siteConfig.acrUserManagedIdentityID | String | User-assigned identity ID for ACR. |
| Azure.WebApp.properties.siteConfig.scmType | String | Source control management type. |
| Azure.WebApp.properties.siteConfig.use32BitWorkerProcess | Boolean | Whether to use 32-bit worker process. |
| Azure.WebApp.properties.siteConfig.autoHealEnabled | Boolean | Whether auto-heal is enabled. |
| Azure.WebApp.properties.siteConfig.autoHealRules | unknown | Auto-heal rules configuration. |
| Azure.WebApp.properties.siteConfig.tracingOptions | String | Tracing options. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingEnabled | Boolean | Whether remote debugging is enabled. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingVersion | String | Remote debugging version. |
| Azure.WebApp.properties.siteConfig.detailedErrorLoggingEnabled | Boolean | Whether detailed error logging is enabled. |
| Azure.WebApp.properties.siteConfig.httpLoggingEnabled | Boolean | Whether HTTP logging is enabled. |
| Azure.WebApp.properties.siteConfig.requestTracingEnabled | Boolean | Whether request tracing is enabled. |
| Azure.WebApp.properties.siteConfig.requestTracingExpirationTime | DateTime | Request tracing expiration time. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingEnabled | Boolean | Whether remote debugging is enabled. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingVersion | String | Remote debugging version. |
| Azure.WebApp.properties.siteConfig.defaultDocuments | unknown | List of default documents. |
| Azure.WebApp.properties.siteConfig.virtualApplications | unknown | List of virtual applications. |
| Azure.WebApp.properties.siteConfig.loadBalancing | String | Load balancing settings. |
| Azure.WebApp.properties.siteConfig.experiments | unknown | Experiments configuration. |
| Azure.WebApp.properties.siteConfig.limits | unknown | Site limits configuration. |
| Azure.WebApp.properties.siteConfig.autoSwapSlotName | String | Auto-swap slot name. |
| Azure.WebApp.properties.siteConfig.localMySqlEnabled | Boolean | Whether local MySQL is enabled. |
| Azure.WebApp.properties.siteConfig.ipSecurityRestrictions | unknown | IP security restrictions. |
| Azure.WebApp.properties.siteConfig.scmIpSecurityRestrictions | unknown | SCM IP security restrictions. |
| Azure.WebApp.properties.siteConfig.scmIpSecurityRestrictionsUseMain | Boolean | Whether SCM IP restrictions use main settings. |
| Azure.WebApp.properties.siteConfig.cors | unknown | CORS settings. |
| Azure.WebApp.properties.siteConfig.push | unknown | Push settings. |
| Azure.WebApp.properties.siteConfig.apiDefinition | unknown | API definition settings. |
| Azure.WebApp.properties.siteConfig.apiManagementConfig | unknown | API management configuration. |
| Azure.WebApp.properties.siteConfig.autoHealEnabled | Boolean | Whether auto-heal is enabled. |
| Azure.WebApp.properties.siteConfig.autoHealRules | unknown | Auto-heal rules configuration. |
| Azure.WebApp.properties.siteConfig.tracingOptions | String | Tracing options. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingEnabled | Boolean | Whether remote debugging is enabled. |
| Azure.WebApp.properties.siteConfig.remoteDebuggingVersion | String | Remote debugging version. |
| Azure.WebApp.properties.siteConfig.detailedErrorLoggingEnabled | Boolean | Whether detailed error logging is enabled. |
| Azure.WebApp.properties.siteConfig.httpLoggingEnabled | Boolean | Whether HTTP logging is enabled. |
| Azure.WebApp.properties.siteConfig.requestTracingEnabled | Boolean | Whether request tracing is enabled. |

### azure-acr-update

***
Updates a container registry.

#### Base Command

`azure-acr-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| registry_name | The name of the container registry. | Required |
| allow_exports | Whether artifacts can be exported. Possible values are: disabled, enabled. | Optional |
| public_network_access | Whether public network access is allowed for the container registry. Possible values are: disabled, enabled. | Optional |
| anonymous_pull_enabled | Whether to enable registry-wide pulls from unauthenticated clients. Possible values are: true, false. | Optional |
| authentication_as_arm_policy | Whether the policy is enabled or not. Possible values are: disabled, enabled. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.ACR.id | String | The resource ID. |
| Azure.ACR.identity | Unknown | The identity of the container registry. |
| Azure.ACR.location | String | The location of the resource. |
| Azure.ACR.name | String | The name of the resource. |
| Azure.ACR.properties.adminUserEnabled | Boolean | The value that indicates whether the admin user is enabled. |
| Azure.ACR.properties.anonymousPullEnabled | Boolean | Enables registry-wide pull from unauthenticated clients. |
| Azure.ACR.properties.creationDate | String | The creation date of the container registry in ISO8601 format. |
| Azure.ACR.properties.dataEndpointEnabled | Boolean | Enable a single data endpoint per region for serving data. |
| Azure.ACR.properties.dataEndpointHostNames | Unknown | List of host names that will serve data when dataEndpointEnabled is true. |
| Azure.ACR.properties.encryption | Unknown | The encryption settings of container registry. |
| Azure.ACR.properties.loginServer | String | The URL that can be used to log into the container registry. |
| Azure.ACR.properties.networkRuleBypassOptions | String | Whether to allow trusted Azure services to access a network restricted registry. |
| Azure.ACR.properties.networkRuleSet | Unknown | The network rule set for a container registry. |
| Azure.ACR.properties.policies | Unknown | The policies for a container registry. |
| Azure.ACR.properties.privateEndpointConnections | Unknown | List of private endpoint connections for a container registry. |
| Azure.ACR.properties.provisioningState | String | The provisioning state of the container registry at the time the operation was called. |
| Azure.ACR.properties.publicNetworkAccess | String | Whether or not public network access is allowed for the container registry. |
| Azure.ACR.properties.status | Unknown | The status of the container registry at the time the operation was called. |
| Azure.ACR.properties.zoneRedundancy | String | Whether or not zone redundancy is enabled for this container registry. |
| Azure.ACR.sku | Unknown | The SKU of the container registry. |
| Azure.ACR.systemData | Unknown | Metadata pertaining to creation and last modification of the resource. |
| Azure.ACR.tags | Unknown | The tags of the resource. |
| Azure.ACR.type | String | The type of the resource. |

### azure-postgres-server-update

***
Updates an existing server.

#### Base Command

`azure-postgres-server-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. | Optional |
| subscription_id | Subscription ID. | Optional |
| server_name | Name of the PostgreSQL server. | Required |
| ssl_enforcement | Whether to enable SSL authentication when connecting to the server. Possible values are: Disabled, Enabled. | Optional |

#### Context Output

There is no context output for this command.

### azure-key-vault-update

***
Updates a key vault in the specified subscription.

#### Base Command

`azure-key-vault-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | Key Vault name. | Required |
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The name of the resource group. | Optional |
| enable_purge_protection | Whether protection against purge is enabled for this vault. This functionality is always enabled, it cannot be disabled. Possible values are: true. | Optional |
| enable_soft_delete | Whether soft delete is enabled for this key vault. This functionality is always enabled, it cannot be disabled. Possible values are: true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.KeyVault.id | String | Resource ID. |
| Azure.KeyVault.name | String | Key Vault name. |
| Azure.KeyVault.type | String | Resource type in Azure. |
| Azure.KeyVault.location | String | Key Vault location. |
| Azure.KeyVault.tags | unknown | Resource tags. |
| Azure.KeyVault.properties.sku.family | String | SKU family name. |
| Azure.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. |
| Azure.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. |
| Azure.KeyVault.properties.accessPolicies | unknown | An array of 0 to 16 identities that have access to the key vault. All identities in the array must use the same tenant ID as the key vault's tenant ID. |
| Azure.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. |
| Azure.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. |
| Azure.KeyVault.properties.accessPolicies.permissions | unknown | Permissions the identity has for keys, secrets and certificates. |
| Azure.KeyVault.properties.enabledForDeployment | Boolean | Whether Azure Virtual Machines are allowed to retrieve certificates stored as secrets from the key vault. |
| Azure.KeyVault.properties.enabledForDiskEncryption | Boolean | Whether Azure Disk Encryption is allowed to retrieve secrets from the vault and unwrap keys. |
| Azure.KeyVault.properties.enabledForTemplateDeployment | Boolean | Whether Azure Resource Manager is allowed to retrieve secrets from the key vault. |
| Azure.KeyVault.properties.enableSoftDelete | Boolean | Whether soft delete is enabled for this key vault. |
| Azure.KeyVault.properties.enablePurgeProtection | Boolean | Whether purge protection is enabled for this key vault. |
| Azure.KeyVault.properties.enableRbacAuthorization | Boolean | Whether Azure Key Vault uses Role Based Access Control \(RBAC\) for authorization of data actions. |
| Azure.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets. |
| Azure.KeyVault.properties.provisioningState | String | The current provisioning state. |
| Azure.KeyVault.properties.privateEndpointConnections | unknown | List of private endpoint connections associated with the key vault. |
| Azure.KeyVault.properties.networkAcls | unknown | Rules governing the accessibility of the key vault from specific network locations. |
| Azure.KeyVault.properties.networkAcls.bypass | String | What traffic can bypass network rules. |
| Azure.KeyVault.properties.networkAcls.defaultAction | String | The default action when no rules match from ipRules and virtualNetworkRules. |
| Azure.KeyVault.properties.networkAcls.ipRules | unknown | The list of IP address rules. |
| Azure.KeyVault.properties.networkAcls.virtualNetworkRules | unknown | The list of virtual network rules. |

### azure-sql-db-threat-policy-update

***
Updates the database's threat detection policy.

#### Base Command

`azure-sql-db-threat-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required |
| db_name | Database name. | Required |
| email_account_admins_enabled | Whether the alert is sent to the account administrators. Possible values: "true" and "false". Possible values are: true, false. | Optional |
| subscription_id | Subscription ID. | Optional |
| resource_group_name | The name of the resource group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.SqlDBThreatPolicy.kind | String | Kind of threat policy. |
| Azure.SqlDBThreatPolicy.location | String | Threat policy location. |
| Azure.SqlDBThreatPolicy.id | String | Threat policy ID. |
| Azure.SqlDBThreatPolicy.name | String | Threat policy name. |
| Azure.SqlDBThreatPolicy.type | String | Threat policy type. |
| Azure.SqlDBThreatPolicy.state | String | Threat policy state. |
| Azure.SqlDBThreatPolicy.creationTime | String | Threat policy creation time. |
| Azure.SqlDBThreatPolicy.retentionDays | Number | Number of days to keep in the Threat Detection audit logs. |
| Azure.SqlDBThreatPolicy.storageAccountAccessKey | String | The identifier key of the Threat Detection audit storage account. |
| Azure.SqlDBThreatPolicy.storageEndpoint | String | Threat Detection audit storage account. |
| Azure.SqlDBThreatPolicy.emailAccountAdmins | Boolean | Email accounts administrators who the alert is sent to. |
| Azure.SqlDBThreatPolicy.emailAddresses | String | List of email addresses to which the alert is sent. |
| Azure.SqlDBThreatPolicy.disabledAlerts | String | List of alerts that are disabled, or an empty string if no alerts are disabled. |
| Azure.SqlDBThreatPolicy.useServerDefault | unknown | Whether to use the default server policy. |
| Azure.SqlDBThreatPolicy.databaseName | String | The name of the database that the threat policy is related to. |
| Azure.SqlDBThreatPolicy.serverName | String | The name of server that the threat policy is related to. |

### azure-sql-db-transparent-data-encryption-set

***
Updates a logical database's transparent data encryption configuration.

#### Base Command

`azure-sql-db-transparent-data-encryption-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required |
| db_name | Database name. | Required |
| state | The state of the transparent data encryption. Possible values are: Disabled, Enabled. | Required |
| subscription_id | Subscription ID. | Optional |
| resource_group_name | The name of the resource group. | Optional |

#### Context Output

There is no context output for this command.

### azure-cosmos-db-update

***
Updates the properties of an existing Azure Cosmos DB database account.

#### Base Command

`azure-cosmos-db-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | Cosmos DB database account name. | Required |
| disable_key_based_metadata_write_access | Whether to disable write operations on metadata resources via account keys. Possible values are: true, false. | Optional |
| subscription_id | Subscription ID. | Optional |
| resource_group_name | The name of the resource group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.CosmosDB.id | String | The unique resource identifier of the ARM resource. |
| Azure.CosmosDB.name | String | The name of the ARM resource. |
| Azure.CosmosDB.location | String | The location of the resource group to which the resource belongs. |
| Azure.CosmosDB.kind | String | The database account type. |
| Azure.CosmosDB.identity.type | String | The type of identity used for the resource. |
| Azure.CosmosDB.identity.userAssignedIdentities | Dictionary | The list of user identities associated with the resource. |
| Azure.CosmosDB.properties.analyticalStorageConfiguration.schemaType | String | The analytical storage schema types. |
| Azure.CosmosDB.properties.apiProperties | Dictionary | API specific properties. |
| Azure.CosmosDB.properties.backupPolicy | unknown | The policy for taking backups on an account. |
| Azure.CosmosDB.properties.capabilities | List | List of Cosmos DB capabilities for the account. |
| Azure.CosmosDB.properties.capacity | Integer | Properties related to capacity enforcement on an account. |
| Azure.CosmosDB.properties.connectorOffer | String | The Cassandra connector offer type for the Cosmos DB database account. |
| Azure.CosmosDB.properties.consistencyPolicy | String | The consistency policy for the Cosmos DB database account. |
| Azure.CosmosDB.properties.cors | List | The CORS policy for the Cosmos DB database account. |
| Azure.CosmosDB.properties.createMode | String | The mode of account creation. |
| Azure.CosmosDB.properties.customerManagedKeyStatus | String | Status of the Customer Managed Key feature on the account. |
| Azure.CosmosDB.properties.databaseAccountOfferType | String | The offer type for the Cosmos DB database account. |
| Azure.CosmosDB.properties.defaultIdentity | String | The default identity for accessing key vault used in features like customer managed keys. |
| Azure.CosmosDB.properties.disableKeyBasedMetadataWriteAccess | Boolean | Whether write operations on metadata resources via account keys is disabled. |
| Azure.CosmosDB.properties.disableLocalAuth | Boolean | Whether local authentication is disabled. |
| Azure.CosmosDB.properties.documentEndpoint | String | The connection endpoint for the Cosmos DB database account. |
| Azure.CosmosDB.properties.enableAnalyticalStorage | Boolean | Whether storage analytics are enabled. |
| Azure.CosmosDB.properties.enableAutomaticFailover | Boolean | Enables automatic failover of the write region. |
| Azure.CosmosDB.properties.enableBurstCapacity | Boolean | Whether Burst Capacity is enabled. |
| Azure.CosmosDB.properties.enableCassandraConnector | Boolean | Enables the Cassandra connector on the Cosmos DB account. |
| Azure.CosmosDB.properties.enableFreeTier | Boolean | Whether Free Tier is enabled. |
| Azure.CosmosDB.properties.enableMultipleWriteLocations | Boolean | Enables the account to write in multiple locations. |
| Azure.CosmosDB.properties.enablePartitionMerge | Boolean | Whether Partition Merge is enabled. |
| Azure.CosmosDB.properties.enablePerRegionPerPartitionAutoscale | Boolean | Whether PerRegionPerPartitionAutoscale is enabled. |
| Azure.CosmosDB.properties.failoverPolicies | List | An array that contains the regions ordered by their failover priorities. |
| Azure.CosmosDB.properties.instanceId | String | A unique identifier assigned to the database account. |
| Azure.CosmosDB.properties.ipRules | List | List of IP rules. |
| Azure.CosmosDB.properties.isVirtualNetworkFilterEnabled | Boolean | Whether the Virtual Network ACL rules are enabled. |
| Azure.CosmosDB.properties.keyVaultKeyUri | String | The URI of the key vault. |
| Azure.CosmosDB.properties.keysMetadata | Dictionary | Metadata related to each access key for the given Cosmos DB database account. |
| Azure.CosmosDB.properties.locations | List | An array that contains all of the locations enabled for the Cosmos DB account. |
| Azure.CosmosDB.properties.minimalTlsVersion | String | The minimum allowed TLS version. |
| Azure.CosmosDB.properties.networkAclBypass | String | Which services are allowed to bypass firewall checks. |
| Azure.CosmosDB.properties.networkAclBypassResourceIds | List | List of resource IDs that are allowed to bypass firewall checks. |
| Azure.CosmosDB.properties.privateEndpointConnections | List | List of private endpoint connections. |
| Azure.CosmosDB.properties.provisioningState | String | The status of the Cosmos DB account at the time the operation was called. |
| Azure.CosmosDB.properties.readLocations | List | An array that contains the read locations enabled for the Cosmos DB account. |
| Azure.CosmosDB.properties.virtualNetworkRules | List | List of Virtual Network ACL rules. |
| Azure.CosmosDB.properties.writeLocations | List | An array that contains the write locations enabled for the Cosmos DB account. |
