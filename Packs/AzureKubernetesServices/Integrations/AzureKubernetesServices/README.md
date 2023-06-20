Deploy and manage containerized applications with a fully managed Kubernetes service.
This integration was integrated and tested with API version 2023-02-01 of AKS.

# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

* The application must have **user_impersonation** permission (can be found in *API permissions* section of the Azure Kubernetes Services app registrations).
* The application must allow **public client flows** (can be found under the *Authentication* section of the Azure Kubernetes Services app registrations).
* The application must allow public client flows (found under the **Authentication** section of the app) for Device-code based authentications.

In case you want to use Device code flow, you must allow public client flows (can be found under the **Authentication** section of the app).

### Authentication Using the User - Authentication Flow

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the user_auth_flow option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Save the instance.
8. Run the `!azure-ks-generate-login-url` command in the War Room and follow the instruction.
9.  Run the ***!azure-ks-auth-test*** command - a 'Success' message should be printed to the War Room.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (ab217a43-e09b-4f80-ae93-482fc7a3d1a3).

### Authentication Using the Device Code Flow
Follow these steps for a self-deployed configuration:

1. Fill in the required parameters.
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
3. Run the ***!azure-ks-auth-start*** command. 
4. Follow the instructions that appear.
5. Run the ***!azure-ks-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

## Configure Azure Kubernetes Services on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Kubernetes Services.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID |  | False |
    | Authentication Type | Type of authentication - can be Authorization Code Flow \(recommended\), Device Code Flow, or Azure Managed Identities. | True |
    | Tenant ID (for authorization code mode) |  | False |
    | Client Secret (for authorization code mode) |  | False |
    | Client Secret (for authorization code mode) |  | False |
    | Application redirect URI (for authorization code mode) |  | False |
    | Authorization code | for user-auth mode - received from the authorization step. see Detailed Instructions \(?\) section | False |
    | Authorization code |  | False |
    | Azure Managed Identities Client ID | The Managed Identities client id for authentication - relevant only if the integration is running on Azure VM. | False |
    | Default Subscription ID | There are two options to insert the specified value, either in the configuration or directly within the commands. However, inserting values in both places will cause an override by the command value. | True |
    | Default Resource Group Name | There are two options to insert the specified value, either in the configuration or directly within the commands. However, inserting values in both places will cause an override by the command value. | True |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-ks-auth-test

***
Tests the connectivity to Azure.

#### Base Command

`azure-ks-auth-test`

#### Input

There are no input arguments for this command.

#### Human Readable Output
>✅ Success!


### azure-ks-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`azure-ks-auth-start`

#### Input

There are no input arguments for this command.

#### Human Readable Output
>### Authorization instructions
>        1. To sign in, use a web browser to open the page:
>            [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
>           and enter the code **XXXXXXXX** to authenticate.
>        2. Run the ***!azure-ks-auth-complete*** command in the War Room.



### azure-ks-auth-complete
***
Run this command to complete the authorization process. Should be used after running the ***azure-ks-auth-start*** command.


#### Base Command

`azure-ks-auth-complete`
#### Input

There are no input arguments for this command.

#### Human Readable Output
>✅ Authorization completed successfully.


### azure-ks-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-ks-auth-reset`
#### Input

There are no input arguments for this command.

#### Human Readable Output

>Authorization was reset successfully. You can now run ***!azure-ks-auth-start*** and ***!azure-ks-auth-complete***.

### azure-ks-clusters-list

***
Gets a list of managed clusters in the specified subscription.

#### Base Command

`azure-ks-clusters-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Subscription ID'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKS.ManagedCluster.id | String | Resource ID. | 
| AzureKS.ManagedCluster.location | String | Resource location. | 
| AzureKS.ManagedCluster.name | String | Resource name. | 
| AzureKS.ManagedCluster.tags | Unknown | Resource tags. | 
| AzureKS.ManagedCluster.type | String | Resource type. | 
| AzureKS.ManagedCluster.properties.provisioningState | String | The current deployment or provisioning state, which only appears in the response. | 
| AzureKS.ManagedCluster.properties.kubernetesVersion | String | Version of Kubernetes specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.maxAgentPools | Number | The maximum number of agent pools for the managed cluster. | 
| AzureKS.ManagedCluster.properties.dnsPrefix | String | DNS prefix specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.fqdn | String | FQDN for the master pool. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.name | String | Unique name of the agent pool profile in the context of the subscription and resource group. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.count | Number | Number of agents \(VMs\) to host Docker containers. Allowed values must be in the range of 0 to 100 \(inclusive\) for user pools and in the range of 1 to 100 \(inclusive\) for system pools. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.vmSize | String | Size of agent VMs. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.maxPods | Number | Maximum number of pods that can run on a node. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.osType | String | The operating system type, either Linux or Windows. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.provisioningState | String | The current deployment or provisioning state. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.orchestratorVersion | String | Version of the orchestrator specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.linuxProfile.adminUsername | String | The name of the administrator account. | 
| AzureKS.ManagedCluster.properties.linuxProfile.ssh.publicKeys.keyData | String | Certificate public key used to authenticate with VMs through SSH. | 
| AzureKS.ManagedCluster.properties.servicePrincipalProfile.clientId | String | The ID for the service principal. | 
| AzureKS.ManagedCluster.properties.nodeResourceGroup | String | Name of the resource group containing agent pool nodes. | 
| AzureKS.ManagedCluster.properties.enableRBAC | Boolean | Whether to enable Kubernetes Role-Based Access Control \(RBAC\). | 
| AzureKS.ManagedCluster.properties.diskEncryptionSetID | String | Resource ID of the disk encryption set to use for enabling encryption at rest. | 
| AzureKS.ManagedCluster.properties.networkProfile.networkPlugin | String | Network plugin used for building Kubernetes network. | 
| AzureKS.ManagedCluster.properties.networkProfile.podCidr | String | A CIDR notation IP range from which to assign pod IPs when kubenet is used. | 
| AzureKS.ManagedCluster.properties.networkProfile.serviceCidr | String | A CIDR notation IP range from which to assign service cluster IPs. | 
| AzureKS.ManagedCluster.properties.networkProfile.dnsServiceIP | String | An IP address assigned to the Kubernetes DNS service. | 
| AzureKS.ManagedCluster.properties.networkProfile.dockerBridgeCidr | String | A CIDR notation IP range assigned to the Docker bridge network. | 
| AzureKS.ManagedCluster.properties.addonProfiles.omsagent.enabled | Boolean | Whether the Operations Management Suite Agent is enabled. | 
| AzureKS.ManagedCluster.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID | String | The resource ID of an existing Log Analytics Workspace to use for storing monitoring data. | 
| AzureKS.ManagedCluster.properties.addonProfiles.httpApplicationRouting.enabled | Boolean | Whether the ingress is configured with automatic public DNS name creation. | 
| AzureKS.ManagedCluster.properties.addonProfiles.httpApplicationRouting.config.HTTPApplicationRoutingZoneName | String | The subscription DNS zone name. | 

#### Command example
```!azure-ks-clusters-list```
#### Context Example
```json
{
    "AzureKS": {
        "ManagedCluster": {
            "id": "/subscriptions/00000000/resourcegroups/aks-integration/providers/Microsoft.ContainerService/managedClusters/aks-integration",
            "identity": {
                "principalId": "000000000000000000",
                "tenantId": "000000000000000",
                "type": "SystemAssigned"
            },
            "location": "westus",
            "name": "aks-integration",
            "properties": {
                "addonProfiles": {
                    "azurepolicy": {
                        "config": null,
                        "enabled": false
                    },
                    "httpApplicationRouting": {
                        "config": {
                            "HTTPApplicationRoutingZoneName": "a6ec8d.westus.aksapp.io"
                        },
                        "enabled": true,
                        "identity": {
                            "clientId": "0000000",
                            "objectId": "000000",
                            "resourceId": "/subscriptions/00000000/resourcegroups/MC_aks-integration_aks-integration_westus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/httpapplicationrouting-aks-integration"
                        }
                    },
                    "omsagent": {
                        "config": {
                            "logAnalyticsWorkspaceResourceID": "/subscriptions/00000000/resourceGroups/DefaultResourceGroup-WUS/providers/Microsoft.OperationalInsights/workspaces/tesrt"
                        },
                        "enabled": false
                    }
                },
                "agentPoolProfiles": [
                    {
                        "count": 1,
                        "currentOrchestratorVersion": "1.21.7",
                        "enableAutoScaling": true,
                        "enableFIPS": false,
                        "enableNodePublicIP": false,
                        "kubeletDiskType": "OS",
                        "maxCount": 5,
                        "maxPods": 110,
                        "minCount": 1,
                        "mode": "System",
                        "name": "agentpool",
                        "nodeImageVersion": "AKSUbuntu-1804gen2containerd-2021.12.07",
                        "orchestratorVersion": "1.21.7",
                        "osDiskSizeGB": 128,
                        "osDiskType": "Managed",
                        "osSKU": "Ubuntu",
                        "osType": "Linux",
                        "powerState": {
                            "code": "Running"
                        },
                        "provisioningState": "Succeeded",
                        "tags": {
                            "type": "aks-slb-managed-outbound-ip"
                        },
                        "type": "VirtualMachineScaleSets",
                        "vmSize": "Standard_DS2_v2"
                    }
                ],
                "azurePortalFQDN": "aks-integration-dns.portal.hcp.westus.azmk8s.io",
                "currentKubernetesVersion": "1.21.7",
                "dnsPrefix": "aks-integration-dns",
                "enableRBAC": true,
                "fqdn": "aks-integration-dns.hcp.westus.azmk8s.io",
                "identityProfile": {
                    "kubeletidentity": {
                        "clientId": "000000000000",
                        "objectId": "0000000000",
                        "resourceId": "/subscriptions/00000000/resourcegroups/MC_aks-integration_aks-integration_westus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-integration-agentpool"
                    }
                },
                "kubernetesVersion": "1.21.7",
                "maxAgentPools": 100,
                "networkProfile": {
                    "dnsServiceIP": "8.8.8.8",
                    "dockerBridgeCidr": "8.8.8.8/8",
                    "loadBalancerProfile": {
                        "effectiveOutboundIPs": [
                            {
                                "id": "/subscriptions/00000000/resourceGroups/MC_aks-integration_aks-integration_westus/providers/Microsoft.Network/publicIPAddresses/81661302-1ebc-450b-80a3-1e5d351ec2c0"
                            }
                        ],
                        "managedOutboundIPs": {
                            "count": 1
                        }
                    },
                    "loadBalancerSku": "Standard",
                    "networkPlugin": "kubenet",
                    "outboundType": "loadBalancer",
                    "podCidr": "8.8.8.8",
                    "serviceCidr": "8.8.8./8"
                },
                "nodeResourceGroup": "MC_aks-integration_aks-integration_westus",
                "oidcIssuerProfile": {
                    "enabled": false
                },
                "powerState": {
                    "code": "Running"
                },
                "provisioningState": "Succeeded",
                "securityProfile": {},
                "servicePrincipalProfile": {
                    "clientId": "msi"
                },
                "storageProfile": {
                    "diskCSIDriver": {
                        "enabled": true
                    },
                    "fileCSIDriver": {
                        "enabled": true
                    },
                    "snapshotController": {
                        "enabled": true
                    }
                },
                "workloadAutoScalerProfile": {}
            },
            "sku": {
                "name": "Base",
                "tier": "Free"
            },
            "tags": {
                "type": "aks-slb-managed-outbound-ip"
            },
            "type": "Microsoft.ContainerService/ManagedClusters"
        }
    }
}
```

#### Human Readable Output

>### AKS Clusters List
>|Name|Status|Location|Tags|Kubernetes version|API server address|Network type (plugin)|
>|---|---|---|---|---|---|---|
>| aks-integration | Succeeded | westus | type: aks-slb-managed-outbound-ip | 1.21.7 | aks-integration-dns.hcp.westus.azmk8s.io | kubenet |


### azure-ks-cluster-addon-update

***
Updates a managed cluster with the specified configuration.

#### Base Command

`azure-ks-cluster-addon-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Subscription ID'. | Optional | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Resource Group Name'. | Optional | 
| resource_name | The name of the managed cluster resource. Can be retrieved using the azure-ks-clusters-list command. | Required | 
| location | Resource location, Can be retrieved using the azure-ks-clusters-list command. Possible values are: australiacentral, australiacentral2, australiaeast, australiasoutheast, brazilse, brazilsouth, canadacentral, canadaeast, centralfrance, centralindia, centralus, centraluseuap, eastasia, eastus, eastus2, eastus2euap, germanyn, germanywc, japaneast, japanwest, koreacentral, koreasouth, northcentralus, northeurope, norwaye, norwayw, southafricanorth, southafricawest, southcentralus, southeastasia, southfrance, southindia, switzerlandn, switzerlandw, uaecentral, uaenorth, uknorth, uksouth, uksouth2, ukwest, westcentralus, westeurope, westindia, westus, westus2. | Required | 
| http_application_routing_enabled | Whether to configure ingress with automatic public DNS name creation. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| monitoring_agent_enabled | Whether to turn on Log Analytics monitoring. If enabled and monitoring_resource_id is not specified, will use the current configured workspace resource ID. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| monitoring_resource_name | The name of an existing Log Analytics workspace to use for storing monitoring data. Can be retrieved in the Log Analytics workspace from the Azure portal. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-ks-cluster-addon-update resource_name=aks-integration location=westus http_application_routing_enabled=true```
#### Human Readable Output

>The request to update the managed cluster was sent successfully.

### azure-ks-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-ks-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### azure-ks-subscriptions-list

***
Gets all subscriptions for a tenant.

#### Base Command

`azure-ks-subscriptions-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKS.Subscription.id | String | The unique identifier of the Azure Kubernetes subscription. | 
| AzureKS.Subscription.authorizationSource | String | The source of authorization for the Azure Kubernetes subscription. | 
| AzureKS.Subscription.managedByTenants | Unknown | The tenants that have access to manage the Azure Kubernetes subscription. | 
| AzureKS.Subscription.subscriptionId | String | The ID of the Azure Kubernetes subscription. | 
| AzureKS.Subscription.tenantId | String | The ID of the tenant associated with the Azure Kubernetes subscription. | 
| AzureKS.Subscription.displayName | String | The display name of the Azure Kubernetes subscription. | 
| AzureKS.Subscription.state | String | The current state of the Azure Kubernetes subscription. | 
| AzureKS.Subscription.subscriptionPolicies.locationPlacementId | String | The ID of the location placement policy for the Azure Kubernetes subscription. | 
| AzureKS.Subscription.subscriptionPolicies.quotaId | String | The ID of the quota policy for the Azure Kubernetes subscription. | 
| AzureKS.Subscription.subscriptionPolicies.spendingLimit | String | The spending limit policy for the Azure Kubernetes subscription. | 
| AzureKS.Subscription.count.type | String | The type of the Azure Kubernetes subscription count. | 
| AzureKS.Subscription.count.value | Number | The value of the Azure Kubernetes subscription count. | 

#### Command example
```!azure-ks-subscriptions-list```
#### Context Example
```json
{
    "AzureKS": {
        "Subscription": [
            {
                "authorizationSource": "RoleBased",
                "displayName": "Access to Azure Active Directory",
                "id": "/subscriptions/000000000000000",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "000000000000000",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "AAD_2015-09-01",
                    "spendingLimit": "On"
                },
                "tenantId": "000000000000000"
            },
            {
                "authorizationSource": "RoleBased",
                "displayName": "Pay-As-You-Go",
                "id": "/subscriptions/00000000",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "00000000",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "PayAsYouGo_2014-09-01",
                    "spendingLimit": "Off"
                },
                "tenantId": "000000000000000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Azure Kubernetes Subscriptions list
>|subscriptionId|tenantId|displayName|state|
>|---|---|---|---|
>| 000000000000000 | 000000000000000 | Access to Azure Active Directory | Enabled |
>| 00000000 | 000000000000000 | Pay-As-You-Go | Enabled |


### azure-ks-resource-group-list

***
Gets all resource groups for a subscription.

#### Base Command

`azure-ks-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID, optional. Note: This argument will override the instance parameter ‘Subscription ID'. | Optional | 
| limit | Limit on the number of resource groups to return. Default value is 50. Default is 50. | Optional | 
| tag | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKS.ResourceGroup.id | String | The unique identifier of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.name | String | The name of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.type | String | The type of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.location | String | The location of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.properties.provisioningState | String | The provisioning state of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags.Owner | String | The owner tag of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags | Unknown | The tags associated with the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags.Name | String | The name tag of the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.managedBy | String | The entity that manages the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags.aks-managed-cluster-name | String | The AKS managed cluster name tag associated with the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags.aks-managed-cluster-rg | String | The AKS managed cluster resource group tag associated with the Azure Kubernetes resource group. | 
| AzureKS.ResourceGroup.tags.type | String | The type tag associated with the Azure Kubernetes resource group. | 

#### Command example
```!azure-ks-resource-group-list```
#### Context Example
```json
{
    "AzureKS": {
        "ResourceGroup": [
            {
                "id": "/subscriptions/00000000/resourceGroups/cloud-shell-storage-eastus",
                "location": "eastus",
                "name": "cloud-shell-storage-eastus",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/demisto",
                "location": "centralus",
                "name": "demisto",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Owner": "Demisto"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/compute-integration",
                "location": "eastus",
                "name": "compute-integration",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/NetworkWatcherRG",
                "location": "westeurope",
                "name": "NetworkWatcherRG",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/echoteamsbot",
                "location": "centralus",
                "name": "echoteamsbot",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/testingteamsbot",
                "location": "centralus",
                "name": "testingteamsbot",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/socbot",
                "location": "eastasia",
                "name": "socbot",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/us-east-rg-backups",
                "location": "westus",
                "name": "us-east-rg-backups",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/us-east-rg",
                "location": "eastus",
                "name": "us-east-rg",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/xcloud",
                "location": "westeurope",
                "name": "xcloud",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/MSDE",
                "location": "westeurope",
                "name": "MSDE",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/DefaultResourceGroup-WEU",
                "location": "westeurope",
                "name": "DefaultResourceGroup-WEU",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {},
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/aks-integration-test_group",
                "location": "centralus",
                "name": "aks-integration-test_group",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/aks-integration-tes_group",
                "location": "centralus",
                "name": "aks-integration-tes_group",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/XDR_Event_",
                "location": "centralus",
                "name": "XDR_Event_Hub_API_Automation",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/DefaultResourceGroup-CUS",
                "location": "centralus",
                "name": "DefaultResourceGroup-CUS",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/sql-integration",
                "location": "eastus",
                "name": "sql-integration",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/ferrum-collector",
                "location": "eastus",
                "name": "ferrum-collector",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Name": "ferrum collector"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/DefaultResourceGroup-EUS",
                "location": "eastus",
                "name": "DefaultResourceGroup-EUS",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {},
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/intune-xdr-eventhub",
                "location": "eastus",
                "name": "intune-xdr-eventhub",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Name": "intune-xdr-eventhub"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/DefaultResourceGroup-WUS",
                "location": "westus",
                "name": "DefaultResourceGroup-WUS",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/aks-integration",
                "location": "westus",
                "name": "aks-integration",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/LogAnalyticsDefaultResources",
                "location": "westus",
                "name": "LogAnalyticsDefaultResources",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/MC_aks-integration_aks-integration_westus",
                "location": "westus",
                "managedBy": "/subscriptions/00000000/resourcegroups/aks-integration/providers/Microsoft.ContainerService/managedClusters/aks-integration",
                "name": "MC_aks-integration_aks-integration_westus",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "aks-managed-cluster-name": "aks-integration",
                    "aks-managed-cluster-rg": "aks-integration",
                    "type": "aks-slb-managed-outbound-ip"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/Elastic_Search",
                "location": "westus2",
                "name": "Elastic_Search",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/Purview-RG",
                "location": "westus2",
                "name": "Purview-RG",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/managed-rg-demistodevpurview",
                "location": "westus2",
                "managedBy": "/subscriptions/00000000/resourceGroups/Purview-RG/providers/Microsoft.Purview/accounts/demistodevpurview",
                "name": "managed-rg-demistodevpurview",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Name": "demistodevpurview"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/demisto-es",
                "location": "germanywestcentral",
                "name": "demisto-es",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {},
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/Azure_Firewall",
                "location": "eastus",
                "name": "Azure_Firewall",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {},
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/SecAndCompRG",
                "location": "eastus",
                "name": "SecAndCompRG",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/00000000/resourceGroups/demisto-sentinel2",
                "location": "centralus",
                "name": "demisto-sentinel2",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            }
        ]
    }
}
```

#### Human Readable Output

>### Resource Groups List
>|Name|Location|Tags|
>|---|---|---|
>| cloud-shell-storage-eastus | eastus |  |
>| demisto | centralus | Owner: Demisto |
>| compute-integration | eastus |  |
>| NetworkWatcherRG | westeurope |  |
>| echoteamsbot | centralus |  |
>| testingteamsbot | centralus |  |
>| socbot | eastasia |  |
>| us-east-rg-backups | westus |  |
>| us-east-rg | eastus |  |
>| xcloud | westeurope |  |
>| MSDE | westeurope |  |
>| DefaultResourceGroup-WEU | westeurope |  |
>| aks-integration-test_group | centralus |  |
>| aks-integration-tes_group | centralus |  |
>| XDR_Event_Hub_API_Automation | centralus |  |
>| DefaultResourceGroup-CUS | centralus |  |
>| sql-integration | eastus |  |
>| ferrum-collector | eastus | Name: ferrum collector |
>| DefaultResourceGroup-EUS | eastus |  |
>| intune-xdr-eventhub | eastus | Name: intune-xdr-eventhub |
>| DefaultResourceGroup-WUS | westus |  |
>| aks-integration | westus |  |
>| LogAnalyticsDefaultResources | westus |  |
>| MC_aks-integration_aks-integration_westus | westus | aks-managed-cluster-name: aks-integration<br/>aks-managed-cluster-rg: aks-integration<br/>type: aks-slb-managed-outbound-ip |
>| Elastic_Search | westus2 |  |
>| Purview-RG | westus2 |  |
>| managed-rg-demistodevpurview | westus2 | Name: demistodevpurview |
>| demisto-es | germanywestcentral |  |
>| Azure_Firewall | eastus |  |
>| SecAndCompRG | eastus |  |
>| demisto-sentinel2 | centralus |  |

