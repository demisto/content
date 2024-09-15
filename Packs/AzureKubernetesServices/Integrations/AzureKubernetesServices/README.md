Deploy and manage containerized applications with a fully managed Kubernetes service.
This integration was integrated and tested with API version 2023-02-01 of AKS.

In order to connect to the AzureKubernetesServices using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

- *Authorization Code Flow* (Recommended).
- *Device Code Flow*.
- *Azure Managed Identities*
- *Client Credentials Flow*.

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

### Authentication Using the Device Code Flow

Follow these steps for a self-deployed configuration:

1. Fill in the required parameters.
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
3. Run the ***!azure-ks-auth-start*** command. 
4. Follow the instructions that appear.
5. Run the ***!azure-ks-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (ab217a43-e09b-4f80-ae93-482fc7a3d1a3).

## Client Credentials Flow Authentication

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)
*Note:* In the *Select members* section, assign the application you created earlier.
To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   1. In the **Authentication Type** field, select the **Client Credentials** option.
   2. In the **Application ID** field, enter your Client/Application ID.
   3. In the **Tenant ID** field, enter your Tenant ID .
   4. In the **Client Secret** field, enter your Client Secret.
   5. Click **Test** to validate the URLs, token, and connection
   6. Save the instance.

### Testing authentication and connectivity
If you are using Device Code Flow or Authorization Code Flow, for testing your authentication and connectivity to the Azure Kubernetes Services service run the ***!azure-ks-auth-test*** command. 
If you are using Client Credentials Flow, click **Test** when you are configuring the instance.

## Configure Azure Kubernetes Services on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Kubernetes Services.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                      | **Description**                                                                                                | **Required** |
    |------------------------------------|----------------------------------------------------------------------------------------------------------------|--------------|
    | Azure Cloud                        | Azure Cloud the K8S cluster resides in. See table below.                                                       | False        |
    | app_id                             | Application ID                                                                                                 | False        |
    | Default subscription_id                    | Subscription ID. There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value.                                                                                               | True         |
    | Default resource_group_name                | Resource Group Name. There are two options to insert the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value.                                                                                  | True         |
    | azure_ad_endpoint                  | Azure AD endpoint associated with a national cloud. See note below.                                     | False        |
    | insecure                           | Trust any certificate \(not secure\)                                                                           | False        |
    | proxy                              | Use system proxy settings                                                                                      | False        |
    | Tenant ID                          | Tenant ID                                                                                                      | False        |
    | Client Secret                      | Encryption key given by the admin                                                                              | False        |
    | Authentication Type                | The request authentication type for the instance                                                               | False        |
    | Authorization code                 | Received from the authorization step                                                                           | False        |
    | Application redirect URI           | The redirect URI entered in the Azure portal                                                                   | False        |
    | Azure Managed Identities Client ID | The managed identities client ID for authentication. Relevant only if the integration is running on Azure VM.  | False        |

4. Azure cloud options

    | Azure Cloud | Description                                                              |
    |-------------|--------------------------------------------------------------------------|
    | Worldwide   | The publicly accessible Azure Cloud                                      |
    | US GCC      | Azure cloud for the USA Government Cloud Community (GCC)                 |
    | US GCC-High | Azure cloud for the USA Government Cloud Community High (GCC-High)       |
    | DoD         | Azure cloud for the USA Department of Defense (DoD)                      |
    | Germany     | Azure cloud for the German Government                                    |
    | China       | Azure cloud for the Chinese Government                                   |
    | Custom      | Custom endpoint configuration to the Azure cloud. See note below. |

   * Note: In most cases, setting Azure cloud is preferred to setting Azure AD endpoint. Only use it in cases where a custom proxy URL is required for accessing a national cloud.

5. Click **Test** to validate the URLs, token, and connection.

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
>
>✅ Success!


### azure-ks-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`azure-ks-auth-start`

#### Input

There are no input arguments for this command.

#### Human Readable Output
>
>### Authorization instructions
>
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
>
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
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 

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


#### Command Example

`!azure-ks-clusters-list`

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
                                "id": "/subscriptions/00000000/resourceGroups/MC_aks-integration_aks-integration_westus/providers/Microsoft.Network/publicIPAddresses/81661302-1ebc-450b"
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
>
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
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| resource_name | The name of the managed cluster resource. Can be retrieved using the azure-ks-clusters-list command. | Required | 
| location | Resource location. Can be retrieved using the azure-ks-clusters-list command. Possible values are: australiacentral, australiacentral2, australiaeast, australiasoutheast, brazilse, brazilsouth, canadacentral, canadaeast, centralfrance, centralindia, centralus, centraluseuap, eastasia, eastus, eastus2, eastus2euap, germanyn, germanywc, japaneast, japanwest, koreacentral, koreasouth, northcentralus, northeurope, norwaye, norwayw, southafricanorth, southafricawest, southcentralus, southeastasia, southfrance, southindia, switzerlandn, switzerlandw, uaecentral, uaenorth, uknorth, uksouth, uksouth2, ukwest, westcentralus, westeurope, westindia, westus, westus2. | Required | 
| http_application_routing_enabled | Whether to configure ingress with automatic public DNS name creation.  Possible values are: true, false. | Optional | 
| monitoring_agent_enabled | Whether to turn on Log Analytics monitoring. If enabled and monitoring_resource_id is not specified, will use the current configured workspace resource ID. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| monitoring_resource_name | The name of an existing Log Analytics workspace to use for storing monitoring data. Can be retrieved in the Log Analytics workspace from the Azure portal. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

`!azure-ks-cluster-addon-update resource_name=aks-integration location=westus http_application_routing_enabled=true`

#### Human Readable Output

>The request to update the managed cluster was sent successfully.

### azure-ks-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-ks-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

`azure-ks-generate-login-url`

#### Human Readable Output

>### Authorization instructions
>
>1. Click the [login URL](https://login.microsoftonline.com) to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
`REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE`
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.


### azure-ks-resource-group-list

***
Gets all resource groups for a subscription.

#### Base Command

`azure-ks-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID, optional. Note: This argument will override the instance parameter ‘Defalut Subscription ID'. | Optional | 
| limit | Limit on the number of resource groups to return. Default is 50. Default is 50. | Optional | 
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
                "id": "/subscriptions/00000000/resourceGroups/demi",
                "location": "centralus",
                "name": "demi",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Owner": "Demi"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
        ]
    }
}
```

#### Human Readable Output

>### Resource Groups List
>|Name|Location|Tags|
>|---|---|---|
>| cloud-shell-storage-eastus | eastus |  |
>| demi | centralus | Owner: Demi |
>| compute-integration | eastus |  |
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
                "id": "/subscriptions/057b1785-fd7",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "057b1785-fd7",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "AAD_2015-09-01",
                    "spendingLimit": "On"
                },
                "tenantId": "ebac1a16-81bf"
            },
            {
                "authorizationSource": "RoleBased",
                "displayName": "Pay-As-You-Go",
                "id": "/subscriptions/0f907ea4-",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "0f907ea4-",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "PayAsYouGo_2014-09-01",
                    "spendingLimit": "Off"
                },
                "tenantId": "ebac1a16"
            }
        ]
    }
}
```

#### Human Readable Output

>### Azure Kubernetes Subscriptions list
>|subscriptionId|tenantId|displayName|state|
>|---|---|---|---|
>| 057b1785-fd7b-4ca3- | ebac1a16-81bf-449b- | Access to Azure Active Directory | Enabled |
>| 0f907ea4-bc8b-4c11- | ebac1a16-81bf-449b- | Pay-As-You-Go | Enabled |

