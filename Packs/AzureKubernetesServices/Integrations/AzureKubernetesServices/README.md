Deploy and manage containerized applications with a fully managed Kubernetes service.
This integration was integrated and tested with API version 2021-09-01 of AKS.

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
7. Enter your Authorization code in the ***Authorization code*** parameter.
7. Save the instance.
8. Run the ***!azure-ks-auth-test*** command - a 'Success' message should be printed to the War Room.

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
    | app_id | Application ID | True |
    | subscription_id | Subscription ID | True |
    | resource_group_name | Resource Group Name | True |
    | azure_ad_endpoint | Azure AD endpoint associated with a national cloud | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | Tenant ID (for User Auth mode) | Tenant ID | False |
    | Client Secret (for User Auth mode) | Encryption key given by the admin | False |
    | Authentication Type | The request authentication type for the instance | False |
    | Authorization code | as received from the authorization step | False |
    | Application redirect URI | the redirect URI entered in the Azure portal | False |

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

There are no input arguments for this command.

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
| AzureKS.ManagedCluster.properties.agentPoolProfiles.orchestratorVersion | String | Version of orchestrator specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.linuxProfile.adminUsername | String | The name of the administrator account. | 
| AzureKS.ManagedCluster.properties.linuxProfile.ssh.publicKeys.keyData | String | Certificate public key used to authenticate with VMs through SSH. | 
| AzureKS.ManagedCluster.properties.servicePrincipalProfile.clientId | String | The ID for the service principal. | 
| AzureKS.ManagedCluster.properties.nodeResourceGroup | String | Name of the resource group containing agent pool nodes. | 
| AzureKS.ManagedCluster.properties.enableRBAC | Boolean | Whether to enable Kubernetes Role-Based Access Control. | 
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
```!azure-ks-clusters-list```

#### Context Example
```json
{
    "AzureKS": {
        "ManagedCluster": {
          "id": "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters",
          "location": "location1",
          "name": "clustername1",
          "tags": {
            "archv2": "",
            "tier": "production"
          },
          "type": "Microsoft.ContainerService/ManagedClusters",
          "properties": {
            "provisioningState": "Succeeded",
            "kubernetesVersion": "1.9.6",
            "maxAgentPools": 1,
            "dnsPrefix": "dnsprefix1",
            "fqdn": "dnsprefix1-abcd1234.hcp.eastus.azmk8s.io",
            "agentPoolProfiles": [
              {
                "name": "nodepool1",
                "count": 3,
                "vmSize": "Standard_DS1_v2",
                "maxPods": 110,
                "osType": "Linux",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.9.6"
              }
            ],
            "linuxProfile": {
              "adminUsername": "azureuser",
              "ssh": {
                "publicKeys": [
                  {
                    "keyData": "keydata"
                  }
                ]
              }
            },
            "servicePrincipalProfile": {
              "clientId": "clientid"
            },
            "nodeResourceGroup": "MC_rg1_clustername1_location1",
            "enableRBAC": false,
            "diskEncryptionSetID": "/subscriptions/subid1/resourceGroups/rg1/providers/Microsoft.Compute/diskEncryptionSets/des",
            "networkProfile": {
              "networkPlugin": "kubenet",
              "podCidr": "10.244.0.0/16",
              "serviceCidr": "10.0.0.0/16",
              "dnsServiceIP": "10.0.0.10",
              "dockerBridgeCidr": "172.17.0.1/16"
            },
            "addonProfiles": {
              "omsagent": {
                "enabled": false,
                "config": {
                  "logAnalyticsWorkspaceResourceID": "workspace"
                }
              },
              "httpApplicationRouting": {
                "enabled": true,
                "config": {
                  "HTTPApplicationRoutingZoneName": "zone"
                }
              }
            }
          }
        }
    }
}
```

#### Human Readable Output

>### AKS Clusters List
>|Name|Status|Location|Tags|Kubernetes version|API server address|Network type (plugin)|
>|---|---|---|---|---|---|---|
>| clustername1 | Succeeded | location1 | tier: production | 1.9.6 | dnsprefix1-abcd1234.hcp.eastus.azmk8s.io | kubenet |


### azure-ks-cluster-addon-update
***
Updates a managed cluster with the specified configuration.


#### Base Command

`azure-ks-cluster-addon-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The name of the managed cluster resource. Can be retrieved using the ***azure-ks-clusters-list*** command. | Required | 
| location | Resource location. Possible values are: australiacentral, australiacentral2, australiaeast, australiasoutheast, brazilse, brazilsouth, canadacentral, canadaeast, centralfrance, centralindia, centralus, centraluseuap, eastasia, eastus, eastus2, eastus2euap, germanyn, germanywc, japaneast, japanwest, koreacentral, koreasouth, northcentralus, northeurope, norwaye, norwayw, southafricanorth, southafricawest, southcentralus, southeastasia, southfrance, southindia, switzerlandn, switzerlandw, uaecentral, uaenorth, uknorth, uksouth, uksouth2, ukwest, westcentralus, westeurope, westindia, westus, westus2. | Required | 
| http_application_routing_enabled | Whether to configure ingress with automatic public DNS name creation. Possible values are: true, false. | Optional | 
| monitoring_agent_enabled | Whether to turn on Log Analytics monitoring. If enabled and *monitoring_resource_id* is not specified, will use the current configured workspace resource ID. Possible values are: true, false. | Optional | 
| monitoring_resource_name | The name of an existing Log Analytics Workspace to use for storing monitoring data. Can be retrieved in the Log Analytics workspace from the Azure portal. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ks-cluster-addon-update resource_name=aks-integration location=westus http_application_routing_enabled=true```

#### Human Readable Output

>The request to update the managed cluster was sent successfully.
