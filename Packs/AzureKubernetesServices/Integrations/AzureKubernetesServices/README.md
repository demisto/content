Deploy and manage containerized applications with a fully managed Kubernetes service.

## Configure Azure Kubernetes Services on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Kubernetes Services.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | app_id | Application ID | True |
    | subscription_id | Subscription ID | True |
    | resource_group_name | Resource Group Name | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-ks-auth-test
***
Tests the connectivity to the Azure.


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
>        2. Run the **!azure-ks-auth-complete** command in the War Room.



### azure-ks-auth-complete
***
Run this command to complete the authorization process. Should be used after running the azure-ks-auth-start command.


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

>Authorization was reset successfully. You can now run **!azure-ks-auth-start** and **!azure-ks-auth-complete**.

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
| AzureKS.ManagedCluster.properties.maxAgentPools | Number | The max number of agent pools for the managed cluster. | 
| AzureKS.ManagedCluster.properties.dnsPrefix | String | DNS prefix specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.fqdn | String | FQDN for the master pool. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.name | String | Unique name of the agent pool profile in the context of the subscription and resource group. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.count | Number | Number of agents \(VMs\) to host docker containers. Allowed values must be in the range of 0 to 100 \(inclusive\) for user pools and in the range of 1 to 100 \(inclusive\) for system pools. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.vmSize | String | Size of agent VMs. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.maxPods | Number | Maximum number of pods that can run on a node. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.osType | String | OsType to be used to specify os type. Choose from Linux and Windows. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.provisioningState | String | The current deployment or provisioning state. | 
| AzureKS.ManagedCluster.properties.agentPoolProfiles.orchestratorVersion | String | Version of orchestrator specified when creating the managed cluster. | 
| AzureKS.ManagedCluster.properties.linuxProfile.adminUsername | String | Specifies the name of the administrator account. | 
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
| AzureKS.ManagedCluster.properties.addonProfiles.httpApplicationRouting.enabled | Boolean | Whether the ingress is configuredd with automatic public DNS name creation. | 
| AzureKS.ManagedCluster.properties.addonProfiles.httpApplicationRouting.config.HTTPApplicationRoutingZoneName | String | The suscription DNS zone name. | 


#### Command Example
```!azure-ks-clusters-list```

#### Context Example
```json
{
    "AzureKS": {
        "ManagedCluster": {
            "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourcegroups/aks-integration/providers/Microsoft.ContainerService/managedClusters/aks-integration",
            "location": "westus",
            "name": "aks-integration",
            "properties": {
                "addonProfiles": {
                    "KubeDashboard": {
                        "config": null,
                        "enabled": false
                    },
                    "azurePolicy": {
                        "config": null,
                        "enabled": false
                    },
                    "httpApplicationRouting": {
                        "config": {
                            "HTTPApplicationRoutingZoneName": "7c66ea1d4aef4799a2ae.westus.aksapp.io"
                        },
                        "enabled": true
                    },
                    "omsagent": {
                        "config": {
                            "logAnalyticsWorkspaceResourceID": "/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/DefaultResourceGroup-WUS/providers/Microsoft.OperationalInsights/workspaces/aks-integration-ws"
                        },
                        "enabled": true
                    }
                },
                "agentPoolProfiles": [
                    {
                        "count": 3,
                        "maxPods": 110,
                        "mode": "System",
                        "name": "agentpool",
                        "nodeImageVersion": "AKSUbuntu-1804-2020.12.01",
                        "nodeLabels": {},
                        "orchestratorVersion": "1.18.10",
                        "osDiskSizeGB": 128,
                        "osDiskType": "Managed",
                        "osType": "Linux",
                        "powerState": {
                            "code": "Running"
                        },
                        "provisioningState": "Succeeded",
                        "type": "VirtualMachineScaleSets",
                        "vmSize": "Standard_DS2_v2"
                    }
                ],
                "apiServerAccessProfile": {
                    "enablePrivateCluster": false
                },
                "dnsPrefix": "aks-integration-dns",
                "enableRBAC": true,
                "fqdn": "aks-integration-dns-883ed03b.hcp.westus.azmk8s.io",
                "kubernetesVersion": "1.18.10",
                "maxAgentPools": 10,
                "networkProfile": {
                    "dnsServiceIP": "10.0.0.10",
                    "dockerBridgeCidr": "172.17.0.1/16",
                    "loadBalancerProfile": {
                        "effectiveOutboundIPs": [
                            {
                                "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/MC_aks-integration_aks-integration_westus/providers/Microsoft.Network/publicIPAddresses/2dfa70a1-ae82-4f8e-a0b5-edd08b5392a4"
                            }
                        ],
                        "managedOutboundIPs": {
                            "count": 1
                        }
                    },
                    "loadBalancerSku": "Standard",
                    "networkPlugin": "kubenet",
                    "outboundType": "loadBalancer",
                    "podCidr": "10.244.0.0/16",
                    "serviceCidr": "10.0.0.0/16"
                },
                "nodeResourceGroup": "MC_aks-integration_aks-integration_westus",
                "powerState": {
                    "code": "Running"
                },
                "provisioningState": "Succeeded",
                "servicePrincipalProfile": {
                    "clientId": "af94cdad-b871-4d4f-98e3-8c2e99713433"
                }
            },
            "sku": {
                "name": "Basic",
                "tier": "Free"
            },
            "tags": {
                "orchestrator": "Kubernetes:1.18.10",
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
>| aks-integration | Succeeded | westus | orchestrator: Kubernetes:1.18.10<br/>type: aks-slb-managed-outbound-ip | 1.18.10 | aks-integration-dns-883ed03b.hcp.westus.azmk8s.io | kubenet |


### azure-ks-cluster-addon-update
***
Updates a managed cluster with the specified configuration.


#### Base Command

`azure-ks-cluster-addon-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The name of the managed cluster resource. Can be retrieved using the azure-ks-clusters-list command. | Required | 
| location | Resource location. Possible values are: australiacentral, australiacentral2, australiaeast, australiasoutheast, brazilse, brazilsouth, canadacentral, canadaeast, centralfrance, centralindia, centralus, centraluseuap, eastasia, eastus, eastus2, eastus2euap, germanyn, germanywc, japaneast, japanwest, koreacentral, koreasouth, northcentralus, northeurope, norwaye, norwayw, southafricanorth, southafricawest, southcentralus, southeastasia, southfrance, southindia, switzerlandn, switzerlandw, uaecentral, uaenorth, uknorth, uksouth, uksouth2, ukwest, westcentralus, westeurope, westindia, westus, westus2. | Required | 
| http_application_routing_enabled | Whether to configure ingress with automatic public DNS name creation. Possible values are: true, false. | Optional | 
| monitoring_agent_enabled | Whether to turn on Log Analytics monitoring. If enabled and monitoring_resource_id is not specified, will use the current configured workspace resource ID. Possible values are: true, false. | Optional | 
| monitoring_resource_name | The name of an existing Log Analytics Workspace to use for storing monitoring data. Can be retrieved in the Log Analytics Workspace from Azure portal. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ks-cluster-addon-update resource_name=aks-integration location=westus http_application_routing_enabled=true```

#### Human Readable Output

>The request to update the managed cluster was sent successfully.
