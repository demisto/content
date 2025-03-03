This integration enables the management of Azure Services using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands.

To use this integration, configure an instance of this integration. This will associate a credential to be used to manage a Azure Subscription.

# Authorize Cortex XSOAR for Azure Cloud
To use this integration you must generate a Service Principal for your Azure subscription. Follow [Microsoft's guide](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal) on how to create a Azure AD application and associated service principal.

After stepping through the guide you will have:

* Your Client ID, which is found in the “client id” box in the “Configure” page of your application in the Azure portal
* Your Secret key, generated when you created the application. You cannot show the key after creation. If you lost the key, you must create a new one in the “Configure” page of your application.
* And finally, a tenant ID. It’s a UUID (e.g. ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL) pointing to the AD containing your application. You will find it in the URL from within the Azure portal, or in the “view endpoints” of any given URL.

## Configure Ansible Azure in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Subscription ID | Your Azure subscription Id. | True |
| Access Secret | Azure client secret | True |
| Client ID | Azure client ID | True |
| Tenant ID | Azure tenant ID | True |
| Azure Cloud Environment | For cloud environments other than the US public cloud, the environment name \(as defined by Azure Python SDK, eg, \`AzureChinaCloud\`, \`AzureUSGovernment\`\), or a metadata discovery endpoint URL \(required for Azure Stack\). | True |
| Certificate Validation Mode | Controls the certificate validation behavior for Azure endpoints. By default, all modules will validate the server certificate, but when an HTTPS proxy is in use, or against Azure Stack, it may be necessary to disable this behavior by passing \`ignore\`. | True |
| API Profile | Selects an API profile to use when communicating with Azure services. Default value of \`latest\` is appropriate for public clouds; future values will allow use with Azure Stack. | True |


# Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

# State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-rm-autoscale
***
Manage Azure autoscale setting
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_autoscale_module.html


#### Base Command

`azure-rm-autoscale`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The identifier of the resource to apply autoscale setting.<br/>It could be the resource id string.<br/>It also could be a dict contains the `name`, `subscription_id`, `namespace`, `types`, `resource_group` of the resource. | Optional | 
| resource_group | Resource group of the resource. | Required | 
| enabled | Specifies whether automatic scaling is enabled for the resource. Possible values are: Yes, No. Default is Yes. | Optional | 
| profiles | The collection of automatic scaling profiles that specify different scaling parameters for different time periods.<br/>A maximum of 20 profiles can be specified. | Optional | 
| notifications | The collection of notifications. | Optional | 
| state | Assert the state of the virtual network. Use `present` to create or update and `absent` to delete. Possible values are: present, absent. Default is present. | Optional | 
| location | location of the resource. | Optional | 
| name | name of the resource. | Required | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAutoscale.state | unknown | Current state of the resource. | 


#### Command Example
```!azure-rm-autoscale target="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss" enabled="True" profiles="{{ [{\"count\": \"1\", \"recurrence_days\": [\"Monday\"], \"name\": \"Auto created scale condition\", \"recurrence_timezone\": \"China Standard Time\", \"recurrence_mins\": [\"0\"], \"min_count\": \"1\", \"max_count\": \"1\", \"recurrence_frequency\": \"Week\", \"recurrence_hours\": [\"18\"]}] }}" name="auto_scale_name" resource_group="myResourceGroup" location="australiasoutheast"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAutoscale": [
            {
                "changed": true,
                "enabled": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/microsoft.insights/autoscalesettings/auto_scale_name",
                "location": "australiasoutheast",
                "name": "auto_scale_name",
                "notifications": [],
                "profiles": [
                    {
                        "count": "1",
                        "max_count": "1",
                        "min_count": "1",
                        "name": "Auto created scale condition",
                        "recurrence_days": [
                            "Monday"
                        ],
                        "recurrence_frequency": "Week",
                        "recurrence_hours": [
                            "18"
                        ],
                        "recurrence_mins": [
                            "0"
                        ],
                        "recurrence_timezone": "China Standard Time"
                    }
                ],
                "status": "CHANGED",
                "tags": {},
                "target": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * enabled: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/microsoft.insights/autoscalesettings/auto_scale_name
>  * location: australiasoutheast
>  * name: auto_scale_name
>  * target: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss
>  * ## Notifications
>  * ## Profiles
>  * ## Auto Created Scale Condition
>    * count: 1
>    * max_count: 1
>    * min_count: 1
>    * name: Auto created scale condition
>    * recurrence_frequency: Week
>    * recurrence_timezone: China Standard Time
>    * ### Recurrence_Days
>      * 0: Monday
>    * ### Recurrence_Hours
>      * 0: 18
>    * ### Recurrence_Mins
>      * 0: 0
>  * ## Tags


### azure-rm-autoscale-info
***
Get Azure Auto Scale Setting facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_autoscale_info_module.html


#### Base Command

`azure-rm-autoscale-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | The name of the Auto Scale Setting. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAutoscaleInfo.autoscales | unknown | List of Azure Scale Settings dicts. | 


#### Command Example
```!azure-rm-autoscale-info resource_group="myResourceGroup" name="auto_scale_name" location="australiasoutheast"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAutoscaleInfo": [
            {
                "autoscales": [
                    {
                        "enabled": true,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/microsoft.insights/autoscalesettings/auto_scale_name",
                        "location": "australiasoutheast",
                        "name": "auto_scale_name",
                        "notifications": [],
                        "profiles": [
                            {
                                "count": "1",
                                "max_count": "1",
                                "min_count": "1",
                                "name": "Auto created scale condition",
                                "recurrence_days": [
                                    "Monday"
                                ],
                                "recurrence_frequency": "Week",
                                "recurrence_hours": [
                                    "18"
                                ],
                                "recurrence_mins": [
                                    "0"
                                ],
                                "recurrence_timezone": "China Standard Time"
                            }
                        ],
                        "tags": {},
                        "target": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss"
                    }
                ],
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Autoscales
>  * ## Auto_Scale_Name
>    * enabled: True
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/microsoft.insights/autoscalesettings/auto_scale_name
>    * location: australiasoutheast
>    * name: auto_scale_name
>    * target: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss
>    * ### Notifications
>    * ### Profiles
>    * ### Auto Created Scale Condition
>      * count: 1
>      * max_count: 1
>      * min_count: 1
>      * name: Auto created scale condition
>      * recurrence_frequency: Week
>      * recurrence_timezone: China Standard Time
>      * #### Recurrence_Days
>        * 0: Monday
>      * #### Recurrence_Hours
>        * 0: 18
>      * #### Recurrence_Mins
>        * 0: 0
>    * ### Tags


### azure-rm-availabilityset
***
Manage Azure Availability Set
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_availabilityset_module.html


#### Base Command

`azure-rm-availabilityset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the availability set exists or will be created. | Required | 
| name | Name of the availability set. | Required | 
| state | Assert the state of the availability set.<br/>Use `present` to create or update a availability set and `absent` to delete a availability set. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| platform_update_domain_count | Update domains indicate groups of virtual machines and underlying physical hardware that can be rebooted at the same time. Default is 5. | Optional | 
| platform_fault_domain_count | Fault domains define the group of virtual machines that share a common power source and network switch.<br/>Should be between `1` and `3`. Default is 3. | Optional | 
| sku | Define if the availability set supports managed disks. Possible values are: Classic, Aligned. Default is Classic. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAvailabilityset.state | unknown | Current state of the availability set. | 
| Azure.AzureRmAvailabilityset.changed | boolean | Whether or not the resource has changed | 


#### Command Example
```!azure-rm-availabilityset name="myAvailabilitySet" location="australiasoutheast" resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAvailabilityset": [
            {
                "changed": true,
                "state": {
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/availabilitySets/myAvailabilitySet",
                    "location": "australiasoutheast",
                    "name": "myAvailabilitySet",
                    "platform_fault_domain_count": 3,
                    "platform_update_domain_count": 5,
                    "sku": "Classic",
                    "tags": null
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/availabilitySets/myAvailabilitySet
>    * location: australiasoutheast
>    * name: myAvailabilitySet
>    * platform_fault_domain_count: 3
>    * platform_update_domain_count: 5
>    * sku: Classic
>    * tags: None


### azure-rm-availabilityset-info
***
Get Azure Availability Set facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_availabilityset_info_module.html


#### Base Command

`azure-rm-availabilityset-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific availability set. | Optional | 
| resource_group | The resource group to search for the desired availability set. | Optional | 
| tags | List of tags to be matched. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAvailabilitysetInfo.azure_availabilityset | unknown | List of availability sets dicts. | 


#### Command Example
```!azure-rm-availabilityset-info name="Testing" resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAvailabilitysetInfo": [
            {
                "changed": false,
                "info": {
                    "azure_availabilitysets": []
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Availabilitysets


### azure-rm-deployment
***
Create or destroy Azure Resource Manager template deployments
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_deployment_module.html


#### Base Command

`azure-rm-deployment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The resource group name to use or create to host the deployed template. | Required | 
| name | The name of the deployment to be tracked in the resource group deployment history.<br/>Re-using a deployment name will overwrite the previous value in the resource group's deployment history. Default is ansible-arm. | Optional | 
| location | The geo-locations in which the resource group will be located. Default is westus. | Optional | 
| deployment_mode | In incremental mode, resources are deployed without deleting existing resources that are not included in the template.<br/>In complete mode resources are deployed and existing resources in the resource group not included in the template are deleted. Possible values are: complete, incremental. Default is incremental. | Optional | 
| template | A hash containing the templates inline. This parameter is mutually exclusive with `template_link`.<br/>Either `template` or `template_link` is required if `state=present`. | Optional | 
| template_link | Uri of file containing the template body. This parameter is mutually exclusive with `template`.<br/>Either `template` or `template_link` is required if `state=present`. | Optional | 
| parameters | A hash of all the required template variables for the deployment template. This parameter is mutually exclusive with `parameters_link`.<br/>Either `parameters_link` or `parameters` is required if `state=present`. | Optional | 
| parameters_link | Uri of file containing the parameters body. This parameter is mutually exclusive with `parameters`.<br/>Either `parameters_link` or `parameters` is required if `state=present`. | Optional | 
| wait_for_deployment_completion | Whether or not to block until the deployment has completed. Default is yes. | Optional | 
| wait_for_deployment_polling_period | Time (in seconds) to wait between polls when waiting for deployment completion. Default is 10. | Optional | 
| state | If `state=present`, template will be created.<br/>If `state=present` and deployment exists, it will be updated.<br/>If `state=absent`, stack will be removed. Possible values are: present, absent. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDeployment.deployment | unknown | Deployment details. | 


#### Command Example
```!azure-rm-deployment resource_group="myResourceGroup" name="myDeployment" location="australiasoutheast" template_link="https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-vm-simple-linux/azuredeploy.json" parameters="{\"vmName\":{\"value\":\"simpleLinuxVM\"},\"adminUsername\":{\"value\":\"exampleadmin\"},\"authenticationType\":{\"value\":\"password\"},\"adminPasswordOrKey\":{\"value\":\"CHANGEME\"},\"dnsLabelPrefix\":{\"value\":\"xsoarexample\"},\"ubuntuOSVersion\":{\"value\":\"18.04-LTS\"},\"VmSize\":{\"value\":\"Standard_B2s\"},\"virtualNetworkName\":{\"value\":\"vNet\"},\"subnetName\":{\"value\":\"Subnet\"},\"networkSecurityGroupName\":{\"value\":\"SecGroupNet\"}}"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDeployment": [
            {
                "changed": true,
                "deployment": {
                    "group_name": "myResourceGroup",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Resources/deployments/myDeployment",
                    "instances": [
                        {
                            "ips": [
                                {
                                    "dns_settings": {
                                        "domain_name_label": "xsoarexample",
                                        "fqdn": "xsoarexample.australiasoutheast.cloudapp.azure.com"
                                    },
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/simpleLinuxVMPublicIP",
                                    "name": "simpleLinuxVMPublicIP",
                                    "public_ip": "1.1.1.1",
                                    "public_ip_allocation_method": "Dynamic"
                                }
                            ],
                            "vm_name": "simpleLinuxVM"
                        }
                    ],
                    "name": "myDeployment",
                    "outputs": {
                        "adminUsername": {
                            "type": "String",
                            "value": "exampleadmin"
                        },
                        "hostname": {
                            "type": "String",
                            "value": "xsoarexample.australiasoutheast.cloudapp.azure.com"
                        },
                        "sshCommand": {
                            "type": "String",
                            "value": "ssh exampleadmin@xsoarexample.australiasoutheast.cloudapp.azure.com"
                        }
                    }
                },
                "msg": "deployment succeeded",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * msg: deployment succeeded
>  * ## Deployment
>    * group_name: myResourceGroup
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Resources/deployments/myDeployment
>    * name: myDeployment
>    * ### Instances
>    * ### Simplelinuxvm
>      * vm_name: simpleLinuxVM
>      * #### Ips
>      * #### Simplelinuxvmpublicip
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/simpleLinuxVMPublicIP
>        * name: simpleLinuxVMPublicIP
>        * public_ip: 1.1.1.1
>        * public_ip_allocation_method: Dynamic
>        * ##### Dns_Settings
>          * domain_name_label: xsoarexample
>          * fqdn: xsoarexample.australiasoutheast.cloudapp.azure.com
>    * ### Outputs
>      * #### Adminusername
>        * type: String
>        * value: exampleadmin
>      * #### Hostname
>        * type: String
>        * value: xsoarexample.australiasoutheast.cloudapp.azure.com
>      * #### Sshcommand
>        * type: String
>        * value: ssh exampleadmin@xsoarexample.australiasoutheast.cloudapp.azure.com


### azure-rm-deployment-info
***
Get Azure Deployment facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_deployment_info_module.html


#### Base Command

`azure-rm-deployment-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | The name of the deployment. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDeploymentInfo.deployments | unknown | A list of dictionaries containing facts for deployments. | 


#### Command Example
```!azure-rm-deployment-info resource_group="myResourceGroup" name="myDeployment" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDeploymentInfo": [
            {
                "changed": false,
                "deployments": [
                    {
                        "correlation_id": "07a08b8c-9c48-45fe-9f67-53c7eea232b6",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Resources/deployments/myDeployment",
                        "name": "myDeployment",
                        "output_resources": [
                            {
                                "depends_on": [],
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/SecGroupNet",
                                "name": "SecGroupNet",
                                "type": "Microsoft.Network/networkSecurityGroups"
                            },
                            {
                                "depends_on": [],
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/vNet",
                                "name": "vNet",
                                "type": "Microsoft.Network/virtualNetworks"
                            },
                            {
                                "depends_on": [],
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIpAddresses/simpleLinuxVMPublicIP",
                                "name": "simpleLinuxVMPublicIP",
                                "type": "Microsoft.Network/publicIpAddresses"
                            },
                            {
                                "depends_on": [
                                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/SecGroupNet",
                                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/vNet",
                                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIpAddresses/simpleLinuxVMPublicIP"
                                ],
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/simpleLinuxVMNetInt",
                                "name": "simpleLinuxVMNetInt",
                                "type": "Microsoft.Network/networkInterfaces"
                            },
                            {
                                "depends_on": [
                                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/simpleLinuxVMNetInt"
                                ],
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/simpleLinuxVM",
                                "name": "simpleLinuxVM",
                                "type": "Microsoft.Compute/virtualMachines"
                            }
                        ],
                        "outputs": {
                            "adminUsername": {
                                "type": "String",
                                "value": "exampleadmin"
                            },
                            "hostname": {
                                "type": "String",
                                "value": "xsoarexample.australiasoutheast.cloudapp.azure.com"
                            },
                            "sshCommand": {
                                "type": "String",
                                "value": "ssh exampleadmin@xsoarexample.australiasoutheast.cloudapp.azure.com"
                            }
                        },
                        "parameters": {
                            "adminPasswordOrKey": {
                                "type": "SecureString"
                            },
                            "adminUsername": {
                                "type": "String",
                                "value": "exampleadmin"
                            },
                            "authenticationType": {
                                "type": "String",
                                "value": "password"
                            },
                            "dnsLabelPrefix": {
                                "type": "String",
                                "value": "xsoarexample"
                            },
                            "location": {
                                "type": "String",
                                "value": "australiasoutheast"
                            },
                            "networkSecurityGroupName": {
                                "type": "String",
                                "value": "SecGroupNet"
                            },
                            "subnetName": {
                                "type": "String",
                                "value": "Subnet"
                            },
                            "ubuntuOSVersion": {
                                "type": "String",
                                "value": "18.04-LTS"
                            },
                            "virtualNetworkName": {
                                "type": "String",
                                "value": "vNet"
                            },
                            "vmName": {
                                "type": "String",
                                "value": "simpleLinuxVM"
                            },
                            "vmSize": {
                                "type": "String",
                                "value": "Standard_B2s"
                            }
                        },
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "template_link": "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-vm-simple-linux/azuredeploy.json"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Deployments
>  * ## Mydeployment
>    * correlation_id: 07a08b8c-9c48-45fe-9f67-53c7eea232b6
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Resources/deployments/myDeployment
>    * name: myDeployment
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * template_link: https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-vm-simple-linux/azuredeploy.json
>    * ### Output_Resources
>    * ### Secgroupnet
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/SecGroupNet
>      * name: SecGroupNet
>      * type: Microsoft.Network/networkSecurityGroups
>      * #### Depends_On
>    * ### Vnet
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/vNet
>      * name: vNet
>      * type: Microsoft.Network/virtualNetworks
>      * #### Depends_On
>    * ### Simplelinuxvmpublicip
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIpAddresses/simpleLinuxVMPublicIP
>      * name: simpleLinuxVMPublicIP
>      * type: Microsoft.Network/publicIpAddresses
>      * #### Depends_On
>    * ### Simplelinuxvmnetint
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/simpleLinuxVMNetInt
>      * name: simpleLinuxVMNetInt
>      * type: Microsoft.Network/networkInterfaces
>      * #### Depends_On
>        * 0: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/SecGroupNet
>        * 1: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/vNet
>        * 2: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIpAddresses/simpleLinuxVMPublicIP
>    * ### Simplelinuxvm
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/simpleLinuxVM
>      * name: simpleLinuxVM
>      * type: Microsoft.Compute/virtualMachines
>      * #### Depends_On
>        * 0: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/simpleLinuxVMNetInt
>    * ### Outputs
>      * #### Adminusername
>        * type: String
>        * value: exampleadmin
>      * #### Hostname
>        * type: String
>        * value: xsoarexample.australiasoutheast.cloudapp.azure.com
>      * #### Sshcommand
>        * type: String
>        * value: ssh exampleadmin@xsoarexample.australiasoutheast.cloudapp.azure.com
>    * ### Parameters
>      * #### Adminpasswordorkey
>        * type: SecureString
>      * #### Adminusername
>        * type: String
>        * value: exampleadmin
>      * #### Authenticationtype
>        * type: String
>        * value: password
>      * #### Dnslabelprefix
>        * type: String
>        * value: xsoarexample
>      * #### Location
>        * type: String
>        * value: australiasoutheast
>      * #### Networksecuritygroupname
>        * type: String
>        * value: SecGroupNet
>      * #### Subnetname
>        * type: String
>        * value: Subnet
>      * #### Ubuntuosversion
>        * type: String
>        * value: 18.04-LTS
>      * #### Virtualnetworkname
>        * type: String
>        * value: vNet
>      * #### Vmname
>        * type: String
>        * value: simpleLinuxVM
>      * #### Vmsize
>        * type: String
>        * value: Standard_B2s


### azure-rm-functionapp
***
Manage Azure Function Apps
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_functionapp_module.html


#### Base Command

`azure-rm-functionapp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the Azure Function App. | Required | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| plan | App service plan.<br/>It can be name of existing app service plan in same resource group as function app.<br/>It can be resource id of existing app service plan.<br/>Resource id. For example /subscriptions/&lt;subs_id&gt;/resourceGroups/&lt;resource_group&gt;/providers/Microsoft.Web/serverFarms/&lt;plan_name&gt;.<br/>It can be a dict which contains `name`, `resource_group`.<br/>`name`. Name of app service plan.<br/>`resource_group`. Resource group name of app service plan. | Optional | 
| container_settings | Web app container settings. | Optional | 
| storage_account | Name of the storage account to use. | Required | 
| app_settings | Dictionary containing application settings. | Optional | 
| state | Assert the state of the Function App. Use `present` to create or update a Function App and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmFunctionapp.state | unknown | Current state of the Azure Function App. | 


#### Command Example
```!azure-rm-functionapp resource_group="myResourceGroup" name="myxsoarFunctionApp" storage_account="xsoarexamplestorage" state="absent"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmFunctionapp": [
            {
                "changed": false,
                "state": {},
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State


### azure-rm-functionapp-info
***
Get Azure Function App facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_functionapp_info_module.html


#### Base Command

`azure-rm-functionapp-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific Function App. | Optional | 
| resource_group | Limit results to a resource group. Required when filtering by name. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmFunctionappInfo.azure_functionapps | unknown | List of Azure Function Apps dicts. | 


#### Command Example
```!azure-rm-functionapp-info resource_group="myResourceGroup"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmFunctionappInfo": [
            {
                "changed": false,
                "info": {
                    "azure_functionapps": []
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Functionapps


### azure-rm-gallery
***
Manage Azure Shared Image Gallery instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_gallery_module.html


#### Base Command

`azure-rm-gallery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | The name of the Shared Image Gallery. Valid names consist of less than 80 alphanumeric characters, underscores and periods. | Required | 
| location | Resource location. | Optional | 
| description | The description of this Shared Image Gallery resource. This property is updatable. | Optional | 
| state | Assert the state of the Gallery.<br/>Use `present` to create or update an Gallery and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGallery.id | string | Resource Id | 


#### Command Example
```!azure-rm-gallery resource_group="myResourceGroup" name="myGallery1283" location="australiasoutheast" description="This is the gallery description." ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGallery": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283


### azure-rm-gallery-info
***
Get Azure Shared Image Gallery info.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_gallery_info_module.html


#### Base Command

`azure-rm-gallery-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Optional | 
| name | Resource name. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGalleryInfo.galleries | unknown | A list of dict results where the key is the name of the gallery and the values are the info for that gallery. | 


#### Command Example
```!azure-rm-gallery-info```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGalleryInfo": [
            {
                "changed": false,
                "galleries": [
                    {
                        "description": "This is the gallery description.",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/MYRESOURCEGROUP/providers/Microsoft.Compute/galleries/myGallery1283",
                        "location": "australiasoutheast",
                        "name": "myGallery1283",
                        "provisioning_state": "Succeeded",
                        "tags": null
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Galleries
>  * ## Mygallery1283
>    * description: This is the gallery description.
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/MYRESOURCEGROUP/providers/Microsoft.Compute/galleries/myGallery1283
>    * location: australiasoutheast
>    * name: myGallery1283
>    * provisioning_state: Succeeded
>    * tags: None


### azure-rm-galleryimage
***
Manage Azure SIG Image instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_galleryimage_module.html


#### Base Command

`azure-rm-galleryimage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| gallery_name | The name of the Shared Image Gallery in which the Image Definition is to be created. | Required | 
| name | The name of the gallery Image Definition to be created or updated. The allowed characters are alphabets and numbers with dots, dashes, and periods allowed in the middle. The maximum length is 80 characters. | Required | 
| location | Resource location. | Optional | 
| description | The description of this gallery Image Definition resource. This property is updatable. | Optional | 
| eula | The Eula agreement for the gallery Image Definition. | Optional | 
| privacy_statement_uri | The privacy statement uri. | Optional | 
| release_note_uri | The release note uri. | Optional | 
| os_type | This property allows you to specify the type of the OS that is included in the disk when creating a VM from a managed image. Possible values are: windows, linux. | Required | 
| os_state | The allowed values for OS State are 'Generalized'. Possible values are: generalized, specialized. | Required | 
| end_of_life_date | The end of life date of the gallery Image Definition. This property can be used for decommissioning purposes. This property is updatable. Format should be according to ISO-8601, for instance "2019-06-26". | Optional | 
| identifier | Image identifier. | Required | 
| recommended | Recommended parameter values. | Optional | 
| disallowed | Disallowed parameter values. | Optional | 
| purchase_plan | Purchase plan. | Optional | 
| state | Assert the state of the GalleryImage.<br/>Use `present` to create or update an GalleryImage and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGalleryimage.id | string | Resource Id | 


#### Command Example
```!azure-rm-galleryimage resource_group="myResourceGroup" gallery_name="myGallery1283" name="myImage" location="australiasoutheast" os_type="linux" os_state="generalized" identifier="{\"publisher\": \"myPublisherName\", \"offer\": \"myOfferName\", \"sku\": \"mySkuName\"}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGalleryimage": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage


### azure-rm-galleryimage-info
***
Get Azure SIG Image info.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_galleryimage_info_module.html


#### Base Command

`azure-rm-galleryimage-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| gallery_name | The name of the shared image gallery from which the image definitions are to be retrieved. | Required | 
| name | Resource name. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGalleryimageInfo.images | unknown | A list of dict results where the key is the name of the image and the values are the info for that image. | 


#### Command Example
```!azure-rm-galleryimage-info resource_group="myResourceGroup" gallery_name="myGallery1283"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGalleryimageInfo": [
            {
                "changed": false,
                "images": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage",
                        "identifier": {
                            "offer": "myOfferName",
                            "publisher": "myPublisherName",
                            "sku": "mySkuName"
                        },
                        "location": "australiasoutheast",
                        "name": "myImage",
                        "os_state": "Generalized",
                        "os_type": "Linux",
                        "tags": null
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Images
>  * ## Myimage
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage
>    * location: australiasoutheast
>    * name: myImage
>    * os_state: Generalized
>    * os_type: Linux
>    * tags: None
>    * ### Identifier
>      * offer: myOfferName
>      * publisher: myPublisherName
>      * sku: mySkuName


### azure-rm-galleryimageversion
***
Manage Azure SIG Image Version instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_galleryimageversion_module.html


#### Base Command

`azure-rm-galleryimageversion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| gallery_name | The name of the Shared Image Gallery in which the Image Definition resides. | Required | 
| gallery_image_name | The name of the gallery Image Definition in which the Image Version is to be created. | Required | 
| name | The name of the gallery Image Version to be created. Needs to follow semantic version name pattern: The allowed characters are digit and period. Digits must be within the range of a 32-bit integer. Format: &lt;MajorVersion&gt;.&lt;MinorVersion&gt;.&lt;Patch&gt;. | Required | 
| location | Resource location. | Optional | 
| publishing_profile | Publishing profile. | Required | 
| state | Assert the state of the GalleryImageVersion.<br/>Use `present` to create or update an GalleryImageVersion and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGalleryimageversion.id | string | Resource Id | 


#### Command Example
```!azure-rm-galleryimageversion resource_group="myResourceGroup" gallery_name="myGallery1283" gallery_image_name="myImage" name="10.1.3" location="australiasoutheast" publishing_profile="{{{\"end_of_life_date\": \"2022-10-01t00:00:00+00:00\", \"exclude_from_latest\": True, \"replica_count\": 1, \"storage_account_type\": \"Standard_LRS\", \"target_regions\": [{\"name\": \"australiasoutheast\", \"regional_replica_count\": 1}], \"managed_image\": {\"name\": \"myImage\", \"resource_group\": \"myResourceGroup\"}}}}" execution-timeout=90000000```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGalleryimageversion": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage/versions/10.1.3",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage/versions/10.1.3


### azure-rm-galleryimageversion-info
***
Get Azure SIG Image Version info.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_galleryimageversion_info_module.html


#### Base Command

`azure-rm-galleryimageversion-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| gallery_name | The name of the Shared Image Gallery in which the Image Definition resides. | Required | 
| gallery_image_name | The name of the gallery Image Definition in which the Image Version resides. | Required | 
| name | Resource name. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmGalleryimageversionInfo.versions | unknown | A list of dict results where the key is the name of the version and the values are the info for that version. | 


#### Command Example
```!azure-rm-galleryimageversion-info resource_group="myResourceGroup" gallery_name="myGallery1283" gallery_image_name="myImage" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmGalleryimageversionInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "versions": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage/versions/10.1.3",
                        "location": "australiasoutheast",
                        "name": "10.1.3",
                        "provisioning_state": "Failed",
                        "publishing_profile": {
                            "endOfLifeDate": "2022-10-01T00:00:00+00:00",
                            "excludeFromLatest": true,
                            "publishedDate": "2021-06-20T15:39:54.9539674+00:00",
                            "replicaCount": 1,
                            "source": {
                                "managedImage": {
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage"
                                }
                            },
                            "storageAccountType": "Standard_LRS",
                            "targetRegions": [
                                {
                                    "name": "Australia Southeast",
                                    "regionalReplicaCount": 1,
                                    "storageAccountType": "Standard_LRS"
                                }
                            ]
                        },
                        "tags": null
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Versions
>  * ## 10.1.3
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/galleries/myGallery1283/images/myImage/versions/10.1.3
>    * location: australiasoutheast
>    * name: 10.1.3
>    * provisioning_state: Failed
>    * tags: None
>    * ### Publishing_Profile
>      * endOfLifeDate: 2022-10-01T00:00:00+00:00
>      * excludeFromLatest: True
>      * publishedDate: 2021-06-20T15:39:54.9539674+00:00
>      * replicaCount: 1
>      * storageAccountType: Standard_LRS
>      * #### Source
>        * ##### Managedimage
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage
>      * #### Targetregions
>      * #### Australia Southeast
>        * name: Australia Southeast
>        * regionalReplicaCount: 1
>        * storageAccountType: Standard_LRS


### azure-rm-image
***
Manage Azure image
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_image_module.html


#### Base Command

`azure-rm-image`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the image. | Required | 
| source | OS disk source from the same region.<br/>It can be a virtual machine, OS disk blob URI, managed OS disk, or OS snapshot.<br/>Each type of source except for blob URI can be given as resource id, name or a dict contains `resource_group`, `name` and `type`.<br/>If source type is blob URI, the source should be the full URI of the blob in string type.<br/>If you specify the `type` in a dict, acceptable value contains `disks`, `virtual_machines` and `snapshots`. | Required | 
| data_disk_sources | List of data disk sources, including unmanaged blob URI, managed disk id or name, or snapshot id or name. | Optional | 
| location | Location of the image. Derived from `resource_group` if not specified. | Optional | 
| os_type | The OS type of image. Possible values are: Windows, Linux. | Optional | 
| state | Assert the state of the image. Use `present` to create or update a image and `absent` to delete an image. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmImage.id | string | Image resource path. | 


#### Command Example
```!azure-rm-image resource_group="myResourceGroup" name="myImage" source="testvm10" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmImage": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage



### azure-rm-image-info
***
Get facts about azure custom images
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_image_info_module.html


#### Base Command

`azure-rm-image-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Optional | 
| name | Name of the image to filter from existing images. | Optional | 
| tags | List of tags to be matched. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmImageInfo.images | unknown | List of image dicts. | 


#### Command Example
```!azure-rm-image-info name="myImage" resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmImageInfo": [
            {
                "changed": false,
                "images": [
                    {
                        "data_disks": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage",
                        "location": "australiasoutheast",
                        "name": "myImage",
                        "os_blob_uri": "https://test/vhds/testvm10.vhd",
                        "os_disk": null,
                        "os_disk_caching": "ReadOnly",
                        "os_state": "Generalized",
                        "os_storage_account_type": "Standard_LRS",
                        "os_type": "Linux",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "source": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10",
                        "tags": null
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Images
>  * ## Myimage
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/images/myImage
>    * location: australiasoutheast
>    * name: myImage
>    * os_blob_uri: https://test/vhds/testvm10.vhd
>    * os_disk: None
>    * os_disk_caching: ReadOnly
>    * os_state: Generalized
>    * os_storage_account_type: Standard_LRS
>    * os_type: Linux
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * source: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10
>    * tags: None
>    * ### Data_Disks


### azure-rm-loadbalancer
***
Manage Azure load balancers
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_loadbalancer_module.html


#### Base Command

`azure-rm-loadbalancer`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the load balancer exists or will be created. | Required | 
| name | Name of the load balancer. | Required | 
| state | Assert the state of the load balancer. Use `present` to create/update a load balancer, or `absent` to delete one. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| sku | The load balancer SKU. Possible values are: Basic, Standard. | Optional | 
| frontend_ip_configurations | List of frontend IPs to be used. | Optional | 
| backend_address_pools | List of backend address pools. | Optional | 
| probes | List of probe definitions used to check endpoint health. | Optional | 
| inbound_nat_pools | Defines an external port range for inbound NAT to a single backend port on NICs associated with a load balancer.<br/>Inbound NAT rules are created automatically for each NIC associated with the Load Balancer using an external port from this range.<br/>Defining an Inbound NAT pool on your Load Balancer is mutually exclusive with defining inbound Nat rules.<br/>Inbound NAT pools are referenced from virtual machine scale sets.<br/>NICs that are associated with individual virtual machines cannot reference an inbound NAT pool.<br/>They have to reference individual inbound NAT rules. | Optional | 
| load_balancing_rules | Object collection representing the load balancing rules Gets the provisioning. | Optional | 
| inbound_nat_rules | Collection of inbound NAT Rules used by a load balancer.<br/>Defining inbound NAT rules on your load balancer is mutually exclusive with defining an inbound NAT pool.<br/>Inbound NAT pools are referenced from virtual machine scale sets.<br/>NICs that are associated with individual virtual machines cannot reference an Inbound NAT pool.<br/>They have to reference individual inbound NAT rules. | Optional | 
| public_ip_address_name | (deprecated) Name of an existing public IP address object to associate with the security group.<br/>This option has been deprecated, and will be removed in 2.9. Use `frontend_ip_configurations` instead. | Optional | 
| probe_port | (deprecated) The port that the health probe will use.<br/>This option has been deprecated, and will be removed in 2.9. Use `probes` instead. | Optional | 
| probe_protocol | (deprecated) The protocol to use for the health probe.<br/>This option has been deprecated, and will be removed in 2.9. Use `probes` instead. Possible values are: Tcp, Http, Https. | Optional | 
| probe_interval | (deprecated) Time (in seconds) between endpoint health probes.<br/>This option has been deprecated, and will be removed in 2.9. Use `probes` instead. Default is 15. | Optional | 
| probe_fail_count | (deprecated) The amount of probe failures for the load balancer to make a health determination.<br/>This option has been deprecated, and will be removed in 2.9. Use `probes` instead. Default is 3. | Optional | 
| probe_request_path | (deprecated) The URL that an HTTP probe or HTTPS probe will use (only relevant if `probe_protocol=Http` or `probe_protocol=Https`).<br/>This option has been deprecated, and will be removed in 2.9. Use `probes` instead. | Optional | 
| protocol | (deprecated) The protocol (TCP or UDP) that the load balancer will use.<br/>This option has been deprecated, and will be removed in 2.9. Use `load_balancing_rules` instead. Possible values are: Tcp, Udp. | Optional | 
| load_distribution | (deprecated) The type of load distribution that the load balancer will employ.<br/>This option has been deprecated, and will be removed in 2.9. Use `load_balancing_rules` instead. Possible values are: Default, SourceIP, SourceIPProtocol. | Optional | 
| frontend_port | (deprecated) Frontend port that will be exposed for the load balancer.<br/>This option has been deprecated, and will be removed in 2.9. Use `load_balancing_rules` instead. | Optional | 
| backend_port | (deprecated) Backend port that will be exposed for the load balancer.<br/>This option has been deprecated, and will be removed in 2.9. Use `load_balancing_rules` instead. | Optional | 
| idle_timeout | (deprecated) Timeout for TCP idle connection in minutes.<br/>This option has been deprecated, and will be removed in 2.9. Use `load_balancing_rules` instead. Default is 4. | Optional | 
| natpool_frontend_port_start | (deprecated) Start of the port range for a NAT pool.<br/>This option has been deprecated, and will be removed in 2.9. Use `inbound_nat_pools` instead. | Optional | 
| natpool_frontend_port_end | (deprecated) End of the port range for a NAT pool.<br/>This option has been deprecated, and will be removed in 2.9. Use `inbound_nat_pools` instead. | Optional | 
| natpool_backend_port | (deprecated) Backend port used by the NAT pool.<br/>This option has been deprecated, and will be removed in 2.9. Use `inbound_nat_pools` instead. | Optional | 
| natpool_protocol | (deprecated) The protocol for the NAT pool.<br/>This option has been deprecated, and will be removed in 2.9. Use `inbound_nat_pools` instead. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmLoadbalancer.state | unknown | Current state of the load balancer. | 
| Azure.AzureRmLoadbalancer.changed | boolean | Whether or not the resource has changed. | 


#### Command Example
```!azure-rm-loadbalancer resource_group="myResourceGroup" name="testloadbalancer1" frontend_ip_configurations="{{ [{\"name\": \"frontendipconf0\", \"public_ip_address\": \"loadbalancerpip\"}] }}" backend_address_pools="{{ [{\"name\": \"backendaddrpool0\"}] }}" probes="{{ [{\"name\": \"prob0\", \"port\": 80}] }}" inbound_nat_pools="{{ [{\"name\": \"inboundnatpool0\", \"frontend_ip_configuration_name\": \"frontendipconf0\", \"protocol\": \"Tcp\", \"frontend_port_range_start\": 80, \"frontend_port_range_end\": 81, \"backend_port\": 8080}] }}" load_balancing_rules="{{ [{\"name\": \"lbrbalancingrule0\", \"frontend_ip_configuration\": \"frontendipconf0\", \"backend_address_pool\": \"backendaddrpool0\", \"frontend_port\": 80, \"backend_port\": 80, \"probe\": \"prob0\"}] }}"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmLoadbalancer": [
            {
                "changed": true,
                "state": {
                    "backend_address_pools": [
                        {
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0",
                            "load_balancing_rules": [
                                {
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                }
                            ],
                            "name": "backendaddrpool0",
                            "provisioning_state": "Succeeded",
                            "type": "Microsoft.Network/loadBalancers/backendAddressPools"
                        }
                    ],
                    "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                    "frontend_ip_configurations": [
                        {
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0",
                            "inbound_nat_pools": [
                                {
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0"
                                }
                            ],
                            "load_balancing_rules": [
                                {
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                }
                            ],
                            "name": "frontendipconf0",
                            "private_ip_allocation_method": "Dynamic",
                            "provisioning_state": "Succeeded",
                            "public_ip_address": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/loadbalancerpip"
                            },
                            "type": "Microsoft.Network/loadBalancers/frontendIPConfigurations"
                        }
                    ],
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1",
                    "inbound_nat_pools": [
                        {
                            "backend_port": 8080,
                            "enable_floating_ip": false,
                            "enable_tcp_reset": false,
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "frontend_ip_configuration": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0"
                            },
                            "frontend_port_range_end": 81,
                            "frontend_port_range_start": 80,
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0",
                            "idle_timeout_in_minutes": 4,
                            "name": "inboundnatpool0",
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "type": "Microsoft.Network/loadBalancers/inboundNatPools"
                        }
                    ],
                    "inbound_nat_rules": [],
                    "load_balancing_rules": [
                        {
                            "backend_address_pool": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0"
                            },
                            "backend_port": 80,
                            "enable_floating_ip": false,
                            "enable_tcp_reset": false,
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "frontend_ip_configuration": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0"
                            },
                            "frontend_port": 80,
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0",
                            "idle_timeout_in_minutes": 4,
                            "load_distribution": "Default",
                            "name": "lbrbalancingrule0",
                            "probe": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0"
                            },
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "type": "Microsoft.Network/loadBalancers/loadBalancingRules"
                        }
                    ],
                    "location": "australiasoutheast",
                    "name": "testloadbalancer1",
                    "probes": [
                        {
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0",
                            "interval_in_seconds": 15,
                            "load_balancing_rules": [
                                {
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                }
                            ],
                            "name": "prob0",
                            "number_of_probes": 3,
                            "port": 80,
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "type": "Microsoft.Network/loadBalancers/probes"
                        }
                    ],
                    "provisioning_state": "Succeeded",
                    "resource_guid": "96a7cea3-982d-4478-b164-c99a2a0ff9a5",
                    "sku": {
                        "name": "Basic"
                    },
                    "type": "Microsoft.Network/loadBalancers"
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1
>    * location: australiasoutheast
>    * name: testloadbalancer1
>    * provisioning_state: Succeeded
>    * resource_guid: 96a7cea3-982d-4478-b164-c99a2a0ff9a5
>    * type: Microsoft.Network/loadBalancers
>    * ### Backend_Address_Pools
>    * ### Backendaddrpool0
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0
>      * name: backendaddrpool0
>      * provisioning_state: Succeeded
>      * type: Microsoft.Network/loadBalancers/backendAddressPools
>      * #### Load_Balancing_Rules
>      * #### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>    * ### Frontend_Ip_Configurations
>    * ### Frontendipconf0
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>      * name: frontendipconf0
>      * private_ip_allocation_method: Dynamic
>      * provisioning_state: Succeeded
>      * type: Microsoft.Network/loadBalancers/frontendIPConfigurations
>      * #### Inbound_Nat_Pools
>      * #### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Inboundnatpools/Inboundnatpool0
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0
>      * #### Load_Balancing_Rules
>      * #### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>      * #### Public_Ip_Address
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/loadbalancerpip
>    * ### Inbound_Nat_Pools
>    * ### Inboundnatpool0
>      * backend_port: 8080
>      * enable_floating_ip: False
>      * enable_tcp_reset: False
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * frontend_port_range_end: 81
>      * frontend_port_range_start: 80
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0
>      * idle_timeout_in_minutes: 4
>      * name: inboundnatpool0
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * type: Microsoft.Network/loadBalancers/inboundNatPools
>      * #### Frontend_Ip_Configuration
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>    * ### Inbound_Nat_Rules
>    * ### Load_Balancing_Rules
>    * ### Lbrbalancingrule0
>      * backend_port: 80
>      * enable_floating_ip: False
>      * enable_tcp_reset: False
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * frontend_port: 80
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>      * idle_timeout_in_minutes: 4
>      * load_distribution: Default
>      * name: lbrbalancingrule0
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * type: Microsoft.Network/loadBalancers/loadBalancingRules
>      * #### Backend_Address_Pool
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0
>      * #### Frontend_Ip_Configuration
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>      * #### Probe
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0
>    * ### Probes
>    * ### Prob0
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0
>      * interval_in_seconds: 15
>      * name: prob0
>      * number_of_probes: 3
>      * port: 80
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * type: Microsoft.Network/loadBalancers/probes
>      * #### Load_Balancing_Rules
>      * #### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>    * ### Sku
>      * name: Basic


### azure-rm-loadbalancer-info
***
Get load balancer facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_loadbalancer_info_module.html


#### Base Command

`azure-rm-loadbalancer-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific resource group. | Optional | 
| resource_group | The resource group to search for the desired load balancer. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmLoadbalancerInfo.azure_loadbalancers | unknown | List of load balancer dicts. | 


#### Command Example
```!azure-rm-loadbalancer-info name="testloadbalancer1" resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmLoadbalancerInfo": [
            {
                "changed": false,
                "info": {
                    "azure_loadbalancers": [
                        {
                            "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1",
                            "location": "australiasoutheast",
                            "name": "testloadbalancer1",
                            "properties": {
                                "backendAddressPools": [
                                    {
                                        "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0",
                                        "name": "backendaddrpool0",
                                        "properties": {
                                            "loadBalancingRules": [
                                                {
                                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                                }
                                            ],
                                            "provisioningState": "Succeeded"
                                        },
                                        "type": "Microsoft.Network/loadBalancers/backendAddressPools"
                                    }
                                ],
                                "frontendIPConfigurations": [
                                    {
                                        "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0",
                                        "name": "frontendipconf0",
                                        "properties": {
                                            "inboundNatPools": [
                                                {
                                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0"
                                                }
                                            ],
                                            "loadBalancingRules": [
                                                {
                                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                                }
                                            ],
                                            "privateIPAllocationMethod": "Dynamic",
                                            "provisioningState": "Succeeded",
                                            "publicIPAddress": {
                                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/loadbalancerpip"
                                            }
                                        },
                                        "type": "Microsoft.Network/loadBalancers/frontendIPConfigurations"
                                    }
                                ],
                                "inboundNatPools": [
                                    {
                                        "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0",
                                        "name": "inboundnatpool0",
                                        "properties": {
                                            "backendPort": 8080,
                                            "enableFloatingIP": false,
                                            "enableTcpReset": false,
                                            "frontendIPConfiguration": {
                                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0"
                                            },
                                            "frontendPortRangeEnd": 81,
                                            "frontendPortRangeStart": 80,
                                            "idleTimeoutInMinutes": 4,
                                            "protocol": "Tcp",
                                            "provisioningState": "Succeeded"
                                        },
                                        "type": "Microsoft.Network/loadBalancers/inboundNatPools"
                                    }
                                ],
                                "inboundNatRules": [],
                                "loadBalancingRules": [
                                    {
                                        "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0",
                                        "name": "lbrbalancingrule0",
                                        "properties": {
                                            "backendAddressPool": {
                                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0"
                                            },
                                            "backendPort": 80,
                                            "enableFloatingIP": false,
                                            "enableTcpReset": false,
                                            "frontendIPConfiguration": {
                                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0"
                                            },
                                            "frontendPort": 80,
                                            "idleTimeoutInMinutes": 4,
                                            "loadDistribution": "Default",
                                            "probe": {
                                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0"
                                            },
                                            "protocol": "Tcp",
                                            "provisioningState": "Succeeded"
                                        },
                                        "type": "Microsoft.Network/loadBalancers/loadBalancingRules"
                                    }
                                ],
                                "probes": [
                                    {
                                        "etag": "W/\"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96\"",
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0",
                                        "name": "prob0",
                                        "properties": {
                                            "intervalInSeconds": 15,
                                            "loadBalancingRules": [
                                                {
                                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0"
                                                }
                                            ],
                                            "numberOfProbes": 3,
                                            "port": 80,
                                            "protocol": "Tcp",
                                            "provisioningState": "Succeeded"
                                        },
                                        "type": "Microsoft.Network/loadBalancers/probes"
                                    }
                                ],
                                "provisioningState": "Succeeded",
                                "resourceGuid": "96a7cea3-982d-4478-b164-c99a2a0ff9a5"
                            },
                            "sku": {
                                "name": "Basic"
                            },
                            "type": "Microsoft.Network/loadBalancers"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Loadbalancers
>    * ### Testloadbalancer1
>      * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1
>      * location: australiasoutheast
>      * name: testloadbalancer1
>      * type: Microsoft.Network/loadBalancers
>      * #### Properties
>        * provisioningState: Succeeded
>        * resourceGuid: 96a7cea3-982d-4478-b164-c99a2a0ff9a5
>        * ##### Backendaddresspools
>        * ##### Backendaddrpool0
>          * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0
>          * name: backendaddrpool0
>          * type: Microsoft.Network/loadBalancers/backendAddressPools
>          * ###### Properties
>            * provisioningState: Succeeded
>            * ####### Loadbalancingrules
>            * ####### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>        * ##### Frontendipconfigurations
>        * ##### Frontendipconf0
>          * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>          * name: frontendipconf0
>          * type: Microsoft.Network/loadBalancers/frontendIPConfigurations
>          * ###### Properties
>            * privateIPAllocationMethod: Dynamic
>            * provisioningState: Succeeded
>            * ####### Inboundnatpools
>            * ####### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Inboundnatpools/Inboundnatpool0
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0
>            * ####### Loadbalancingrules
>            * ####### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>            * ####### Publicipaddress
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/loadbalancerpip
>        * ##### Inboundnatpools
>        * ##### Inboundnatpool0
>          * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/inboundNatPools/inboundnatpool0
>          * name: inboundnatpool0
>          * type: Microsoft.Network/loadBalancers/inboundNatPools
>          * ###### Properties
>            * backendPort: 8080
>            * enableFloatingIP: False
>            * enableTcpReset: False
>            * frontendPortRangeEnd: 81
>            * frontendPortRangeStart: 80
>            * idleTimeoutInMinutes: 4
>            * protocol: Tcp
>            * provisioningState: Succeeded
>            * ####### Frontendipconfiguration
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>        * ##### Inboundnatrules
>        * ##### Loadbalancingrules
>        * ##### Lbrbalancingrule0
>          * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>          * name: lbrbalancingrule0
>          * type: Microsoft.Network/loadBalancers/loadBalancingRules
>          * ###### Properties
>            * backendPort: 80
>            * enableFloatingIP: False
>            * enableTcpReset: False
>            * frontendPort: 80
>            * idleTimeoutInMinutes: 4
>            * loadDistribution: Default
>            * protocol: Tcp
>            * provisioningState: Succeeded
>            * ####### Backendaddresspool
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/backendAddressPools/backendaddrpool0
>            * ####### Frontendipconfiguration
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/frontendIPConfigurations/frontendipconf0
>            * ####### Probe
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0
>        * ##### Probes
>        * ##### Prob0
>          * etag: W/"4fcaeb51-9c56-4e98-9fa1-15eca75d0b96"
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/probes/prob0
>          * name: prob0
>          * type: Microsoft.Network/loadBalancers/probes
>          * ###### Properties
>            * intervalInSeconds: 15
>            * numberOfProbes: 3
>            * port: 80
>            * protocol: Tcp
>            * provisioningState: Succeeded
>            * ####### Loadbalancingrules
>            * ####### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Loadbalancers/Testloadbalancer1/Loadbalancingrules/Lbrbalancingrule0
>              * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/loadBalancers/testloadbalancer1/loadBalancingRules/lbrbalancingrule0
>      * #### Sku
>        * name: Basic


### azure-rm-manageddisk
***
Manage Azure Manage Disks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_manageddisk_module.html


#### Base Command

`azure-rm-manageddisk`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the managed disk exists or will be created. | Required | 
| name | Name of the managed disk. | Required | 
| state | Assert the state of the managed disk. Use `present` to create or update a managed disk and `absent` to delete a managed disk. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| storage_account_type | Type of storage for the managed disk.<br/>If not specified, the disk is created as `Standard_LRS`.<br/>`Standard_LRS` is for Standard HDD.<br/>`StandardSSD_LRS` (added in 2.8) is for Standard SSD.<br/>`Premium_LRS` is for Premium SSD.<br/>`UltraSSD_LRS` (added in 2.8) is for Ultra SSD, which is in preview mode, and only available on select instance types.<br/>See `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disks-types` for more information about disk types. Possible values are: Standard_LRS, StandardSSD_LRS, Premium_LRS, UltraSSD_LRS. | Optional | 
| create_option | `import` from a VHD file in `source_uri` and `copy` from previous managed disk `source_uri`. Possible values are: empty, import, copy. | Optional | 
| source_uri | URI to a valid VHD file to be used or the resource ID of the managed disk to copy. | Optional | 
| os_type | Type of Operating System.<br/>Used when `create_option=copy` or `create_option=import` and the source is an OS disk.<br/>If omitted during creation, no value is set.<br/>If omitted during an update, no change is made.<br/>Once set, this value cannot be cleared. Possible values are: linux, windows. | Optional | 
| disk_size_gb | Size in GB of the managed disk to be created.<br/>If `create_option=copy` then the value must be greater than or equal to the source's size. | Optional | 
| managed_by | Name of an existing virtual machine with which the disk is or will be associated, this VM should be in the same resource group.<br/>To detach a disk from a vm, explicitly set to ''.<br/>If this option is unset, the value will not be changed. | Optional | 
| attach_caching | Disk caching policy controlled by VM. Will be used when attached to the VM defined by `managed_by`.<br/>If this option is different from the current caching policy, the managed disk will be deattached and attached with current caching option again. Possible values are: , read_only, read_write. | Optional | 
| tags | Tags to assign to the managed disk.<br/>Format tags as 'key' or 'key:value'. | Optional | 
| zone | The Azure managed disk's zone.<br/>Allowed values are `1`, `2`, `3` and `' '`. Possible values are: 1, 2, 3, . | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmManageddisk.id | unknown | The managed disk resource ID. | 
| Azure.AzureRmManageddisk.state | unknown | Current state of the managed disk. | 
| Azure.AzureRmManageddisk.changed | boolean | Whether or not the resource has changed. | 


#### Command Example
```!azure-rm-manageddisk name="mymanageddisk" location="australiasoutheast" resource_group="myResourceGroup" disk_size_gb="4" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmManageddisk": [
            {
                "changed": true,
                "state": {
                    "create_option": "empty",
                    "disk_size_gb": 4,
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/disks/mymanageddisk",
                    "location": "australiasoutheast",
                    "managed_by": null,
                    "name": "mymanageddisk",
                    "os_type": null,
                    "source_uri": null,
                    "storage_account_type": "Standard_LRS",
                    "tags": null,
                    "zone": ""
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * create_option: empty
>    * disk_size_gb: 4
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/disks/mymanageddisk
>    * location: australiasoutheast
>    * managed_by: None
>    * name: mymanageddisk
>    * os_type: None
>    * source_uri: None
>    * storage_account_type: Standard_LRS
>    * tags: None
>    * zone: 


### azure-rm-manageddisk-info
***
Get managed disk facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_manageddisk_info_module.html


#### Base Command

`azure-rm-manageddisk-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific managed disk. | Optional | 
| resource_group | Limit results to a specific resource group. | Optional | 
| tags | Limit results by providing a list of tags.<br/>Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmManageddiskInfo.azure_managed_disk | unknown | List of managed disk dicts. | 


#### Command Example
```!azure-rm-manageddisk-info name="mymanageddisk" resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmManageddiskInfo": [
            {
                "changed": false,
                "info": {
                    "azure_managed_disk": [
                        {
                            "create_option": "empty",
                            "disk_size_gb": 4,
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/disks/mymanageddisk",
                            "location": "australiasoutheast",
                            "managed_by": null,
                            "name": "mymanageddisk",
                            "os_type": null,
                            "source_uri": null,
                            "storage_account_type": "Standard_LRS",
                            "tags": null,
                            "zone": ""
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Managed_Disk
>    * ### Mymanageddisk
>      * create_option: empty
>      * disk_size_gb: 4
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/disks/mymanageddisk
>      * location: australiasoutheast
>      * managed_by: None
>      * name: mymanageddisk
>      * os_type: None
>      * source_uri: None
>      * storage_account_type: Standard_LRS
>      * tags: None
>      * zone: 


### azure-rm-resource-info
***
Generic facts of Azure resources
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_resource_info_module.html


#### Base Command

`azure-rm-resource-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Azure RM Resource URL. | Optional | 
| api_version | Specific API version to be used. | Optional | 
| provider | Provider type, should be specified in no URL is given. | Optional | 
| resource_group | Resource group to be used.<br/>Required if URL is not specified. | Optional | 
| resource_type | Resource type. | Optional | 
| resource_name | Resource name. | Optional | 
| subresource | List of subresources. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmResourceInfo.response | unknown | Response specific to resource type. | 


#### Command Example
```!azure-rm-resource-info resource_group="myResourceGroup" provider="compute" resource_type="virtualMachines" resource_name="testvm10"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmResourceInfo": [
            {
                "changed": false,
                "response": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10",
                        "location": "australiasoutheast",
                        "name": "testvm10",
                        "properties": {
                            "hardwareProfile": {
                                "vmSize": "Standard_B2ms"
                            },
                            "networkProfile": {
                                "networkInterfaces": [
                                    {
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/testvm1001",
                                        "properties": {
                                            "primary": true
                                        }
                                    }
                                ]
                            },
                            "osProfile": {
                                "adminUsername": "exampleadmin",
                                "allowExtensionOperations": true,
                                "computerName": "testvm10",
                                "linuxConfiguration": {
                                    "disablePasswordAuthentication": false,
                                    "patchSettings": {
                                        "assessmentMode": "ImageDefault",
                                        "patchMode": "ImageDefault"
                                    },
                                    "provisionVMAgent": true
                                },
                                "requireGuestProvisionSignal": true,
                                "secrets": []
                            },
                            "provisioningState": "Succeeded",
                            "storageProfile": {
                                "dataDisks": [],
                                "imageReference": {
                                    "exactVersion": "0.20210329.591",
                                    "offer": "debian-10",
                                    "publisher": "Debian",
                                    "sku": "10",
                                    "version": "0.20210329.591"
                                },
                                "osDisk": {
                                    "caching": "ReadOnly",
                                    "createOption": "FromImage",
                                    "diskSizeGB": 30,
                                    "name": "testvm10.vhd",
                                    "osType": "Linux",
                                    "vhd": {
                                        "uri": "https://testvm103335.blob.core.windows.net/vhds/testvm10.vhd"
                                    }
                                }
                            },
                            "vmId": "052c538f-3b0a-4c06-9996-8f8a32bb208f"
                        },
                        "resources": [
                            {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension",
                                "location": "australiasoutheast",
                                "name": "myvmextension",
                                "properties": {
                                    "autoUpgradeMinorVersion": true,
                                    "provisioningState": "Succeeded",
                                    "publisher": "Microsoft.Azure.Extensions",
                                    "settings": {
                                        "commandToExecute": "hostname"
                                    },
                                    "type": "CustomScript",
                                    "typeHandlerVersion": "2.0"
                                },
                                "type": "Microsoft.Compute/virtualMachines/extensions"
                            }
                        ],
                        "tags": {
                            "_own_nic_": "testvm1001",
                            "_own_nsg_": "testvm1001",
                            "_own_pip_": "testvm1001",
                            "_own_sa_": "testvm103335"
                        },
                        "type": "Microsoft.Compute/virtualMachines"
                    }
                ],
                "status": "SUCCESS",
                "url": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.compute/virtualMachines/testvm10"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * url: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.compute/virtualMachines/testvm10
>  * ## Response
>  * ## Testvm10
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10
>    * location: australiasoutheast
>    * name: testvm10
>    * type: Microsoft.Compute/virtualMachines
>    * ### Properties
>      * provisioningState: Succeeded
>      * vmId: 052c538f-3b0a-4c06-9996-8f8a32bb208f
>      * #### Hardwareprofile
>        * vmSize: Standard_B2ms
>      * #### Networkprofile
>        * ##### Networkinterfaces
>        * ##### /Subscriptions/11111111-1111-1111-1111-111111111111/Resourcegroups/Myresourcegroup/Providers/Microsoft.Network/Networkinterfaces/Testvm1001
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/testvm1001
>          * ###### Properties
>            * primary: True
>      * #### Osprofile
>        * adminUsername: exampleadmin
>        * allowExtensionOperations: True
>        * computerName: testvm10
>        * requireGuestProvisionSignal: True
>        * ##### Linuxconfiguration
>          * disablePasswordAuthentication: False
>          * provisionVMAgent: True
>          * ###### Patchsettings
>            * assessmentMode: ImageDefault
>            * patchMode: ImageDefault
>        * ##### Secrets
>      * #### Storageprofile
>        * ##### Datadisks
>        * ##### Imagereference
>          * exactVersion: 0.20210329.591
>          * offer: debian-10
>          * publisher: Debian
>          * sku: 10
>          * version: 0.20210329.591
>        * ##### Osdisk
>          * caching: ReadOnly
>          * createOption: FromImage
>          * diskSizeGB: 30
>          * name: testvm10.vhd
>          * osType: Linux
>          * ###### Vhd
>            * uri: https://testvm103335.blob.core.windows.net/vhds/testvm10.vhd
>    * ### Resources
>    * ### Myvmextension
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension
>      * location: australiasoutheast
>      * name: myvmextension
>      * type: Microsoft.Compute/virtualMachines/extensions
>      * #### Properties
>        * autoUpgradeMinorVersion: True
>        * provisioningState: Succeeded
>        * publisher: Microsoft.Azure.Extensions
>        * type: CustomScript
>        * typeHandlerVersion: 2.0
>        * ##### Settings
>          * commandToExecute: hostname
>    * ### Tags
>      * _own_nic_: testvm1001
>      * _own_nsg_: testvm1001
>      * _own_pip_: testvm1001
>      * _own_sa_: testvm103335


### azure-rm-resourcegroup
***
Manage Azure resource groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_resourcegroup_module.html


#### Base Command

`azure-rm-resourcegroup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| force_delete_nonempty | Remove a resource group and all associated resources.<br/>Use with `state=absent` to delete a resource group that contains resources. Default is no. | Optional | 
| location | Azure location for the resource group. Required when creating a new resource group.<br/>Cannot be changed once resource group is created. | Optional | 
| name | Name of the resource group. | Required | 
| state | Assert the state of the resource group. Use `present` to create or update and `absent` to delete.<br/>When `absent` a resource group containing resources will not be removed unless the `force` option is used. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmResourcegroup.contains_resources | boolean | Whether or not the resource group contains associated resources. | 
| Azure.AzureRmResourcegroup.state | unknown | Current state of the resource group. | 


#### Command Example
```!azure-rm-resourcegroup name="myResourceGroup" location="australiasoutheast" tags="{\"testing\": \"testing\", \"delete\": \"never\"}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmResourcegroup": [
            {
                "changed": true,
                "contains_resources": false,
                "state": {
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup",
                    "location": "australiasoutheast",
                    "name": "myResourceGroup",
                    "provisioning_state": "Succeeded",
                    "tags": {
                        "delete": "never",
                        "testing": "testing"
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * contains_resources: False
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup
>    * location: australiasoutheast
>    * name: myResourceGroup
>    * provisioning_state: Succeeded
>    * ### Tags
>      * delete: never
>      * testing: testing


### azure-rm-resourcegroup-info
***
Get resource group facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_resourcegroup_info_module.html


#### Base Command

`azure-rm-resourcegroup-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific resource group. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| list_resources | List all resources under the resource group.<br/>Note this will cost network overhead for each resource group. Suggest use this when `name` set. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmResourcegroupInfo.azure_resourcegroups | unknown | List of resource group dicts. | 


#### Command Example
```!azure-rm-resourcegroup-info name="myResourceGroup" location="australiasoutheast"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmResourcegroupInfo": [
            {
                "changed": false,
                "resourcegroups": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup",
                        "location": "australiasoutheast",
                        "name": "myResourceGroup",
                        "properties": {
                            "provisioningState": "Succeeded"
                        },
                        "tags": {
                            "delete": "never",
                            "testing": "testing"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Resourcegroups
>  * ## Myresourcegroup
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup
>    * location: australiasoutheast
>    * name: myResourceGroup
>    * ### Properties
>      * provisioningState: Succeeded
>    * ### Tags
>      * delete: never
>      * testing: testing


### azure-rm-snapshot
***
Manage Azure Snapshot instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_snapshot_module.html


#### Base Command

`azure-rm-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | Resource name. | Optional | 
| location | Resource location. | Optional | 
| sku | SKU. | Optional | 
| os_type | The Operating System type. Possible values are: Linux, Windows. | Optional | 
| creation_data | Disk source information. CreationData information cannot be changed after the disk has been created. | Optional | 
| state | Assert the state of the Snapshot.<br/>Use `present` to create or update an Snapshot and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmSnapshot.id | string | Resource Id | 


#### Command Example
```!azure-rm-snapshot resource_group="myResourceGroup" name="mySnapshot" creation_data="{\"create_option\": \"Copy\", \"source_uri\": \"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/MYRESOURCEGROUP/providers/Microsoft.Compute/disks/mymanageddisk\"}" state="present" append_tags="Yes"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmSnapshot": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/snapshots/mySnapshot",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/snapshots/mySnapshot



### azure-rm-virtualmachine
***
Manage Azure virtual machines
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachine_module.html


#### Base Command

`azure-rm-virtualmachine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of the resource group containing the VM. | Required | 
| name | Name of the VM. | Required | 
| custom_data | Data made available to the VM and used by `cloud-init`.<br/>Only used on Linux images with `cloud-init` enabled.<br/>Consult `https://docs.microsoft.com/en-us/azure/virtual-machines/linux/using-cloud-init#cloud-init-overview` for cloud-init ready images.<br/>To enable cloud-init on a Linux image, follow `https://docs.microsoft.com/en-us/azure/virtual-machines/linux/cloudinit-prepare-custom-image`. | Optional | 
| state | State of the VM.<br/>Set to `present` to create a VM with the configuration specified by other options, or to update the configuration of an existing VM.<br/>Set to `absent` to remove a VM.<br/>Does not affect power state. Use `started`/`allocated`/`restarted` parameters to change the power state of a VM. Possible values are: absent, present. Default is present. | Optional | 
| started | Whether the VM is started or stopped.<br/>Set to (true) with `state=present` to start the VM.<br/>Set to `false` to stop the VM. Possible values are: Yes, No. Default is Yes. | Optional | 
| allocated | Whether the VM is allocated or deallocated, only useful with `state=present`. Possible values are: Yes, No. Default is Yes. | Optional | 
| generalized | Whether the VM is generalized or not.<br/>Set to `true` with `state=present` to generalize the VM.<br/>Generalizing a VM is irreversible. | Optional | 
| restarted | Set to `true` with `state=present` to restart a running VM. | Optional | 
| location | Valid Azure location for the VM. Defaults to location of the resource group. | Optional | 
| short_hostname | Name assigned internally to the host. On a Linux VM this is the name returned by the `hostname` command.<br/>When creating a VM, short_hostname defaults to `name`. | Optional | 
| vm_size | A valid Azure VM size value. For example, `Standard_D4`.<br/>Choices vary depending on the subscription and location. Check your subscription for available choices.<br/>Required when creating a VM. | Optional | 
| admin_username | Admin username used to access the VM after it is created.<br/>Required when creating a VM. | Optional | 
| admin_password | Password for the admin username.<br/>Not required if the `os_type=Linux` and SSH password authentication is disabled by setting `ssh_password_enabled=false`. | Optional | 
| ssh_password_enabled | Whether to enable or disable SSH passwords.<br/>When `os_type=Linux`, set to `false` to disable SSH password authentication and require use of SSH keys. Possible values are: Yes, No. Default is Yes. | Optional | 
| ssh_public_keys | For `os_type=Linux` provide a list of SSH keys.<br/>Accepts a list of dicts where each dictionary contains two keys, `path` and `key_data`.<br/>Set `path` to the default location of the authorized_keys files. For example, `path=/home/&lt;admin username&gt;/.ssh/authorized_keys`.<br/>Set `key_data` to the actual value of the public key. | Optional | 
| image | The image used to build the VM.<br/>For custom images, the name of the image. To narrow the search to a specific resource group, a dict with the keys `name` and `resource_group`.<br/>For Marketplace images, a dict with the keys `publisher`, `offer`, `sku`, and `version`.<br/>Set `version=latest` to get the most recent version of a given image. | Required | 
| availability_set | Name or ID of an existing availability set to add the VM to. The `availability_set` should be in the same resource group as VM. | Optional | 
| storage_account_name | Name of a storage account that supports creation of VHD blobs.<br/>If not specified for a new VM, a new storage account named &lt;vm name&gt;01 will be created using storage type `Standard_LRS`. | Optional | 
| storage_container_name | Name of the container to use within the storage account to store VHD blobs.<br/>If not specified, a default container will be created. Default is vhds. | Optional | 
| storage_blob_name | Name of the storage blob used to hold the OS disk image of the VM.<br/>Must end with '.vhd'.<br/>If not specified, defaults to the VM name + '.vhd'. | Optional | 
| managed_disk_type | Managed OS disk type.<br/>Create OS disk with managed disk if defined.<br/>If not defined, the OS disk will be created with virtual hard disk (VHD). Possible values are: Standard_LRS, StandardSSD_LRS, Premium_LRS. | Optional | 
| os_disk_name | OS disk name. | Optional | 
| os_disk_caching | Type of OS disk caching. Possible values are: ReadOnly, ReadWrite. Default is ReadOnly. | Optional | 
| os_disk_size_gb | Type of OS disk size in GB. | Optional | 
| os_type | Base type of operating system. Possible values are: Windows, Linux. Default is Linux. | Optional | 
| data_disks | Describes list of data disks.<br/>Use `azure_rm_mangeddisk` to manage the specific disk. | Optional | 
| public_ip_allocation_method | Allocation method for the public IP of the VM.<br/>Used only if a network interface is not specified.<br/>When set to `Dynamic`, the public IP address may change any time the VM is rebooted or power cycled.<br/>The `Disabled` choice was added in Ansible 2.6. Possible values are: Dynamic, Static, Disabled. Default is Static. | Optional | 
| open_ports | List of ports to open in the security group for the VM, when a security group and network interface are created with a VM.<br/>For Linux hosts, defaults to allowing inbound TCP connections to port 22.<br/>For Windows hosts, defaults to opening ports 3389 and 5986. | Optional | 
| network_interface_names | Network interface names to add to the VM.<br/>Can be a string of name or resource ID of the network interface.<br/>Can be a dict containing `resource_group` and `name` of the network interface.<br/>If a network interface name is not provided when the VM is created, a default network interface will be created.<br/>To create a new network interface, at least one Virtual Network with one Subnet must exist. | Optional | 
| virtual_network_resource_group | The resource group to use when creating a VM with another resource group's virtual network. | Optional | 
| virtual_network_name | The virtual network to use when creating a VM.<br/>If not specified, a new network interface will be created and assigned to the first virtual network found in the resource group.<br/>Use with `virtual_network_resource_group` to place the virtual network in another resource group. | Optional | 
| subnet_name | Subnet for the VM.<br/>Defaults to the first subnet found in the virtual network or the subnet of the `network_interface_name`, if provided.<br/>If the subnet is in another resource group, specify the resource group with `virtual_network_resource_group`. | Optional | 
| remove_on_absent | Associated resources to remove when removing a VM using `state=absent`.<br/>To remove all resources related to the VM being removed, including auto-created resources, set to `all`.<br/>To remove only resources that were automatically created while provisioning the VM being removed, set to `all_autocreated`.<br/>To remove only specific resources, set to `network_interfaces`, `virtual_storage` or `public_ips`.<br/>Any other input will be ignored. Default is ['all']. | Optional | 
| plan | Third-party billing plan for the VM. | Optional | 
| accept_terms | Accept terms for Marketplace images that require it.<br/>Only Azure service admin/account admin users can purchase images from the Marketplace.<br/>Only valid when a `plan` is specified. Possible values are: Yes, No. Default is No. | Optional | 
| zones | A list of Availability Zones for your VM. | Optional | 
| license_type | On-premise license for the image or disk.<br/>Only used for images that contain the Windows Server operating system.<br/>To remove all license type settings, set to the string `None`. Possible values are: Windows_Server, Windows_Client. | Optional | 
| vm_identity | Identity for the VM. Possible values are: SystemAssigned. | Optional | 
| winrm | List of Windows Remote Management configurations of the VM. | Optional | 
| boot_diagnostics | Manage boot diagnostics settings for a VM.<br/>Boot diagnostics includes a serial console and remote console screenshots. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachine.powerstate | string | Indicates if the state is \`running\`, \`stopped\`, \`deallocated\`, \`generalized\`. | 
| Azure.AzureRmVirtualmachine.deleted_vhd_uris | unknown | List of deleted Virtual Hard Disk URIs. | 
| Azure.AzureRmVirtualmachine.deleted_network_interfaces | unknown | List of deleted NICs. | 
| Azure.AzureRmVirtualmachine.deleted_public_ips | unknown | List of deleted public IP address names. | 
| Azure.AzureRmVirtualmachine.azure_vm | unknown | Facts about the current state of the object. Note that facts are not part of the registered output but available directly. | 


#### Command Example
```!azure-rm-virtualmachine resource_group="myResourceGroup" name="testvm10" state="present" started="Yes" allocated="No" admin_username="exampleadmin" admin_password="CHANGEME" ssh_password_enabled="Yes" image="{{ {'offer': 'debian-10', 'publisher': 'Debian', 'sku': '10','version': 'latest'} }}" vm_size=Standard_B2ms```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachine": [
            {
                "changed": true,
                "powerstate_change": null,
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * powerstate_change: None


### azure-rm-virtualmachine-info
***
Get virtual machine facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachine_info_module.html


#### Base Command

`azure-rm-virtualmachine-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of the resource group containing the virtual machines (required when filtering by vm name). | Optional | 
| name | Name of the virtual machine. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachineInfo.vms | unknown | List of virtual machines. | 


#### Command Example
```!azure-rm-virtualmachine-info resource_group="myResourceGroup"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachineInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "vms": [
                    {
                        "admin_username": "exampleadmin",
                        "boot_diagnostics": {
                            "enabled": false,
                            "storage_uri": false
                        },
                        "data_disks": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/simpleLinuxVM",
                        "image": {
                            "offer": "UbuntuServer",
                            "publisher": "Canonical",
                            "sku": "18.04-LTS",
                            "version": "latest"
                        },
                        "location": "australiasoutheast",
                        "name": "simpleLinuxVM",
                        "network_interface_names": [
                            "simpleLinuxVMNetInt"
                        ],
                        "os_disk_caching": "ReadWrite",
                        "os_type": "Linux",
                        "power_state": "running",
                        "resource_group": "myResourceGroup",
                        "state": "present",
                        "tags": null,
                        "vm_size": "Standard_B2s"
                    },
                    {
                        "admin_username": "exampleadmin",
                        "boot_diagnostics": {
                            "enabled": false,
                            "storage_uri": false
                        },
                        "data_disks": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10",
                        "image": {
                            "offer": "debian-10",
                            "publisher": "Debian",
                            "sku": "10",
                            "version": "0.20210329.591"
                        },
                        "location": "australiasoutheast",
                        "name": "testvm10",
                        "network_interface_names": [
                            "testvm1001"
                        ],
                        "os_disk_caching": "ReadOnly",
                        "os_type": "Linux",
                        "power_state": "running",
                        "resource_group": "myResourceGroup",
                        "state": "present",
                        "storage_account_name": "testvm103335",
                        "storage_blob_name": "testvm10.vhd",
                        "storage_container_name": "vhds",
                        "tags": {
                            "_own_nic_": "testvm1001",
                            "_own_nsg_": "testvm1001",
                            "_own_pip_": "testvm1001",
                            "_own_sa_": "testvm103335"
                        },
                        "vm_size": "Standard_B2ms"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Vms
>  * ## Exampleadmin
>    * admin_username: exampleadmin
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/simpleLinuxVM
>    * location: australiasoutheast
>    * name: simpleLinuxVM
>    * os_disk_caching: ReadWrite
>    * os_type: Linux
>    * power_state: running
>    * resource_group: myResourceGroup
>    * state: present
>    * tags: None
>    * vm_size: Standard_B2s
>    * ### Boot_Diagnostics
>      * enabled: False
>      * storage_uri: False
>    * ### Data_Disks
>    * ### Image
>      * offer: UbuntuServer
>      * publisher: Canonical
>      * sku: 18.04-LTS
>      * version: latest
>    * ### Network_Interface_Names
>      * 0: simpleLinuxVMNetInt
>  * ## Exampleadmin
>    * admin_username: exampleadmin
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10
>    * location: australiasoutheast
>    * name: testvm10
>    * os_disk_caching: ReadOnly
>    * os_type: Linux
>    * power_state: running
>    * resource_group: myResourceGroup
>    * state: present
>    * storage_account_name: testvm103335
>    * storage_blob_name: testvm10.vhd
>    * storage_container_name: vhds
>    * vm_size: Standard_B2ms
>    * ### Boot_Diagnostics
>      * enabled: False
>      * storage_uri: False
>    * ### Data_Disks
>    * ### Image
>      * offer: debian-10
>      * publisher: Debian
>      * sku: 10
>      * version: 0.20210329.591
>    * ### Network_Interface_Names
>      * 0: testvm1001
>    * ### Tags
>      * _own_nic_: testvm1001
>      * _own_nsg_: testvm1001
>      * _own_pip_: testvm1001
>      * _own_sa_: testvm103335


### azure-rm-virtualmachineextension
***
Managed Azure Virtual Machine extension
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachineextension_module.html


#### Base Command

`azure-rm-virtualmachineextension`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the vm extension exists or will be created. | Required | 
| name | Name of the vm extension. | Required | 
| state | State of the vm extension. Use `present` to create or update a vm extension and `absent` to delete a vm extension. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| virtual_machine_name | The name of the virtual machine where the extension should be create or updated. | Optional | 
| publisher | The name of the extension handler publisher. | Optional | 
| virtual_machine_extension_type | The type of the extension handler. | Optional | 
| type_handler_version | The type version of the extension handler. | Optional | 
| settings | Json formatted public settings for the extension. | Optional | 
| protected_settings | Json formatted protected settings for the extension. | Optional | 
| auto_upgrade_minor_version | Whether the extension handler should be automatically upgraded across minor versions. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachineextension.state | unknown | Current state of the vm extension. | 
| Azure.AzureRmVirtualmachineextension.changed | boolean | Whether or not the resource has changed. | 


#### Command Example
```!azure-rm-virtualmachineextension name="myvmextension" location="australiasoutheast" resource_group="myResourceGroup" virtual_machine_name="testvm10" publisher="Microsoft.Azure.Extensions" virtual_machine_extension_type="CustomScript" type_handler_version="2.0" settings="{\"commandToExecute\": \"hostname\"}" auto_upgrade_minor_version="True" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachineextension": [
            {
                "changed": true,
                "state": {
                    "auto_upgrade_minor_version": true,
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension",
                    "location": "australiasoutheast",
                    "name": "myvmextension",
                    "protected_settings": null,
                    "publisher": "Microsoft.Azure.Extensions",
                    "settings": {
                        "commandToExecute": "hostname"
                    },
                    "type_handler_version": "2.0",
                    "virtual_machine_extension_type": "CustomScript"
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * auto_upgrade_minor_version: True
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension
>    * location: australiasoutheast
>    * name: myvmextension
>    * protected_settings: None
>    * publisher: Microsoft.Azure.Extensions
>    * type_handler_version: 2.0
>    * virtual_machine_extension_type: CustomScript
>    * ### Settings
>      * commandToExecute: hostname


### azure-rm-virtualmachineextension-info
***
Get Azure Virtual Machine Extension facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachineextension_info_module.html


#### Base Command

`azure-rm-virtualmachineextension-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| virtual_machine_name | The name of the virtual machine containing the extension. | Required | 
| name | The name of the virtual machine extension. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachineextensionInfo.extensions | unknown | A list of dictionaries containing facts for Virtual Machine Extension. | 


#### Command Example
```!azure-rm-virtualmachineextension-info resource_group="myResourceGroup" virtual_machine_name="testvm10" name="myvmextension" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachineextensionInfo": [
            {
                "changed": false,
                "extensions": [
                    {
                        "auto_upgrade_minor_version": true,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension",
                        "location": "australiasoutheast",
                        "name": "myvmextension",
                        "provisioning_state": "Succeeded",
                        "publisher": "Microsoft.Azure.Extensions",
                        "resource_group": "myResourceGroup",
                        "settings": {
                            "commandToExecute": "hostname"
                        },
                        "tags": null,
                        "type": "CustomScript",
                        "virtual_machine_name": "testvm10"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Extensions
>  * ## Myvmextension
>    * auto_upgrade_minor_version: True
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/testvm10/extensions/myvmextension
>    * location: australiasoutheast
>    * name: myvmextension
>    * provisioning_state: Succeeded
>    * publisher: Microsoft.Azure.Extensions
>    * resource_group: myResourceGroup
>    * tags: None
>    * type: CustomScript
>    * virtual_machine_name: testvm10
>    * ### Settings
>      * commandToExecute: hostname


### azure-rm-virtualmachineimage-info
***
Get virtual machine image facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachineimage_info_module.html


#### Base Command

`azure-rm-virtualmachineimage-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | Azure location value, for example `westus`, `eastus`, `eastus2`, `northcentralus`, etc.<br/>Supplying only a location value will yield a list of available publishers for the location. | Required | 
| publisher | Name of an image publisher. List image offerings associated with a particular publisher. | Optional | 
| offer | Name of an image offering. Combine with SKU to see a list of available image versions. | Optional | 
| sku | Image offering SKU. Combine with offer to see a list of available versions. | Optional | 
| version | Specific version number of an image. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachineimageInfo.azure_vmimages | unknown | List of image dicts. | 


#### Command Example
```!azure-rm-virtualmachineimage-info location="australiasoutheast" publisher="Debian" offer="debian-10" sku="10" version=0.20190705.396```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachineimageInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "vmimages": [
                    {
                        "id": "/Subscriptions/11111111-1111-1111-1111-111111111111/Providers/Microsoft.Compute/Locations/australiasoutheast/Publishers/Debian/ArtifactTypes/VMImage/Offers/debian-10/Skus/10/Versions/0.20190705.396",
                        "location": "australiasoutheast",
                        "name": "0.20190705.396",
                        "properties": {
                            "automaticOSUpgradeProperties": {
                                "automaticOSUpgradeSupported": false
                            },
                            "dataDiskImages": [],
                            "hyperVGeneration": "V1",
                            "osDiskImage": {
                                "operatingSystem": "Linux"
                            }
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Vmimages
>  * ## 0.20190705.396
>    * id: /Subscriptions/11111111-1111-1111-1111-111111111111/Providers/Microsoft.Compute/Locations/australiasoutheast/Publishers/Debian/ArtifactTypes/VMImage/Offers/debian-10/Skus/10/Versions/0.20190705.396
>    * location: australiasoutheast
>    * name: 0.20190705.396
>    * ### Properties
>      * hyperVGeneration: V1
>      * #### Automaticosupgradeproperties
>        * automaticOSUpgradeSupported: False
>      * #### Datadiskimages
>      * #### Osdiskimage
>        * operatingSystem: Linux


### azure-rm-virtualmachinescaleset
***
Manage Azure virtual machine scale sets
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescaleset_module.html


#### Base Command

`azure-rm-virtualmachinescaleset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of the resource group containing the virtual machine scale set. | Required | 
| name | Name of the virtual machine. | Required | 
| state | Assert the state of the virtual machine scale set.<br/>State `present` will check that the machine exists with the requested configuration. If the configuration of the existing machine does not match, the machine will be updated.<br/>State `absent` will remove the virtual machine scale set. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| short_hostname | Short host name. | Optional | 
| vm_size | A valid Azure VM size value. For example, `Standard_D4`.<br/>The list of choices varies depending on the subscription and location. Check your subscription for available choices. | Optional | 
| capacity | Capacity of VMSS. Default is 1. | Optional | 
| tier | SKU Tier. Possible values are: Basic, Standard. | Optional | 
| upgrade_policy | Upgrade policy.<br/>Required when creating the Azure virtual machine scale sets. Possible values are: Manual, Automatic. | Optional | 
| admin_username | Admin username used to access the host after it is created. Required when creating a VM. | Optional | 
| admin_password | Password for the admin username.<br/>Not required if the os_type is Linux and SSH password authentication is disabled by setting `ssh_password_enabled=false`. | Optional | 
| ssh_password_enabled | When the os_type is Linux, setting `ssh_password_enabled=false` will disable SSH password authentication and require use of SSH keys. Possible values are: Yes, No. Default is Yes. | Optional | 
| ssh_public_keys | For `os_type=Linux` provide a list of SSH keys.<br/>Each item in the list should be a dictionary where the dictionary contains two keys, `path` and `key_data`.<br/>Set the `path` to the default location of the authorized_keys files.<br/>On an Enterprise Linux host, for example, the `path=/home/&lt;admin username&gt;/.ssh/authorized_keys`. Set `key_data` to the actual value of the public key. | Optional | 
| image | Specifies the image used to build the VM.<br/>If a string, the image is sourced from a custom image based on the name.<br/>If a dict with the keys `publisher`, `offer`, `sku`, and `version`, the image is sourced from a Marketplace image. Note that set `version=latest` to get the most recent version of a given image.<br/>If a dict with the keys `name` and `resource_group`, the image is sourced from a custom image based on the `name` and `resource_group` set. Note that the key `resource_group` is optional and if omitted, all images in the subscription will be searched for by `name`.<br/>Custom image support was added in Ansible 2.5. | Required | 
| os_disk_caching | Type of OS disk caching. Possible values are: ReadOnly, ReadWrite. Default is ReadOnly. | Optional | 
| os_type | Base type of operating system. Possible values are: Windows, Linux. Default is Linux. | Optional | 
| managed_disk_type | Managed disk type. Possible values are: Standard_LRS, Premium_LRS. | Optional | 
| data_disks | Describes list of data disks. | Optional | 
| virtual_network_resource_group | When creating a virtual machine, if a specific virtual network from another resource group should be used.<br/>Use this parameter to specify the resource group to use. | Optional | 
| virtual_network_name | Virtual Network name. | Optional | 
| subnet_name | Subnet name. | Optional | 
| load_balancer | Load balancer name. | Optional | 
| application_gateway | Application gateway name. | Optional | 
| remove_on_absent | When removing a VM using `state=absent`, also remove associated resources.<br/>It can be `all` or a list with any of the following ['network_interfaces', 'virtual_storage', 'public_ips'].<br/>Any other input will be ignored. Default is ['all']. | Optional | 
| enable_accelerated_networking | Indicates whether user wants to allow accelerated networking for virtual machines in scaleset being created. | Optional | 
| security_group | Existing security group with which to associate the subnet.<br/>It can be the security group name which is in the same resource group.<br/>It can be the resource ID.<br/>It can be a dict which contains `name` and `resource_group` of the security group. | Optional | 
| overprovision | Specifies whether the Virtual Machine Scale Set should be overprovisioned. Possible values are: Yes, No. Default is Yes. | Optional | 
| single_placement_group | When true this limits the scale set to a single placement group, of max size 100 virtual machines. Possible values are: Yes, No. Default is Yes. | Optional | 
| zones | A list of Availability Zones for your virtual machine scale set. | Optional | 
| custom_data | Data which is made available to the virtual machine and used by e.g., `cloud-init`.<br/>Many images in the marketplace are not cloud-init ready. Thus, data sent to `custom_data` would be ignored.<br/>If the image you are attempting to use is not listed in `https://docs.microsoft.com/en-us/azure/virtual-machines/linux/using-cloud-init#cloud-init-overview`, follow these steps `https://docs.microsoft.com/en-us/azure/virtual-machines/linux/cloudinit-prepare-custom-image`. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescaleset.azure_vmss | unknown | Facts about the current state of the object.
Note that facts are not part of the registered output but available directly. | 


#### Command Example
```!azure-rm-virtualmachinescaleset resource_group="myResourceGroup" name="testvmss" vm_size="Standard_DS1_v2" capacity="2" virtual_network_name="vnet" upgrade_policy="Manual" subnet_name="subnet" admin_username="adminUser" ssh_password_enabled=Yes admin_password="CHANGEME" managed_disk_type="Standard_LRS" image="{{ {'offer': 'debian-10', 'publisher': 'Debian', 'sku': '10','version': 'latest'} }}"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescaleset": [
            {
                "changed": true,
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True


### azure-rm-virtualmachinescaleset-info
***
Get Virtual Machine Scale Set facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescaleset_info_module.html


#### Base Command

`azure-rm-virtualmachinescaleset-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific virtual machine scale set. | Optional | 
| resource_group | The resource group to search for the desired virtual machine scale set. | Optional | 
| tags | List of tags to be matched. | Optional | 
| format | Format of the data returned.<br/>If `raw` is selected information will be returned in raw format from Azure Python SDK.<br/>If `curated` is selected the structure will be identical to input parameters of `azure_rm_virtualmachinescaleset` module.<br/>In Ansible 2.5 and lower facts are always returned in raw format.<br/>Please note that this option will be deprecated in 2.10 when curated format will become the only supported format. Possible values are: curated, raw. Default is raw. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescalesetInfo.vmss | unknown | List of virtual machine scale sets. | 


#### Command Example
```!azure-rm-virtualmachinescaleset-info resource_group="myResourceGroup" name="testvmss" format="curated"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescalesetInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "vmss": [
                    {
                        "admin_password": null,
                        "admin_username": "adminUser",
                        "capacity": 2,
                        "data_disks": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss",
                        "image": {
                            "offer": "debian-10",
                            "publisher": "Debian",
                            "sku": "10",
                            "version": "0.20210329.591"
                        },
                        "load_balancer": null,
                        "location": "australiasoutheast",
                        "managed_disk_type": "Standard_LRS",
                        "name": "testvmss",
                        "os_disk_caching": "ReadOnly",
                        "os_type": "Linux",
                        "overprovision": true,
                        "resource_group": "myResourceGroup",
                        "ssh_password_enabled": true,
                        "state": "present",
                        "subnet_name": "Subnet",
                        "tags": null,
                        "tier": "Standard",
                        "upgrade_policy": "Manual",
                        "virtual_network_name": null,
                        "vm_size": "Standard_DS1_v2"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Vmss
>  * ## Adminuser
>    * admin_password: None
>    * admin_username: adminUser
>    * capacity: 2
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss
>    * load_balancer: None
>    * location: australiasoutheast
>    * managed_disk_type: Standard_LRS
>    * name: testvmss
>    * os_disk_caching: ReadOnly
>    * os_type: Linux
>    * overprovision: True
>    * resource_group: myResourceGroup
>    * ssh_password_enabled: True
>    * state: present
>    * subnet_name: Subnet
>    * tags: None
>    * tier: Standard
>    * upgrade_policy: Manual
>    * virtual_network_name: None
>    * vm_size: Standard_DS1_v2
>    * ### Data_Disks
>    * ### Image
>      * offer: debian-10
>      * publisher: Debian
>      * sku: 10
>      * version: 0.20210329.591


### azure-rm-virtualmachinescalesetextension
***
Manage Azure Virtual Machine Scale Set (VMSS) extensions
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescalesetextension_module.html


#### Base Command

`azure-rm-virtualmachinescalesetextension`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the VMSS extension exists or will be created. | Required | 
| vmss_name | The name of the virtual machine where the extension should be create or updated. | Required | 
| name | Name of the VMSS extension. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| publisher | The name of the extension handler publisher. | Optional | 
| type | The type of the extension handler. | Optional | 
| type_handler_version | The type version of the extension handler. | Optional | 
| settings | A dictionary containing extension settings.<br/>Settings depend on extension type.<br/>Refer to `https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/overview` for more information. | Optional | 
| protected_settings | A dictionary containing protected extension settings.<br/>Settings depend on extension type.<br/>Refer to `https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/overview` for more information. | Optional | 
| auto_upgrade_minor_version | Whether the extension handler should be automatically upgraded across minor versions. | Optional | 
| state | Assert the state of the extension.<br/>Use `present` to create or update an extension and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescalesetextension.id | string | VMSS extension resource ID. | 


#### Command Example
```!azure-rm-virtualmachinescalesetextension name="myvmssextension" location="australiasoutheast" resource_group="myResourceGroup" vmss_name="testvmss" publisher="Microsoft.Azure.Extensions" type="CustomScript" type_handler_version="2.0" settings="{\"commandToExecute\": \"hostname\"}" auto_upgrade_minor_version="True" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescalesetextension": [
            {
                "changed": true,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/extensions/myvmssextension",
                "state": {},
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/extensions/myvmssextension
>  * ## State


### azure-rm-virtualmachinescalesetextension-info
***
Get Azure Virtual Machine Scale Set Extension facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescalesetextension_info_module.html


#### Base Command

`azure-rm-virtualmachinescalesetextension-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| vmss_name | The name of VMSS containing the extension. | Required | 
| name | The name of the virtual machine extension. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescalesetextensionInfo.extensions | unknown | A list of dictionaries containing facts for Virtual Machine Extension. | 


#### Command Example
```!azure-rm-virtualmachinescalesetextension-info resource_group="myResourceGroup" vmss_name="testvmss" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescalesetextensionInfo": [
            {
                "changed": false,
                "extensions": [
                    {
                        "auto_upgrade_minor_version": true,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/extensions/myvmssextension",
                        "name": "myvmssextension",
                        "provisioning_state": "Creating",
                        "publisher": "Microsoft.Azure.Extensions",
                        "resource_group": "myResourceGroup",
                        "settings": {
                            "commandToExecute": "hostname"
                        },
                        "type": "CustomScript",
                        "vmss_name": "testvmss"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Extensions
>  * ## Myvmssextension
>    * auto_upgrade_minor_version: True
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/extensions/myvmssextension
>    * name: myvmssextension
>    * provisioning_state: Creating
>    * publisher: Microsoft.Azure.Extensions
>    * resource_group: myResourceGroup
>    * type: CustomScript
>    * vmss_name: testvmss
>    * ### Settings
>      * commandToExecute: hostname


### azure-rm-virtualmachinescalesetinstance
***
Get Azure Virtual Machine Scale Set Instance facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescalesetinstance_module.html


#### Base Command

`azure-rm-virtualmachinescalesetinstance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| vmss_name | The name of the VM scale set. | Required | 
| instance_id | The instance ID of the virtual machine. | Required | 
| latest_model | Set to `yes` to upgrade to the latest model. | Optional | 
| power_state | Use this option to change power state of the instance. Possible values are: running, stopped, deallocated. | Required | 
| state | State of the VMSS instance. Use `present` to update an instance and `absent` to delete an instance. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescalesetinstance.instances | unknown | A list of instances. | 


#### Command Example
```!azure-rm-virtualmachinescalesetinstance resource_group="myResourceGroup" vmss_name="testvmss" instance_id="2" latest_model="True" power_state=running```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescalesetinstance": [
            {
                "changed": false,
                "instances": [],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Instances


### azure-rm-virtualmachinescalesetinstance-info
***
Get Azure Virtual Machine Scale Set Instance facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualmachinescalesetinstance_info_module.html


#### Base Command

`azure-rm-virtualmachinescalesetinstance-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| vmss_name | The name of the VM scale set. | Required | 
| instance_id | The instance ID of the virtual machine. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualmachinescalesetinstanceInfo.instances | unknown | A list of dictionaries containing facts for Virtual Machine Scale Set VM. | 


#### Command Example
```!azure-rm-virtualmachinescalesetinstance-info resource_group="myResourceGroup" vmss_name="testvmss"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualmachinescalesetinstanceInfo": [
            {
                "changed": false,
                "instances": [
                    {
                        "computer_name": "testvmss000001",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/virtualMachines/1",
                        "image_reference": {
                            "offer": "debian-10",
                            "publisher": "Debian",
                            "sku": "10",
                            "version": "0.20210329.591"
                        },
                        "instance_id": "1",
                        "latest_model": false,
                        "name": "testvmss_1",
                        "power_state": "running",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "tags": null,
                        "vm_id": "a5d531ad-8a0d-4a06-a5ed-e19ab6536177"
                    },
                    {
                        "computer_name": "testvmss000003",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/virtualMachines/3",
                        "image_reference": {
                            "offer": "debian-10",
                            "publisher": "Debian",
                            "sku": "10",
                            "version": "0.20210329.591"
                        },
                        "instance_id": "3",
                        "latest_model": false,
                        "name": "testvmss_3",
                        "power_state": "running",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "tags": null,
                        "vm_id": "cf99d90e-2358-4373-adc3-f2d5d181e9a1"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Instances
>  * ## Testvmss000001
>    * computer_name: testvmss000001
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/virtualMachines/1
>    * instance_id: 1
>    * latest_model: False
>    * name: testvmss_1
>    * power_state: running
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * tags: None
>    * vm_id: a5d531ad-8a0d-4a06-a5ed-e19ab6536177
>    * ### Image_Reference
>      * offer: debian-10
>      * publisher: Debian
>      * sku: 10
>      * version: 0.20210329.591
>  * ## Testvmss000003
>    * computer_name: testvmss000003
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachineScaleSets/testvmss/virtualMachines/3
>    * instance_id: 3
>    * latest_model: False
>    * name: testvmss_3
>    * power_state: running
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * tags: None
>    * vm_id: cf99d90e-2358-4373-adc3-f2d5d181e9a1
>    * ### Image_Reference
>      * offer: debian-10
>      * publisher: Debian
>      * sku: 10
>      * version: 0.20210329.591


### azure-rm-webapp

***
Manage Web App instances
 Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_webapp_module.html

#### Base Command

`azure-rm-webapp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of the resource group to which the resource belongs. | Required | 
| name | Unique name of the app to create or update. To create or update a deployment slot, use the {slot} parameter. | Required | 
| location | Resource location. If not set, location from the resource group will be used as default. | Optional | 
| plan | App service plan. Required for creation. Can be name of existing app service plan in same resource group as web app. Can be the resource ID of an existing app service plan. For example /subscriptions/&lt;subs_id&gt;/resourceGroups/&lt;resource_group&gt;/providers/Microsoft.Web/serverFarms/&lt;plan_name&gt;. Can be a dict containing five parameters, defined below. `name`, name of app service plan. `resource_group`, resource group of the app service plan. `sku`, SKU of app service plan, allowed values listed on `https://azure.microsoft.com/en-us/pricing/details/app-service/linux/`. `is_linux`, whether or not the app service plan is Linux. defaults to `False`. `number_of_workers`, number of workers for app service plan. | Optional | 
| frameworks | Set of run time framework settings. Each setting is a dictionary. See `https://docs.microsoft.com/en-us/azure/app-service/app-service-web-overview` for more info. | Optional | 
| container_settings | Web app container settings. | Optional | 
| scm_type | Repository type of deployment source, for example `LocalGit`, `GitHub`. List of supported values maintained at `https://docs.microsoft.com/en-us/rest/api/appservice/webapps/createorupdate#scmtype`. | Optional | 
| deployment_source | Deployment source for git. | Optional | 
| startup_file | The web's startup file. Used only for Linux web apps. | Optional | 
| client_affinity_enabled | Whether or not to send session affinity cookies, which route client requests in the same session to the same instance. Possible values are: Yes, No. Default is Yes. | Optional | 
| https_only | Configures web site to accept only https requests. | Optional | 
| dns_registration | Whether or not the web app hostname is registered with DNS on creation. Set to `false` to register. | Optional | 
| skip_custom_domain_verification | Whether or not to skip verification of custom (non *.azurewebsites.net) domains associated with web app. Set to `true` to skip. | Optional | 
| ttl_in_seconds | Time to live in seconds for web app default domain name. | Optional | 
| app_settings | Configure web app application settings. Suboptions are in key value pair format. | Optional | 
| purge_app_settings | Purge any existing application settings. Replace web app application settings with app_settings. | Optional | 
| app_state | Start/Stop/Restart the web app. Possible values are: started, stopped, restarted. Default is started. | Optional | 
| state | State of the Web App. Use `present` to create or update a Web App and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmWebapp.azure_webapp | string | ID of current web app. | 

#### Command example
```!azure-rm-webapp name=test resource_group=resource_group plan="{{{'name': 'testing', 'resource_group': 'resource_group', 'sku': 'mySkuName', 'is_linux': 'true', 'number_of_workers': '1'}}}"```
#### Context Example
```json
{
    "Azure": {
        "AzureRmWebapp": [
            {
                "changed": true,
                "id": "ID",
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * id: ID


### azure-rm-webapp-info
***
Get Azure web app facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_webapp_info_module.html


#### Base Command

`azure-rm-webapp-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific web app. | Optional | 
| resource_group | Limit results by resource group. | Optional | 
| return_publish_profile | Indicate whether to return publishing profile of the web app. Possible values are: Yes, No. Default is No. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmWebappInfo.webapps | unknown | List of web apps. | 


#### Command Example
```!azure-rm-webapp-info resource_group="myResourceGroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmWebappInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "webapps": []
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Webapps


### azure-rm-webappslot
***
Manage Azure Web App slot
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_webappslot_module.html


#### Base Command

`azure-rm-webappslot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of the resource group to which the resource belongs. | Required | 
| name | Unique name of the deployment slot to create or update. | Required | 
| webapp_name | Web app name which this deployment slot belongs to. | Required | 
| location | Resource location. If not set, location from the resource group will be used as default. | Optional | 
| configuration_source | Source slot to clone configurations from when creating slot. Use webapp's name to refer to the production slot. | Optional | 
| auto_swap_slot_name | Used to configure target slot name to auto swap, or disable auto swap.<br/>Set it target slot name to auto swap.<br/>Set it to False to disable auto slot swap. | Optional | 
| swap | Swap deployment slots of a web app. | Optional | 
| frameworks | Set of run time framework settings. Each setting is a dictionary.<br/>See `https://docs.microsoft.com/en-us/azure/app-service/app-service-web-overview` for more info. | Optional | 
| container_settings | Web app slot container settings. | Optional | 
| startup_file | The slot startup file.<br/>This only applies for Linux web app slot. | Optional | 
| app_settings | Configure web app slot application settings. Suboptions are in key value pair format. | Optional | 
| purge_app_settings | Purge any existing application settings. Replace slot application settings with app_settings. | Optional | 
| deployment_source | Deployment source for git. | Optional | 
| app_state | Start/Stop/Restart the slot. Possible values are: started, stopped, restarted. Default is started. | Optional | 
| state | State of the Web App deployment slot.<br/>Use `present` to create or update a  slot and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object.<br/>Metadata tags on the object will be updated with any provided values.<br/>To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags.<br/>When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmWebappslot.id | string | ID of current slot. | 


### azure-rm-azurefirewall
***
Manage Azure Firewall instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_azurefirewall_module.html


#### Base Command

`azure-rm-azurefirewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | The name of the Azure Firewall. | Required | 
| location | Resource location. | Optional | 
| application_rule_collections | Collection of application rule collections used by Azure Firewall. | Optional | 
| nat_rule_collections | Collection of NAT rule collections used by Azure Firewall. | Optional | 
| network_rule_collections | Collection of network rule collections used by Azure Firewall. | Optional | 
| ip_configurations | IP configuration of the Azure Firewall resource. | Optional | 
| state | Assert the state of the AzureFirewall. Use `present` to create or update an AzureFirewall and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAzurefirewall.id | string | Resource ID. | 


#### Command Example
```!azure-rm-azurefirewall resource_group="myResourceGroup" name="myAzureFirewall" tags="{{ {'key1': 'value1'} }}" ip_configurations="{{ [{'subnet': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet', 'public_ip_address': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress', 'name': 'azureFirewallIpConfiguration'}] }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAzurefirewall": [
            {
                "changed": false,
                "compare": [],
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall",
                "modifiers": {
                    "/location": {
                        "comparison": "location",
                        "updatable": false
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall
>  * ## Compare
>  * ## Modifiers
>    * ### /Location
>      * comparison: location
>      * updatable: False


### azure-rm-azurefirewall-info
***
Get AzureFirewall info.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_azurefirewall_info_module.html


#### Base Command

`azure-rm-azurefirewall-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Optional | 
| name | Resource name. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmAzurefirewallInfo.firewalls | unknown | A list of dict results where the key is the name of the AzureFirewall and the values are the facts for that AzureFirewall. | 


#### Command Example
```!azure-rm-azurefirewall-info ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmAzurefirewallInfo": [
            {
                "changed": false,
                "firewalls": [
                    {
                        "etag": "W/\"3c426480-93a2-4db2-93d9-d3f0cbfd45ba\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall",
                        "ip_configurations": [
                            {
                                "etag": "W/\"3c426480-93a2-4db2-93d9-d3f0cbfd45ba\"",
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall/azureFirewallIpConfigurations/azureFirewallIpConfiguration",
                                "name": "azureFirewallIpConfiguration",
                                "properties": {
                                    "privateIPAddress": "1.1.1.2",
                                    "privateIPAllocationMethod": "Dynamic",
                                    "provisioningState": "Succeeded",
                                    "publicIPAddress": {
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress"
                                    },
                                    "subnet": {
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet"
                                    }
                                },
                                "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                            }
                        ],
                        "location": "australiasoutheast",
                        "name": "myAzureFirewall",
                        "nat_rule_collections": [],
                        "network_rule_collections": [],
                        "provisioning_state": "Succeeded",
                        "tags": {
                            "key1": "value1"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Firewalls
>  * ## Myazurefirewall
>    * etag: W/"3c426480-93a2-4db2-93d9-d3f0cbfd45ba"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall
>    * location: australiasoutheast
>    * name: myAzureFirewall
>    * provisioning_state: Succeeded
>    * ### Ip_Configurations
>    * ### Azurefirewallipconfiguration
>      * etag: W/"3c426480-93a2-4db2-93d9-d3f0cbfd45ba"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall/azureFirewallIpConfigurations/azureFirewallIpConfiguration
>      * name: azureFirewallIpConfiguration
>      * type: Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations
>      * #### Properties
>        * privateIPAddress: 1.1.1.2
>        * privateIPAllocationMethod: Dynamic
>        * provisioningState: Succeeded
>        * ##### Publicipaddress
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress
>        * ##### Subnet
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet
>    * ### Nat_Rule_Collections
>    * ### Network_Rule_Collections
>    * ### Tags
>      * key1: value1


### azure-rm-virtualnetwork
***
Manage Azure virtual networks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetwork_module.html


#### Base Command

`azure-rm-virtualnetwork`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| address_prefixes_cidr | List of IPv4 address ranges where each is formatted using CIDR notation. Required when creating a new virtual network or using `purge_address_prefixes`. | Optional | 
| dns_servers | Custom list of DNS servers. Maximum length of two. The first server in the list will be treated as the Primary server. This is an explicit list. Existing DNS servers will be replaced with the specified list. Use the `purge_dns_servers` option to remove all custom DNS servers and revert to default Azure servers. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| name | Name of the virtual network. | Required | 
| purge_address_prefixes | Use with `state=present` to remove any existing `address_prefixes`. Default is no. | Optional | 
| purge_dns_servers | Use with `state=present` to remove existing DNS servers, reverting to default Azure servers. Mutually exclusive with DNS servers. | Optional | 
| state | State of the virtual network. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualnetwork.state | unknown | Current state of the virtual network. | 


#### Command Example
```!azure-rm-virtualnetwork resource_group="myResourceGroup" name="myVirtualNetwork" address_prefixes_cidr="{{ ['10.1.0.0/16', '1.1.1.3/16'] }}" dns_servers="{{ ['127.0.0.1', '127.0.0.2'] }}" tags="{{ {'testing': 'testing', 'delete': 'on-exit'} }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualnetwork": [
            {
                "changed": false,
                "check_mode": false,
                "state": {
                    "address_prefixes": [
                        "10.0.0.0/16",
                        "10.1.0.0/16",
                        "1.1.1.3/16"
                    ],
                    "dns_servers": [
                        "127.0.0.1",
                        "127.0.0.2"
                    ],
                    "etag": "W/\"fb7ef035-16d2-4915-80b7-956c42d7a2fb\"",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork",
                    "location": "australiasoutheast",
                    "name": "myVirtualNetwork",
                    "provisioning_state": "Succeeded",
                    "tags": {
                        "delete": "on-exit",
                        "testing": "testing"
                    },
                    "type": "Microsoft.Network/virtualNetworks"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * check_mode: False
>  * ## State
>    * etag: W/"fb7ef035-16d2-4915-80b7-956c42d7a2fb"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork
>    * location: australiasoutheast
>    * name: myVirtualNetwork
>    * provisioning_state: Succeeded
>    * type: Microsoft.Network/virtualNetworks
>    * ### Address_Prefixes
>      * 0: 10.0.0.0/16
>      * 1: 10.1.0.0/16
>      * 2: 1.1.1.3/16
>    * ### Dns_Servers
>      * 0: 127.0.0.1
>      * 1: 127.0.0.2
>    * ### Tags
>      * delete: on-exit
>      * testing: testing


### azure-rm-virtualnetwork-info
***
Get virtual network facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetwork_info_module.html


#### Base Command

`azure-rm-virtualnetwork-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific security group. | Optional | 
| resource_group | Limit results by resource group. Required when filtering by name. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualnetworkInfo.azure_virtualnetworks | unknown | List of virtual network dicts. | 
| Azure.AzureRmVirtualnetworkInfo.virtualnetworks | unknown | List of virtual network dicts with same format as \`azure_rm_virtualnetwork\` module parameters. | 


#### Command Example
```!azure-rm-virtualnetwork-info resource_group="myResourceGroup" name="myVirtualNetwork" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualnetworkInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "virtualnetworks": [
                    {
                        "address_prefixes": [
                            "10.0.0.0/16",
                            "10.1.0.0/16",
                            "1.1.1.3/16"
                        ],
                        "dns_servers": [
                            "127.0.0.1",
                            "127.0.0.2"
                        ],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork",
                        "location": "australiasoutheast",
                        "name": "myVirtualNetwork",
                        "provisioning_state": "Succeeded",
                        "subnets": [
                            {
                                "address_prefix": "10.0.0.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/default",
                                "name": "default",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            },
                            {
                                "address_prefix": "10.1.0.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                                "name": "mySubnet",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            }
                        ],
                        "tags": {
                            "delete": "on-exit",
                            "testing": "testing"
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Virtualnetworks
>  * ## Myvirtualnetwork
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork
>    * location: australiasoutheast
>    * name: myVirtualNetwork
>    * provisioning_state: Succeeded
>    * ### Address_Prefixes
>      * 0: 10.0.0.0/16
>      * 1: 10.1.0.0/16
>      * 2: 1.1.1.3/16
>    * ### Dns_Servers
>      * 0: 127.0.0.1
>      * 1: 127.0.0.2
>    * ### Subnets
>    * ### Default
>      * address_prefix: 10.0.0.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/default
>      * name: default
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Mysubnet
>      * address_prefix: 10.1.0.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>      * name: mySubnet
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Tags
>      * delete: on-exit
>      * testing: testing


### azure-rm-virtualnetworkgateway
***
Manage Azure virtual network gateways
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkgateway_module.html


#### Base Command

`azure-rm-virtualnetworkgateway`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where VPN Gateway exists or will be created. | Required | 
| name | Name of VPN Gateway. | Required | 
| state | State of the VPN Gateway. Use `present` to create or update VPN gateway and `absent` to delete VPN gateway. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| virtual_network | An existing virtual network with which the VPN Gateway will be associated. Required when creating a VPN Gateway. Can be the name of the virtual network. Must be in the same resource group as VPN gateway when specified by name. Can be the resource ID of the virtual network. Can be a dict which contains `name` and `resource_group` of the virtual network. | Required | 
| ip_configurations | List of IP configurations. | Optional | 
| gateway_type | The type of this virtual network gateway. Possible values are: vpn, express_route. Default is vpn. | Optional | 
| vpn_type | The type of this virtual private network. Possible values are: route_based, policy_based. Default is route_based. | Optional | 
| enable_bgp | Whether BGP is enabled for this virtual network gateway or not. Possible values are: Yes, No. Default is No. | Optional | 
| sku | The reference of the VirtualNetworkGatewaySku resource which represents the SKU selected for Virtual network gateway. Possible values are: VpnGw1, VpnGw2, VpnGw3. Default is VpnGw1. | Optional | 
| bgp_settings | Virtual network gateway's BGP speaker settings. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualnetworkgateway.id | string | Virtual Network Gateway resource ID. | 


#### Command Example
```!azure-rm-virtualnetworkgateway resource_group="myResourceGroup" name="myVirtualNetworkGateway" ip_configurations="{{ [{'name': 'testipconfig', 'private_ip_allocation_method': 'Dynamic', 'public_ip_address_name': 'testipaddr'}] }}" virtual_network="myVirtualNetwork" tags="{{ {'common': 'xyz'} }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualnetworkgateway": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworkGateways/myVirtualNetworkGateway",
                "state": {},
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworkGateways/myVirtualNetworkGateway
>  * ## State


### azure-rm-virtualnetworkpeering
***
Manage Azure Virtual Network Peering
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkpeering_module.html


#### Base Command

`azure-rm-virtualnetworkpeering`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the vnet exists. | Required | 
| name | Name of the virtual network peering. | Required | 
| virtual_network | Name or resource ID of the virtual network to be peered. | Required | 
| remote_virtual_network | Remote virtual network to be peered. It can be name of remote virtual network in same resource group. It can be remote virtual network resource ID. It can be a dict which contains `name` and `resource_group` of remote virtual network. Required when creating. | Optional | 
| allow_virtual_network_access | Allows VMs in the remote VNet to access all VMs in the local VNet. Possible values are: Yes, No. Default is No. | Optional | 
| allow_forwarded_traffic | Allows forwarded traffic from the VMs in the remote VNet. Possible values are: Yes, No. Default is No. | Optional | 
| use_remote_gateways | If remote gateways can be used on this virtual network. Possible values are: Yes, No. Default is No. | Optional | 
| allow_gateway_transit | Allows VNet to use the remote VNet's gateway. Remote VNet gateway must have --allow-gateway-transit enabled for remote peering. Only 1 peering can have this flag enabled. Cannot be set if the VNet already has a gateway. Possible values are: Yes, No. Default is No. | Optional | 
| state | State of the virtual network peering. Use `present` to create or update a peering and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualnetworkpeering.id | string | ID of the Azure virtual network peering. | 


#### Command Example
```!azure-rm-virtualnetworkpeering resource_group="myResourceGroup" virtual_network="myVirtualNetwork" name="myPeering" remote_virtual_network="{{ {'resource_group': 'mySecondResourceGroup', 'name': 'myRemoteVirtualNetwork'} }}" allow_virtual_network_access="False" allow_forwarded_traffic="True" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualnetworkpeering": [
            {
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False


### azure-rm-virtualnetworkpeering-info
***
Get facts of Azure Virtual Network Peering
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkpeering_info_module.html


#### Base Command

`azure-rm-virtualnetworkpeering-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the vnet exists. | Required | 
| virtual_network | Name or resource ID of a virtual network. | Required | 
| name | Name of the virtual network peering. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmVirtualnetworkpeeringInfo.vnetpeerings | unknown | A list of Virtual Network Peering facts. | 


#### Command Example
```!azure-rm-virtualnetworkpeering-info resource_group="myResourceGroup" virtual_network="myVirtualNetwork" name="myPeering" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmVirtualnetworkpeeringInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "vnetpeerings": [
                    {
                        "allow_forwarded_traffic": true,
                        "allow_gateway_transit": false,
                        "allow_virtual_network_access": false,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/virtualNetworkPeerings/myPeering",
                        "name": "myPeering",
                        "peering_state": "Initiated",
                        "provisioning_state": "Succeeded",
                        "remote_address_space": {
                            "address_prefixes": [
                                "1.1.1.3/16"
                            ]
                        },
                        "remote_virtual_network": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/mySecondResourceGroup/providers/Microsoft.Network/virtualNetworks/myRemoteVirtualNetwork",
                        "use_remote_gateways": false
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Vnetpeerings
>  * ## Mypeering
>    * allow_forwarded_traffic: True
>    * allow_gateway_transit: False
>    * allow_virtual_network_access: False
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/virtualNetworkPeerings/myPeering
>    * name: myPeering
>    * peering_state: Initiated
>    * provisioning_state: Succeeded
>    * remote_virtual_network: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/mySecondResourceGroup/providers/Microsoft.Network/virtualNetworks/myRemoteVirtualNetwork
>    * use_remote_gateways: False
>    * ### Remote_Address_Space
>      * #### Address_Prefixes
>        * 0: 1.1.1.3/16


### azure-rm-subnet
***
Manage Azure subnets
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_subnet_module.html


#### Base Command

`azure-rm-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the subnet. | Required | 
| address_prefix_cidr | CIDR defining the IPv4 address space of the subnet. Must be valid within the context of the virtual network. | Optional | 
| security_group | Existing security group with which to associate the subnet. It can be the security group name which is in the same resource group. Can be the resource ID of the security group. Can be a dict containing the `name` and `resource_group` of the security group. | Optional | 
| state | Assert the state of the subnet. Use `present` to create or update a subnet and use `absent` to delete a subnet. Possible values are: absent, present. Default is present. | Optional | 
| virtual_network_name | Name of an existing virtual network with which the subnet is or will be associated. | Required | 
| route_table | The reference of the RouteTable resource. Can be the name or resource ID of the route table. Can be a dict containing the `name` and `resource_group` of the route table. | Optional | 
| service_endpoints | An array of service endpoints. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmSubnet.state | unknown | Current state of the subnet. | 


#### Command Example
```!azure-rm-subnet resource_group="myResourceGroup" virtual_network_name="myVirtualNetwork" name="mySubnet" address_prefix_cidr="10.1.0.0/24" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmSubnet": [
            {
                "changed": false,
                "state": {
                    "address_prefix": "10.1.0.0/24",
                    "address_prefixes": null,
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                    "name": "mySubnet",
                    "network_security_group": {},
                    "private_endpoint_network_policies": "Enabled",
                    "private_link_service_network_policies": "Enabled",
                    "provisioning_state": "Succeeded",
                    "route_table": {}
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * address_prefix: 10.1.0.0/24
>    * address_prefixes: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>    * name: mySubnet
>    * private_endpoint_network_policies: Enabled
>    * private_link_service_network_policies: Enabled
>    * provisioning_state: Succeeded
>    * ### Network_Security_Group
>    * ### Route_Table


### azure-rm-subnet-info
***
Get Azure Subnet facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_subnet_info_module.html


#### Base Command

`azure-rm-subnet-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| virtual_network_name | The name of the virtual network. | Required | 
| name | The name of the subnet. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmSubnetInfo.subnets | unknown | A list of dictionaries containing facts for subnet. | 


#### Command Example
```!azure-rm-subnet-info resource_group="myResourceGroup" virtual_network_name="myVirtualNetwork" name="mySubnet" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmSubnetInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "subnets": [
                    {
                        "address_prefix_cidr": "10.1.0.0/24",
                        "address_prefixes_cidr": null,
                        "delegations": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                        "name": "mySubnet",
                        "private_endpoint_network_policies": "Enabled",
                        "private_link_service_network_policies": "Enabled",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "route_table": null,
                        "security_group": null,
                        "service_endpoints": null,
                        "virtual_network_name": "myVirtualNetwork"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Subnets
>  * ## Mysubnet
>    * address_prefix_cidr: 10.1.0.0/24
>    * address_prefixes_cidr: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>    * name: mySubnet
>    * private_endpoint_network_policies: Enabled
>    * private_link_service_network_policies: Enabled
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * route_table: None
>    * security_group: None
>    * service_endpoints: None
>    * virtual_network_name: myVirtualNetwork
>    * ### Delegations


### azure-rm-trafficmanagerendpoint
***
Manage Azure Traffic Manager endpoint
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerendpoint_module.html


#### Base Command

`azure-rm-trafficmanagerendpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the Traffic Manager endpoint exists or will be created. | Required | 
| name | The name of the endpoint. | Required | 
| profile_name | Name of Traffic Manager profile where this endpoints attaches to. | Required | 
| type | The type of the endpoint. Possible values are: azure_endpoints, external_endpoints, nested_endpoints. | Required | 
| target_resource_id | The Azure Resource URI of the of the endpoint. Not applicable to endpoints of `type=external_endpoints`. | Optional | 
| target | The fully-qualified DNS name of the endpoint. | Optional | 
| enabled | The status of the endpoint. Possible values are: Yes, No. Default is Yes. | Optional | 
| weight | The weight of this endpoint when traffic manager profile has routing_method of `weighted`. Possible values are from 1 to 1000. | Optional | 
| priority | The priority of this endpoint when traffic manager profile has routing_method of `priority`. Possible values are from 1 to 1000, lower values represent higher priority. This is an optional parameter. If specified, it must be specified on all endpoints. No two endpoints can share the same priority value. | Optional | 
| location | Specifies the location of the external or nested endpoints when using the 'Performance' traffic routing method. | Optional | 
| min_child_endpoints | The minimum number of endpoints that must be available in the child profile in order for the parent profile to be considered available. Only applicable to endpoint of `type=nested_endpoints`. | Optional | 
| geo_mapping | The list of countries/regions mapped to this endpoint when traffic manager profile has routing_method of `geographic`. | Optional | 
| state | Assert the state of the Traffic Manager endpoint. Use `present` to create or update a Traffic Manager endpoint and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmTrafficmanagerendpoint.id | string | The ID of the traffic manager endpoint. | 


#### Command Example
```!azure-rm-trafficmanagerendpoint resource_group="myResourceGroup" profile_name="tmtest" name="testendpoint1" type="external_endpoints" location="westus" priority="2" weight="1" target="1.2.3.4" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmTrafficmanagerendpoint": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1


### azure-rm-trafficmanagerendpoint-info
***
Get Azure Traffic Manager endpoint facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerendpoint_info_module.html


#### Base Command

`azure-rm-trafficmanagerendpoint-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific Traffic Manager endpoint. | Optional | 
| resource_group | The resource group to search for the desired Traffic Manager profile. | Required | 
| profile_name | Name of Traffic Manager Profile. | Required | 
| type | Type of endpoint. Possible values are: azure_endpoints, external_endpoints, nested_endpoints. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmTrafficmanagerendpointInfo.endpoints | unknown | List of Traffic Manager endpoints. | 


#### Command Example
```!azure-rm-trafficmanagerendpoint-info resource_group="myResourceGroup" profile_name="tmtest" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmTrafficmanagerendpointInfo": [
            {
                "changed": false,
                "endpoints": [
                    {
                        "enabled": true,
                        "geo_mapping": null,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                        "location": "West US",
                        "min_child_endpoints": null,
                        "monitor_status": "Degraded",
                        "name": "testendpoint1",
                        "priority": 2,
                        "resource_group": "myResourceGroup",
                        "target": "1.2.3.4",
                        "target_resource_id": null,
                        "type": "external_endpoints",
                        "weight": 1
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Endpoints
>  * ## Testendpoint1
>    * enabled: True
>    * geo_mapping: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1
>    * location: West US
>    * min_child_endpoints: None
>    * monitor_status: Degraded
>    * name: testendpoint1
>    * priority: 2
>    * resource_group: myResourceGroup
>    * target: 1.2.3.4
>    * target_resource_id: None
>    * type: external_endpoints
>    * weight: 1


### azure-rm-trafficmanagerprofile
***
Manage Azure Traffic Manager profile
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerprofile_module.html


#### Base Command

`azure-rm-trafficmanagerprofile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the Traffic Manager profile exists or will be created. | Required | 
| name | Name of the Traffic Manager profile. | Required | 
| state | Assert the state of the Traffic Manager profile. Use `present` to create or update a Traffic Manager profile and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to `global` because in default public Azure cloud, Traffic Manager profile can only be deployed globally. Reference `https://docs.microsoft.com/en-us/azure/traffic-manager/quickstart-create-traffic-manager-profile#create-a-traffic-manager-profile`. Default is global. | Optional | 
| profile_status | The status of the Traffic Manager profile. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| routing_method | The traffic routing method of the Traffic Manager profile. Possible values are: performance, priority, weighted, geographic. Default is performance. | Optional | 
| dns_config | The DNS settings of the Traffic Manager profile. | Optional | 
| monitor_config | The endpoint monitoring settings of the Traffic Manager profile. Default is {'protocol': 'HTTP', 'port': 80, 'path': '/'}. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmTrafficmanagerprofile.id | string | The ID of the traffic manager profile. | 
| Azure.AzureRmTrafficmanagerprofile.endpoints | unknown | List of endpoint IDs attached to the profile. | 


#### Command Example
```!azure-rm-trafficmanagerprofile name="tmtest" resource_group="myResourceGroup" location="global" profile_status="enabled" routing_method="priority" dns_config="{{ {'relative_name': 'xsoartmtest', 'ttl': 60} }}" monitor_config="{{ {'protocol': 'HTTPS', 'port': 80, 'path': '/'} }}" tags="{{ {'Environment': 'Test'} }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmTrafficmanagerprofile": [
            {
                "changed": false,
                "endpoints": [
                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1"
                ],
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest
>  * ## Endpoints
>    * 0: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1


### azure-rm-trafficmanagerprofile-info
***
Get Azure Traffic Manager profile facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerprofile_info_module.html


#### Base Command

`azure-rm-trafficmanagerprofile-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific Traffic Manager profile. | Optional | 
| resource_group | The resource group to search for the desired Traffic Manager profile. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmTrafficmanagerprofileInfo.tms | unknown | List of Traffic Manager profiles. | 


#### Command Example
```!azure-rm-trafficmanagerprofile-info ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmTrafficmanagerprofileInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "tms": [
                    {
                        "dns_config": {
                            "fqdn": "xsoartmtest.trafficmanager.net",
                            "relative_name": "xsoartmtest",
                            "ttl": 60
                        },
                        "endpoints": [
                            {
                                "geo_mapping": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                                "location": "West US",
                                "min_child_endpoints": null,
                                "name": "testendpoint1",
                                "priority": 2,
                                "status": "Enabled",
                                "target": "1.2.3.4",
                                "target_resource_id": null,
                                "type": "external_endpoints",
                                "weight": 1
                            }
                        ],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest",
                        "location": "global",
                        "monitor_config": {
                            "interval": 30,
                            "path": "/",
                            "port": 80,
                            "profile_monitor_status": null,
                            "protocol": "HTTPS",
                            "timeout": 10,
                            "tolerated_failures": 3
                        },
                        "name": "tmtest",
                        "profile_status": "Enabled",
                        "resource_group": "myresourcegroup",
                        "routing_method": "priority",
                        "state": "present",
                        "tags": {
                            "Environment": "Test"
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Tms
>  * ## Tmtest
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest
>    * location: global
>    * name: tmtest
>    * profile_status: Enabled
>    * resource_group: myresourcegroup
>    * routing_method: priority
>    * state: present
>    * ### Dns_Config
>      * fqdn: xsoartmtest.trafficmanager.net
>      * relative_name: xsoartmtest
>      * ttl: 60
>    * ### Endpoints
>    * ### Testendpoint1
>      * geo_mapping: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1
>      * location: West US
>      * min_child_endpoints: None
>      * name: testendpoint1
>      * priority: 2
>      * status: Enabled
>      * target: 1.2.3.4
>      * target_resource_id: None
>      * type: external_endpoints
>      * weight: 1
>    * ### Monitor_Config
>      * interval: 30
>      * path: /
>      * port: 80
>      * profile_monitor_status: None
>      * protocol: HTTPS
>      * timeout: 10
>      * tolerated_failures: 3
>    * ### Tags
>      * Environment: Test


### azure-rm-networkinterface
***
Manage Azure network interfaces
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_networkinterface_module.html


#### Base Command

`azure-rm-networkinterface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the network interface exists or will be created. | Required | 
| name | Name of the network interface. | Required | 
| state | Assert the state of the network interface. Use `present` to create or update an interface and `absent` to delete an interface. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| virtual_network | An existing virtual network with which the network interface will be associated. Required when creating a network interface. It can be the virtual network's name. Make sure your virtual network is in the same resource group as NIC when you give only the name. It can be the virtual network's resource id. It can be a dict which contains `name` and `resource_group` of the virtual network. | Required | 
| subnet_name | Name of an existing subnet within the specified virtual network. Required when creating a network interface. Use the `virtual_network`'s resource group. | Required | 
| os_type | Determines any rules to be added to a default security group. When creating a network interface, if no security group name is provided, a default security group will be created. If the `os_type=Windows`, a rule allowing RDP access will be added. If the `os_type=Linux`, a rule allowing SSH access will be added. Possible values are: Windows, Linux. Default is Linux. | Optional | 
| private_ip_address | (Deprecate) Valid IPv4 address that falls within the specified subnet. This option will be deprecated in 2.9, use `ip_configurations` instead. | Optional | 
| private_ip_allocation_method | (Deprecate) Whether or not the assigned IP address is permanent. When creating a network interface, if you specify `private_ip_address=Static`, you must provide a value for `private_ip_address`. You can update the allocation method to `Static` after a dynamic private IP address has been assigned. This option will be deprecated in 2.9, use `ip_configurations` instead. Possible values are: Dynamic, Static. Default is Dynamic. | Optional | 
| public_ip | (Deprecate) When creating a network interface, if no public IP address name is provided a default public IP address will be created. Set to `false` if you do not want a public IP address automatically created. This option will be deprecated in 2.9, use `ip_configurations` instead. Default is yes. | Optional | 
| public_ip_address_name | (Deprecate) Name of an existing public IP address object to associate with the security group. This option will be deprecated in 2.9, use `ip_configurations` instead. | Optional | 
| public_ip_allocation_method | (Deprecate) If a `public_ip_address_name` is not provided, a default public IP address will be created. The allocation method determines whether or not the public IP address assigned to the network interface is permanent. This option will be deprecated in 2.9, use `ip_configurations` instead. Possible values are: Dynamic, Static. Default is Dynamic. | Optional | 
| ip_configurations | List of IP configurations. Each configuration object should include field `private_ip_address`, `private_ip_allocation_method`, `public_ip_address_name`, `public_ip`, `public_ip_allocation_method`, `name`. | Optional | 
| enable_accelerated_networking | Whether the network interface should be created with the accelerated networking feature or not. Possible values are: Yes, No. Default is No. | Optional | 
| create_with_security_group | Whether a security group should be be created with the NIC. If this flag set to `True` and no `security_group` set, a default security group will be created. Possible values are: Yes, No. Default is Yes. | Optional | 
| security_group | An existing security group with which to associate the network interface. If not provided, a default security group will be created when `create_with_security_group=true`. It can be the name of security group. Make sure the security group is in the same resource group when you only give its name. It can be the resource id. It can be a dict contains security_group's `name` and `resource_group`. | Optional | 
| open_ports | When a default security group is created for a Linux host a rule will be added allowing inbound TCP connections to the default SSH port `22`, and for a Windows host rules will be added allowing inbound access to RDP ports `3389` and `5986`. Override the default ports by providing a list of open ports. | Optional | 
| enable_ip_forwarding | Whether to enable IP forwarding. Possible values are: Yes, No. Default is No. | Optional | 
| dns_servers | Which DNS servers should the NIC lookup. List of IP addresses. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmNetworkinterface.state | unknown | The current state of the network interface. | 


#### Command Example
```!azure-rm-networkinterface name="nic001" resource_group="myResourceGroup" virtual_network="myVirtualNetwork" subnet_name="mySubnet" ip_configurations="{{ [{'name': 'ipconfig1', 'public_ip_address_name': 'publicip001', 'primary': True}] }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmNetworkinterface": [
            {
                "changed": false,
                "state": {
                    "dns_servers": [],
                    "dns_settings": {
                        "applied_dns_servers": [],
                        "dns_servers": [],
                        "internal_dns_name_label": null,
                        "internal_fqdn": null
                    },
                    "enable_accelerated_networking": false,
                    "enable_ip_forwarding": false,
                    "etag": "W/\"165cdc7d-852f-4e0c-af11-0511290660a3\"",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001",
                    "ip_configuration": {
                        "application_security_groups": null,
                        "load_balancer_backend_address_pools": null,
                        "name": "ipconfig1",
                        "primary": true,
                        "private_ip_address": "1.1.1.3",
                        "private_ip_allocation_method": "Dynamic",
                        "public_ip_address": {
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                            "name": "publicip001",
                            "public_ip_allocation_method": null
                        },
                        "subnet": {
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                            "name": "mySubnet",
                            "resource_group": "myResourceGroup",
                            "virtual_network_name": "myVirtualNetwork"
                        }
                    },
                    "ip_configurations": [
                        {
                            "application_security_groups": null,
                            "load_balancer_backend_address_pools": null,
                            "name": "ipconfig1",
                            "primary": true,
                            "private_ip_address": "1.1.1.3",
                            "private_ip_allocation_method": "Dynamic",
                            "public_ip_address": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                                "name": "publicip001",
                                "public_ip_allocation_method": null
                            },
                            "subnet": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                                "name": "mySubnet",
                                "resource_group": "myResourceGroup",
                                "virtual_network_name": "myVirtualNetwork"
                            }
                        }
                    ],
                    "location": "australiasoutheast",
                    "mac_address": null,
                    "name": "nic001",
                    "network_security_group": {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001",
                        "name": "nic001"
                    },
                    "provisioning_state": "Succeeded",
                    "tags": {},
                    "type": "Microsoft.Network/networkInterfaces"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * enable_accelerated_networking: False
>    * enable_ip_forwarding: False
>    * etag: W/"165cdc7d-852f-4e0c-af11-0511290660a3"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001
>    * location: australiasoutheast
>    * mac_address: None
>    * name: nic001
>    * provisioning_state: Succeeded
>    * type: Microsoft.Network/networkInterfaces
>    * ### Dns_Servers
>    * ### Dns_Settings
>      * internal_dns_name_label: None
>      * internal_fqdn: None
>      * #### Applied_Dns_Servers
>      * #### Dns_Servers
>    * ### Ip_Configuration
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 1.1.1.3
>      * private_ip_allocation_method: Dynamic
>      * #### Public_Ip_Address
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>        * name: publicip001
>        * public_ip_allocation_method: None
>      * #### Subnet
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>        * name: mySubnet
>        * resource_group: myResourceGroup
>        * virtual_network_name: myVirtualNetwork
>    * ### Ip_Configurations
>    * ### Ipconfig1
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 1.1.1.3
>      * private_ip_allocation_method: Dynamic
>      * #### Public_Ip_Address
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>        * name: publicip001
>        * public_ip_allocation_method: None
>      * #### Subnet
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>        * name: mySubnet
>        * resource_group: myResourceGroup
>        * virtual_network_name: myVirtualNetwork
>    * ### Network_Security_Group
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001
>      * name: nic001
>    * ### Tags


### azure-rm-networkinterface-info
***
Get network interface facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_networkinterface_info_module.html


#### Base Command

`azure-rm-networkinterface-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific network interface. | Optional | 
| resource_group | Name of the resource group containing the network interface(s). Required when searching by name. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmNetworkinterfaceInfo.azure_networkinterfaces | unknown | List of network interface dicts. | 
| Azure.AzureRmNetworkinterfaceInfo.networkinterfaces | unknown | List of network interface dicts. Each dict contains parameters can be passed to \`azure_rm_networkinterface\` module. | 


#### Command Example
```!azure-rm-networkinterface-info resource_group="myResourceGroup" name="nic001" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmNetworkinterfaceInfo": [
            {
                "changed": false,
                "networkinterfaces": [
                    {
                        "dns_servers": [],
                        "dns_settings": {
                            "applied_dns_servers": [],
                            "dns_servers": [],
                            "internal_dns_name_label": null,
                            "internal_fqdn": null
                        },
                        "enable_accelerated_networking": false,
                        "enable_ip_forwarding": false,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001",
                        "ip_configurations": [
                            {
                                "application_security_groups": null,
                                "load_balancer_backend_address_pools": null,
                                "name": "ipconfig1",
                                "primary": true,
                                "private_ip_address": "1.1.1.3",
                                "private_ip_allocation_method": "Dynamic",
                                "public_ip_address": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                                "public_ip_allocation_method": null
                            }
                        ],
                        "location": "australiasoutheast",
                        "mac_address": null,
                        "name": "nic001",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "security_group": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001",
                        "subnet": "mySubnet",
                        "tags": null,
                        "virtual_network": {
                            "name": "myVirtualNetwork",
                            "resource_group": "myResourceGroup"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Networkinterfaces
>  * ## Nic001
>    * enable_accelerated_networking: False
>    * enable_ip_forwarding: False
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001
>    * location: australiasoutheast
>    * mac_address: None
>    * name: nic001
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * security_group: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001
>    * subnet: mySubnet
>    * tags: None
>    * ### Dns_Servers
>    * ### Dns_Settings
>      * internal_dns_name_label: None
>      * internal_fqdn: None
>      * #### Applied_Dns_Servers
>      * #### Dns_Servers
>    * ### Ip_Configurations
>    * ### Ipconfig1
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 1.1.1.3
>      * private_ip_allocation_method: Dynamic
>      * public_ip_address: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>      * public_ip_allocation_method: None
>    * ### Virtual_Network
>      * name: myVirtualNetwork
>      * resource_group: myResourceGroup


### azure-rm-publicipaddress
***
Manage Azure Public IP Addresses
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_publicipaddress_module.html


#### Base Command

`azure-rm-publicipaddress`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group with which the Public IP is associated. | Required | 
| allocation_method | Control whether the assigned Public IP remains permanently assigned to the object. If not set to `Static`, the IP address my changed anytime an associated virtual machine is power cycled. Possible values are: dynamic, static, Static, Dynamic. Default is dynamic. | Optional | 
| domain_name | The customizable portion of the FQDN assigned to public IP address. This is an explicit setting. If no value is provided, any existing value will be removed on an existing public IP. | Optional | 
| name | Name of the Public IP. | Required | 
| state | Assert the state of the Public IP. Use `present` to create or update a and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| sku | The public IP address SKU. Possible values are: basic, standard, Basic, Standard. | Optional | 
| ip_tags | List of IpTag associated with the public IP address. Each element should contain type:value pair. | Optional | 
| idle_timeout | Idle timeout in minutes. | Optional | 
| version | The public IP address version. Possible values are: ipv4, ipv6. Default is ipv4. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmPublicipaddress.state | unknown | Facts about the current state of the object. | 


#### Command Example
```!azure-rm-publicipaddress resource_group="myResourceGroup" name="my_public_ip" allocation_method="static" domain_name="foobar" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmPublicipaddress": [
            {
                "changed": false,
                "state": {
                    "dns_settings": {
                        "domain_name_label": "foobar",
                        "fqdn": "foobar.australiasoutheast.cloudapp.azure.com",
                        "reverse_fqdn": null
                    },
                    "etag": "W/\"1bee56b0-3bdb-45c8-b378-ddc94cc8e504\"",
                    "idle_timeout_in_minutes": 4,
                    "ip_address": "1.1.1.3",
                    "location": "australiasoutheast",
                    "name": "my_public_ip",
                    "provisioning_state": "Succeeded",
                    "public_ip_address_version": "ipv4",
                    "public_ip_allocation_method": "static",
                    "sku": "Basic",
                    "tags": {},
                    "type": "Microsoft.Network/publicIPAddresses"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * etag: W/"1bee56b0-3bdb-45c8-b378-ddc94cc8e504"
>    * idle_timeout_in_minutes: 4
>    * ip_address: 1.1.1.3
>    * location: australiasoutheast
>    * name: my_public_ip
>    * provisioning_state: Succeeded
>    * public_ip_address_version: ipv4
>    * public_ip_allocation_method: static
>    * sku: Basic
>    * type: Microsoft.Network/publicIPAddresses
>    * ### Dns_Settings
>      * domain_name_label: foobar
>      * fqdn: foobar.australiasoutheast.cloudapp.azure.com
>      * reverse_fqdn: None
>    * ### Tags


### azure-rm-publicipaddress-info
***
Get public IP facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_publicipaddress_info_module.html


#### Base Command

`azure-rm-publicipaddress-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific Public IP. | Optional | 
| resource_group | Limit results by resource group. Required when using name parameter. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmPublicipaddressInfo.azure_publicipaddresses | unknown | List of public IP address dicts. Please note that this option will be deprecated in 2.10 when curated format will become the only supported format. | 
| Azure.AzureRmPublicipaddressInfo.publicipaddresses | unknown | List of publicipaddress. Contains the detail which matches azure_rm_publicipaddress parameters. Returned when the format parameter set to curated. | 


#### Command Example
```!azure-rm-publicipaddress-info resource_group="myResourceGroup" name="my_public_ip" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmPublicipaddressInfo": [
            {
                "changed": false,
                "publicipaddresses": [
                    {
                        "allocation_method": "static",
                        "dns_settings": {
                            "domain_name_label": "foobar",
                            "fqdn": "foobar.australiasoutheast.cloudapp.azure.com",
                            "reverse_fqdn": null
                        },
                        "etag": "W/\"1bee56b0-3bdb-45c8-b378-ddc94cc8e504\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/my_public_ip",
                        "idle_timeout": 4,
                        "ip_address": "1.1.1.3",
                        "ip_tags": {},
                        "location": "australiasoutheast",
                        "name": "my_public_ip",
                        "provisioning_state": "Succeeded",
                        "sku": "Basic",
                        "tags": null,
                        "type": "Microsoft.Network/publicIPAddresses",
                        "version": "ipv4"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Publicipaddresses
>  * ## My_Public_Ip
>    * allocation_method: static
>    * etag: W/"1bee56b0-3bdb-45c8-b378-ddc94cc8e504"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/my_public_ip
>    * idle_timeout: 4
>    * ip_address: 1.1.1.3
>    * location: australiasoutheast
>    * name: my_public_ip
>    * provisioning_state: Succeeded
>    * sku: Basic
>    * tags: None
>    * type: Microsoft.Network/publicIPAddresses
>    * version: ipv4
>    * ### Dns_Settings
>      * domain_name_label: foobar
>      * fqdn: foobar.australiasoutheast.cloudapp.azure.com
>      * reverse_fqdn: None
>    * ### Ip_Tags


### azure-rm-route
***
Manage Azure route resource
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_route_module.html


#### Base Command

`azure-rm-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the route. | Required | 
| state | Assert the state of the route. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| address_prefix | The destination CIDR to which the route applies. | Optional | 
| next_hop_type | The type of Azure hop the packet should be sent to. Possible values are: virtual_network_gateway, vnet_local, internet, virtual_appliance, none. Default is none. | Optional | 
| next_hop_ip_address | The IP address packets should be forwarded to. Next hop values are only allowed in routes where the next hop type is VirtualAppliance. | Optional | 
| route_table_name | The name of the route table. | Required | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmRoute.id | string | Current state of the route. | 


#### Command Example
```!azure-rm-route resource_group="myResourceGroup" name="myRoute" address_prefix="10.1.0.0/16" next_hop_type="virtual_network_gateway" route_table_name="myRouteTable" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmRoute": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable/routes/myRoute",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable/routes/myRoute


### azure-rm-routetable
***
Manage Azure route table resource
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_routetable_module.html


#### Base Command

`azure-rm-routetable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the route table. | Required | 
| state | Assert the state of the route table. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| disable_bgp_route_propagation | Specified whether to disable the routes learned by BGP on that route table. Possible values are: Yes, No. Default is No. | Optional | 
| location | Region of the resource. Derived from `resource_group` if not specified. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmRoutetable.changed | boolean | Whether the resource is changed. | 
| Azure.AzureRmRoutetable.id | string | Resource ID. | 


#### Command Example
```!azure-rm-routetable resource_group="myResourceGroup" name="myRouteTable" disable_bgp_route_propagation="False" tags="{{ {'purpose': 'testing'} }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmRoutetable": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable


### azure-rm-routetable-info
***
Get route table facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_routetable_info_module.html


#### Base Command

`azure-rm-routetable-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific route table. | Optional | 
| resource_group | Limit results in a specific resource group. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmRoutetableInfo.id | string | Resource ID. | 
| Azure.AzureRmRoutetableInfo.name | string | Name of the resource. | 
| Azure.AzureRmRoutetableInfo.resource_group | string | Resource group of the route table. | 
| Azure.AzureRmRoutetableInfo.disable_bgp_route_propagation | boolean | Whether the routes learned by BGP on that route table disabled. | 
| Azure.AzureRmRoutetableInfo.tags | unknown | Tags of the route table. | 
| Azure.AzureRmRoutetableInfo.routes | unknown | Current routes of the route table. | 


#### Command Example
```!azure-rm-routetable-info name="Testing" resource_group="myResourceGroup"```

#### Context Example
```json
{
    "Azure": {
        "AzureRmRoutetableInfo": [
            {
                "changed": false,
                "route_tables": [],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Route_Tables


### azure-rm-securitygroup
***
Manage Azure network security groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_securitygroup_module.html


#### Base Command

`azure-rm-securitygroup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| default_rules | The set of default rules automatically added to a security group at creation. In general default rules will not be modified. Modify rules to shape the flow of traffic to or from a subnet or NIC. See rules below for the makeup of a rule dict. | Optional | 
| location | Valid azure location. Defaults to location of the resource group. | Optional | 
| name | Name of the security group to operate on. | Optional | 
| purge_default_rules | Remove any existing rules not matching those defined in the default_rules parameter. Default is no. | Optional | 
| purge_rules | Remove any existing rules not matching those defined in the rules parameters. Default is no. | Optional | 
| resource_group | Name of the resource group the security group belongs to. | Required | 
| rules | Set of rules shaping traffic flow to or from a subnet or NIC. Each rule is a dictionary. | Optional | 
| state | Assert the state of the security group. Set to `present` to create or update a security group. Set to `absent` to remove a security group. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmSecuritygroup.state | unknown | Current state of the security group. | 


#### Command Example
```!azure-rm-securitygroup resource_group="myResourceGroup" name="mysecgroup" purge_rules="True" rules="{{ [{'name': 'DenySSH', 'protocol': 'Tcp', 'destination_port_range': 22, 'access': 'Deny', 'priority': 100, 'direction': 'Inbound'}, {'name': 'AllowSSH', 'protocol': 'Tcp', 'source_address_prefix': ['1.1.1.3/24', '1.1.1.4/24'], 'destination_port_range': 22, 'access': 'Allow', 'priority': 101, 'direction': 'Inbound'}, {'name': 'AllowMultiplePorts', 'protocol': 'Tcp', 'source_address_prefix': ['1.1.1.1/24', '1.1.1.4/24'], 'destination_port_range': [80, 443], 'access': 'Allow', 'priority': 102}] }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmSecuritygroup": [
            {
                "changed": true,
                "state": {
                    "default_rules": [
                        {
                            "access": "Allow",
                            "description": "Allow inbound traffic from all VMs in VNET",
                            "destination_address_prefix": "VirtualNetwork",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound",
                            "name": "AllowVnetInBound",
                            "priority": 65000,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "VirtualNetwork",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        }
                    ],
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup",
                    "location": "australiasoutheast",
                    "name": "mysecgroup",
                    "network_interfaces": [],
                    "rules": [
                        {
                            "access": "Deny",
                            "description": null,
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "22",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH",
                            "name": "DenySSH",
                            "priority": 100,
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "*",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        }
                    ],
                    "subnets": [],
                    "tags": {},
                    "type": "Microsoft.Network/networkSecurityGroups"
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup
>    * location: australiasoutheast
>    * name: mysecgroup
>    * type: Microsoft.Network/networkSecurityGroups
>    * ### Default_Rules
>    * ### Allowvnetinbound
>      * access: Allow
>      * description: Allow inbound traffic from all VMs in VNET
>      * destination_address_prefix: VirtualNetwork
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound
>      * name: AllowVnetInBound
>      * priority: 65000
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: VirtualNetwork
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Network_Interfaces
>    * ### Rules
>    * ### Denyssh
>      * access: Deny
>      * description: None
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: 22
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH
>      * name: DenySSH
>      * priority: 100
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * source_address_prefix: *
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Subnets
>    * ### Tags


### azure-rm-securitygroup-info
***
Get security group facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_securitygroup_info_module.html


#### Base Command

`azure-rm-securitygroup-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific security group. | Optional | 
| resource_group | Name of the resource group to use. | Required | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmSecuritygroupInfo.securitygroups | unknown | List containing security group dicts. | 


#### Command Example
```!azure-rm-securitygroup-info resource_group="myResourceGroup" name="mysecgroup" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmSecuritygroupInfo": [
            {
                "changed": false,
                "securitygroups": [
                    {
                        "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup",
                        "location": "australiasoutheast",
                        "name": "mysecgroup",
                        "properties": {
                            "defaultSecurityRules": [
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound",
                                    "name": "AllowVnetInBound",
                                    "properties": {
                                        "access": "Allow",
                                        "description": "Allow inbound traffic from all VMs in VNET",
                                        "destinationAddressPrefix": "VirtualNetwork",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 65000,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "VirtualNetwork",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                }
                            ],
                            "provisioningState": "Succeeded",
                            "resourceGuid": "2ceea731-b4fb-4999-8ac6-0b6a74a1df94",
                            "securityRules": [
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH",
                                    "name": "DenySSH",
                                    "properties": {
                                        "access": "Deny",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "22",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 100,
                                        "protocol": "Tcp",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "*",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                }
                            ]
                        },
                        "tags": {},
                        "type": "Microsoft.Network/networkSecurityGroups"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Securitygroups
>  * ## Mysecgroup
>    * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup
>    * location: australiasoutheast
>    * name: mysecgroup
>    * type: Microsoft.Network/networkSecurityGroups
>    * ### Properties
>      * provisioningState: Succeeded
>      * resourceGuid: 2ceea731-b4fb-4999-8ac6-0b6a74a1df94
>      * #### Defaultsecurityrules
>      * #### Allowvnetinbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound
>        * name: AllowVnetInBound
>        * ##### Properties
>          * access: Allow
>          * description: Allow inbound traffic from all VMs in VNET
>          * destinationAddressPrefix: VirtualNetwork
>          * destinationPortRange: *
>          * direction: Inbound
>          * priority: 65000
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: VirtualNetwork
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Securityrules
>      * #### Denyssh
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH
>        * name: DenySSH
>        * ##### Properties
>          * access: Deny
>          * destinationAddressPrefix: *
>          * destinationPortRange: 22
>          * direction: Inbound
>          * priority: 100
>          * protocol: Tcp
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: *
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>    * ### Tags


### azure-rm-dnsrecordset
***
Create, delete and update DNS record sets and records
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnsrecordset_module.html


#### Base Command

`azure-rm-dnsrecordset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| zone_name | Name of the existing DNS zone in which to manage the record set. | Required | 
| relative_name | Relative name of the record set. | Required | 
| record_type | The type of record set to create or delete. Possible values are: A, AAAA, CNAME, MX, NS, SRV, TXT, PTR, CAA, SOA. | Required | 
| record_mode | Whether existing record values not sent to the module should be purged. Possible values are: append, purge. Default is purge. | Optional | 
| state | Assert the state of the record set. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| time_to_live | Time to live of the record set in seconds. Default is 3600. | Optional | 
| records | List of records to be created depending on the type of record (set). | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDnsrecordset.state | unknown | Current state of the DNS record set. | 


#### Command Example
```!azure-rm-dnsrecordset resource_group="myResourceGroup" relative_name="www" zone_name="xsoarexample.com" record_type="A" records="{{ [{'entry': '192.168.100.101'}, {'entry': '192.168.100.102'}, {'entry': '192.168.100.103'}] }}" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDnsrecordset": [
            {
                "changed": false,
                "state": {
                    "arecords": [
                        {
                            "ipv4_address": "192.168.100.101"
                        },
                        {
                            "ipv4_address": "192.168.100.102"
                        },
                        {
                            "ipv4_address": "192.168.100.103"
                        }
                    ],
                    "etag": "97b23b1e-1d39-4340-a97b-325b17725d55",
                    "fqdn": "www.xsoarexample.com.",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www",
                    "name": "www",
                    "provisioning_state": "Succeeded",
                    "target_resource": {},
                    "ttl": 3600,
                    "type": "A"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * etag: 97b23b1e-1d39-4340-a97b-325b17725d55
>    * fqdn: www.xsoarexample.com.
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www
>    * name: www
>    * provisioning_state: Succeeded
>    * ttl: 3600
>    * type: A
>    * ### Arecords
>    * ### List
>      * ipv4_address: 192.168.100.101
>    * ### List
>      * ipv4_address: 192.168.100.102
>    * ### List
>      * ipv4_address: 192.168.100.103
>    * ### Target_Resource


### azure-rm-dnsrecordset-info
***
Get DNS Record Set facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnsrecordset_info_module.html


#### Base Command

`azure-rm-dnsrecordset-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| relative_name | Only show results for a Record Set. | Optional | 
| resource_group | Limit results by resource group. Required when filtering by name or type. | Optional | 
| zone_name | Limit results by zones. Required when filtering by name or type. | Optional | 
| record_type | Limit record sets by record type. | Optional | 
| top | Limit the maximum number of record sets to return. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDnsrecordsetInfo.azure_dnsrecordset | unknown | List of record set dicts. | 
| Azure.AzureRmDnsrecordsetInfo.dnsrecordsets | unknown | List of record set dicts, which shares the same hierarchy as \`azure_rm_dnsrecordset\` module's parameter. | 


#### Command Example
```!azure-rm-dnsrecordset-info resource_group="myResourceGroup" zone_name="xsoarexample.com" relative_name="www" record_type="A" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDnsrecordsetInfo": [
            {
                "changed": false,
                "dnsrecordsets": [
                    {
                        "fqdn": "www.xsoarexample.com.",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www",
                        "provisioning_state": "Succeeded",
                        "record_type": "A",
                        "records": [
                            {
                                "ipv4_address": "192.168.100.101"
                            },
                            {
                                "ipv4_address": "192.168.100.102"
                            },
                            {
                                "ipv4_address": "192.168.100.103"
                            }
                        ],
                        "relative_name": "www",
                        "time_to_live": 3600
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Dnsrecordsets
>  * ## Www
>    * fqdn: www.xsoarexample.com.
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www
>    * provisioning_state: Succeeded
>    * record_type: A
>    * relative_name: www
>    * time_to_live: 3600
>    * ### Records
>    * ### List
>      * ipv4_address: 192.168.100.101
>    * ### List
>      * ipv4_address: 192.168.100.102
>    * ### List
>      * ipv4_address: 192.168.100.103


### azure-rm-dnszone
***
Manage Azure DNS zones
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnszone_module.html


#### Base Command

`azure-rm-dnszone`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | name of resource group. | Required | 
| name | Name of the DNS zone. | Required | 
| state | Assert the state of the zone. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| type | The type of this DNS zone (`public` or `private`). Possible values are: public, private. | Optional | 
| registration_virtual_networks | A list of references to virtual networks that register hostnames in this DNS zone. This is a only when `type=private`. Each element can be the name or resource id, or a dict contains `name`, `resource_group` information of the virtual network. | Optional | 
| resolution_virtual_networks | A list of references to virtual networks that resolve records in this DNS zone. This is a only when `type=private`. Each element can be the name or resource id, or a dict contains `name`, `resource_group` information of the virtual network. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDnszone.state | unknown | Current state of the zone. | 


#### Command Example
```!azure-rm-dnszone resource_group="myResourceGroup" name="xsoarexample.com" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDnszone": [
            {
                "changed": false,
                "check_mode": false,
                "state": {
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                    "name": "xsoarexample.com",
                    "name_servers": [
                        "ns1-01.azure-dns.com.",
                        "ns2-01.azure-dns.net.",
                        "ns3-01.azure-dns.org.",
                        "ns4-01.azure-dns.info."
                    ],
                    "number_of_record_sets": 3,
                    "registration_virtual_networks": null,
                    "resolution_virtual_networks": null,
                    "tags": {},
                    "type": "public"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * check_mode: False
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>    * name: xsoarexample.com
>    * number_of_record_sets: 3
>    * registration_virtual_networks: None
>    * resolution_virtual_networks: None
>    * type: public
>    * ### Name_Servers
>      * 0: ns1-01.azure-dns.com.
>      * 1: ns2-01.azure-dns.net.
>      * 2: ns3-01.azure-dns.org.
>      * 3: ns4-01.azure-dns.info.
>    * ### Tags


### azure-rm-dnszone-info
***
Get DNS zone facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnszone_info_module.html


#### Base Command

`azure-rm-dnszone-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Limit results by resource group. Required when filtering by name. | Optional | 
| name | Only show results for a specific zone. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.AzureRmDnszoneInfo.azure_dnszones | unknown | List of zone dicts. | 
| Azure.AzureRmDnszoneInfo.dnszones | unknown | List of zone dicts, which share the same layout as azure_rm_dnszone module parameter. | 


#### Command Example
```!azure-rm-dnszone-info resource_group="myResourceGroup" name="xsoarexample.com" ```

#### Context Example
```json
{
    "Azure": {
        "AzureRmDnszoneInfo": [
            {
                "changed": false,
                "dnszones": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                        "max_number_of_record_sets": 10000,
                        "name": "xsoarexample.com",
                        "name_servers": [
                            "ns1-01.azure-dns.com.",
                            "ns2-01.azure-dns.net.",
                            "ns3-01.azure-dns.org.",
                            "ns4-01.azure-dns.info."
                        ],
                        "number_of_record_sets": 3,
                        "registration_virtual_networks": null,
                        "resolution_virtual_networks": null,
                        "tags": {},
                        "type": "public"
                    }
                ],
                "info": {
                    "azure_dnszones": [
                        {
                            "etag": "00000002-0000-0000-2a52-97b25176d701",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                            "location": "global",
                            "name": "xsoarexample.com",
                            "properties": {
                                "maxNumberOfRecordSets": 10000,
                                "nameServers": [
                                    "ns1-01.azure-dns.com.",
                                    "ns2-01.azure-dns.net.",
                                    "ns3-01.azure-dns.org.",
                                    "ns4-01.azure-dns.info."
                                ],
                                "numberOfRecordSets": 3,
                                "zoneType": "Public"
                            },
                            "tags": {},
                            "type": "Microsoft.Network/dnszones"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Dnszones
>    * ### Xsoarexample.Com
>      * etag: 00000002-0000-0000-2a52-97b25176d701
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>      * location: global
>      * name: xsoarexample.com
>      * type: Microsoft.Network/dnszones
>      * #### Properties
>        * maxNumberOfRecordSets: 10000
>        * numberOfRecordSets: 3
>        * zoneType: Public
>        * ##### Nameservers
>          * 0: ns1-01.azure-dns.com.
>          * 1: ns2-01.azure-dns.net.
>          * 2: ns3-01.azure-dns.org.
>          * 3: ns4-01.azure-dns.info.
>      * #### Tags
>  * ## Dnszones
>  * ## Xsoarexample.Com
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>    * max_number_of_record_sets: 10000
>    * name: xsoarexample.com
>    * number_of_record_sets: 3
>    * registration_virtual_networks: None
>    * resolution_virtual_networks: None
>    * type: public
>    * ### Name_Servers
>      * 0: ns1-01.azure-dns.com.
>      * 1: ns2-01.azure-dns.net.
>      * 2: ns3-01.azure-dns.org.
>      * 3: ns4-01.azure-dns.info.
>    * ### Tags


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide).

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
