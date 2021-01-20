Manage Palo Alto Networks Firewall and Panorama. For more information see Panorama documentation.
This integration was integrated and tested with version xx of Panorama
## Configure Panorama on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Panorama.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | server | Server URL \(e.g., https://192.168.0.1\) | True |
    | port | Port \(e.g 443\) | False |
    | key | API Key | True |
    | device_group | Device group - Panorama instances only \(write shared for Shared location\) | False |
    | vsys | Vsys - Firewall instances only | False |
    | template | Template - Panorama instances only | False |
    | use_url_filtering | Use URL Filtering for auto enrichment | False |
    | additional_suspicious | URL Filtering Additional suspicious categories. CSV list of categories that will be considered suspicious. | False |
    | additional_malicious | URL Filtering Additional malicious categories. CSV list of categories that will be considered malicious. | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### panorama
***
Run any command supported in the API.


#### Base Command

`panorama`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action to be taken, such as show, get, set, edit, delete, rename, clone, move, override, multi-move, multi-clone, or complete. Possible values are: set, edit, delete, rename, clone, move, override, muti-move, multi-clone, complete, show, get. | Optional | 
| category | Category parameter. For example, when exporting a configuration file, use "category=configuration". | Optional | 
| cmd | Specifies the xml structure that defines the command. Used for operation commands. | Optional | 
| command | Run a command. For example, command =&lt;show&gt;&lt;arp&gt;&lt;entry name='all'/&gt;&lt;/arp&gt;&lt;/show&gt;. | Optional | 
| dst | Specifies a destination. | Optional | 
| element | Used to define a new value for an object. | Optional | 
| to | End time (used when cloning an object). | Optional | 
| from | Start time (used when cloning an object). | Optional | 
| key | Sets a key value. | Optional | 
| log-type | Retrieves log types. For example, log-type=threat for threat logs. | Optional | 
| where | Specifies the type of a move operation (for example, where=after, where=before, where=top, where=bottom). | Optional | 
| period | Time period. For example, period=last-24-hrs. | Optional | 
| xpath | xpath location. For example, xpath=/config/predefined/application/entry[@name='hotmail']. | Optional | 
| pcap-id | PCAP ID included in the threat log. | Optional | 
| serialno | Specifies the device serial number. | Optional | 
| reporttype | Chooses the report type, such as dynamic, predefined or custom. | Optional | 
| reportname | Report name. | Optional | 
| type | Request type (e.g. export, import, log, config). Default is keygen,config,commit,op,report,log,import,export,user-id,version. | Optional | 
| search-time | The time that the PCAP was received on the firewall. Used for threat PCAPs. | Optional | 
| target | Target number of the firewall. Use only on a Panorama instance. | Optional | 
| job-id | Job ID. | Optional | 
| query | Query string. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-get-predefined-threats-list
***
Gets the predefined threats list from a Firewall or Panorama and stores it as a JSON file in the context.


#### Base Command

`panorama-get-predefined-threats-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The firewall managed by Panorama from which to retrieve the predefined threats. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.Name | string | File name. | 
| File.Type | string | File type. | 
| File.Info | string | File information. | 
| File.Extension | string | File extension. | 
| File.EntryID | string | File entry ID. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.SHA512 | string | SHA512 hash of the file. | 
| File.SSDeep | string | SSDeep hash of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-commit
***
Commits a configuration to the Palo Alto firewall or Panorama, but does not validate if the commit was successful. Committing to Panorama does not push the configuration to the firewalls. To push the configuration, run the panorama-push-to-device-group command.


#### Base Command

`panorama-commit`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | Job ID to commit. | 
| Panorama.Commit.Status | string | Commit status. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-push-to-device-group
***
Pushes rules from PAN-OS to the configured device group.


#### Base Command

`panorama-push-to-device-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | String | Device group in which the policies were pushed. | 
| Panorama.Push.JobID | Number | Job ID of the polices that were pushed. | 
| Panorama.Push.Status | String | Push status. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-addresses
***
Returns a list of addresses.


#### Base Command

`panorama-list-addresses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the list of addresses. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Address device group. | 
| Panorama.Addresses.Tags | String | Address tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-address
***
Returns address details for the supplied address name.


#### Base Command

`panorama-get-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tags | String | Address tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-address
***
Creates an address object.


#### Base Command

`panorama-create-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | New address name. | Required | 
| description | New address description. | Optional | 
| fqdn | FQDN of the new address. | Optional | 
| ip_netmask | IP Netmask of the new address. For example, 10.10.10.10/24. | Optional | 
| ip_range | IP range of the new address IP. For example, 10.10.10.0-10.10.10.255. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag for the new address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tag | String | Address tag. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-address
***
Delete an address object


#### Base Command

`panorama-delete-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name that was deleted. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-address-groups
***
Returns a list of address groups.


#### Base Command

`panorama-list-address-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the Address groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | String | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | Address group tag. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-address-group
***
Get details for the specified address group


#### Base Command

`panorama-get-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | string | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | Address group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-address-group
***
Creates a static or dynamic address group.


#### Base Command

`panorama-create-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address group name. | Required | 
| type | Address group type. Possible values are: dynamic, static. | Required | 
| match | Dynamic Address group match. e.g: "1.1.1.1 or 2.2.2.2". | Optional | 
| addresses | Static address group list of addresses. | Optional | 
| description | Address group description. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags for the Address group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Addresses | string | Static Address group list of addresses. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | Address group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-block-vulnerability
***
Sets a vulnerability signature to block mode.


#### Base Command

`panorama-block-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| drop_mode | Type of session rejection. Possible values are: "drop", "alert", "block-ip", "reset-both", "reset-client", and "reset-server". Default is "drop". Possible values are: drop, alert, block-ip, reset-both, reset-client, reset-server. | Optional | 
| vulnerability_profile | Name of vulnerability profile. | Required | 
| threat_id | Numerical threat ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.ID | string | ID of vulnerability that has been blocked/overridden. | 
| Panorama.Vulnerability.NewAction | string | New action for the vulnerability. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-address-group
***
Deletes an address group.


#### Base Command

`panorama-delete-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of address group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Name of address group that was deleted. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-address-group
***
Edits a static or dynamic address group.


#### Base Command

`panorama-edit-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address group to edit. | Required | 
| type | Address group type. Possible values are: static, dynamic. | Required | 
| match | Address group new match. For example, '1.1.1.1 and 2.2.2.2'. | Optional | 
| element_to_add | Element to add to the list of the static address group. Only existing Address objects can be added. | Optional | 
| element_to_remove | Element to remove from the list of the static address group. Only existing Address objects can be removed. | Optional | 
| description | Address group new description. | Optional | 
| tags | The tag of the Address group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Filter | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | string | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | Address group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-services
***
Returns a list of addresses.


#### Base Command

`panorama-list-services`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the Services. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Description | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group in which the service was configured \(Panorama instances\). | 
| Panorama.Services.Tags | String | Service tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-service
***
Returns service details for the supplied service name.


#### Base Command

`panorama-get-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Description | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 
| Panorama.Service.Tags | String | Service tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-service
***
Creates a service.


#### Base Command

`panorama-create-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name for the new service. | Required | 
| protocol | Protocol for the new service. Possible values are: tcp, udp, sctp. | Required | 
| destination_port | Destination port  for the new service. | Required | 
| source_port | Source port  for the new service. | Optional | 
| description | Description for the new service. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | Tags for the new service. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Descritpion | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 
| Panorama.Services.Tags | String | Service tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-service
***
Deletes a service.


#### Base Command

`panorama-delete-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Name of the deleted service. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-service-groups
***
Returns a list of service groups.


#### Base Command

`panorama-list-service-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tags for which to filter the Service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-service-group
***
Returns details for the specified service group.


#### Base Command

`panorama-get-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-service-group
***
Creates a service group.


#### Base Command

`panorama-create-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service group name. | Required | 
| services | Service group related services. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | Tags for which to filter Service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-service-group
***
Deletes a service group.


#### Base Command

`panorama-delete-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Name of the deleted service group. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-service-group
***
Edit a service group.


#### Base Command

`panorama-edit-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service group to edit. | Required | 
| services_to_add | Services to add to the service group. Only existing Services objects can be added. | Optional | 
| services_to_remove | Services to remove from the service group. Only existing Services objects can be removed. | Optional | 
| tags | Tag of the Service group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-custom-url-category
***
Returns information for a custom URL category.


#### Base Command

`panorama-get-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Custom URL category name. | Required | 
| device-group | The device group for which to return addresses for the custom URL category (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | String | The category name of the custom URL. | 
| Panorama.CustomURLCategory.Description | String | The category description of the custom URL. | 
| Panorama.CustomURLCategory.Sites | String | The list of sites of the custom URL category. | 
| Panorama.CustomURLCategory.DeviceGroup | String | The device group for the custom URL Category \(Panorama instances\). | 
| Panorama.CustomURLCategory.Categories | String | The list of categories of the custom URL category. | 
| Panorama.CustomURLCategory.Type | String | The category type of the custom URL. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-custom-url-category
***
Creates a custom URL category.


#### Base Command

`panorama-create-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the custom URL category to create. | Required | 
| description | Description of the custom URL category to create. | Optional | 
| sites | List of sites for the custom URL category. | Optional | 
| device-group | The device group for which to return addresses for the custom URL category (Panorama instances). | Optional | 
| type | The category type of the URL. Relevant from PAN-OS v9.x. Possible values are: URL List, Category Match. | Optional | 
| categories | The list of categories. Relevant from PAN-OS v9.x. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | String | Custom URL category name. | 
| Panorama.CustomURLCategory.Description | String | Custom URL category description. | 
| Panorama.CustomURLCategory.Sites | String | Custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | String | Device group for the Custom URL Category \(Panorama instances\). | 
| Panorama.CustomURLCategory.Sites | String | Custom URL category list of categories. | 
| Panorama.CustomURLCategory.Type | String | Custom URL category type. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-custom-url-category
***
Deletes a custom URL category.


#### Base Command

`panorama-delete-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the custom URL category to delete. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | Name of the custom URL category to delete. | 
| Panorama.CustomURLCategory.DeviceGroup | string | Device group for the Custom URL Category \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-custom-url-category
***
Adds or removes sites to and from a custom URL category.


#### Base Command

`panorama-edit-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the custom URL category to add or remove sites. | Required | 
| sites | A comma separated list of sites to add to the custom URL category. | Optional | 
| action | Adds or removes sites or categories. Can be "add",or "remove". Possible values are: add, remove. | Required | 
| categories | A comma separated list of categories to add to the custom URL category. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | Custom URL category name. | 
| Panorama.CustomURLCategory.Description | string | Custom URL category description. | 
| Panorama.CustomURLCategory.Sites | string | Custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | string | Device group for the Custom URL Category \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-url-category
***
Gets a URL category from URL filtering.


#### Base Command

`panorama-get-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | URL. | 
| Panorama.URLFilter.Category | string | URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Gets a URL category from URL filtering.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-url-category-from-cloud
***
Returns a URL category from URL filtering.


#### Base Command

`panorama-get-url-category-from-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-url-category-from-host
***
Returns a URL category from URL filtering.


#### Base Command

`panorama-get-url-category-from-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-url-filter
***
Returns information for a URL filtering rule.


#### Base Command

`panorama-get-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL Filter name. | Required | 
| device-group | The device group for which to return addresses for the URL Filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category name. | 
| Panorama.URLFilter.Category.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override block list. | 
| Panorama.URLFilter.OverrideAllowList | string | URL Filter override allow list. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-url-filter
***
Creates a URL filtering rule.


#### Base Command

`panorama-create-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter to create. | Required | 
| url_category | URL categories. | Required | 
| action | Action for the URL categories. Can be "allow", "block", "alert", "continue", or "override". Possible values are: allow, block, alert, continue, override. | Required | 
| override_allow_list | CSV list of URLs to exclude from the allow list. | Optional | 
| override_block_list | CSV list of URLs to exclude from the blocked list. | Optional | 
| description | URL Filter description. | Optional | 
| device-group | The device group for which to return addresses for the URL Filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category name. | 
| Panorama.URLFilter.Category.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override allow list. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override blocked list. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-url-filter
***
Edit a URL filtering rule.


#### Base Command

`panorama-edit-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter to edit. | Required | 
| element_to_change | Element to change. Can be "override_allow_list", or "override_block_list". Possible values are: override_allow_list, override_block_list, description. | Required | 
| element_value | Element value. Limited to one value. | Required | 
| add_remove_element | Add or remove an element from the Allow List or Block List fields. Default is to 'add' the element_value to the list. Possible values are: add, remove. Default is add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category. | 
| Panorama.URLFilter.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideAllowList | string | Allow Overrides for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | Block Overrides for the URL category. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-url-filter
***
Deletes a URL filtering rule.


#### Base Command

`panorama-delete-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter rule to delete. | Required | 
| device-group | The device group for which to return addresses for the URL filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL filter rule name. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-edls
***
Returns a list of external dynamic lists.


#### Base Command

`panorama-list-edls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-edl
***
Returns information for an external dynamic list


#### Base Command

`panorama-get-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-create-edl
***
Creates an external dynamic list.


#### Base Command

`panorama-create-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL. | Required | 
| url | URL from which to pull the EDL. | Required | 
| type | The type of EDL. Possible values are: ip, url, domain. | Required | 
| recurring | Time interval for pulling and updating the EDL. Possible values are: five-minute, hourly. | Required | 
| certificate_profile | Certificate Profile name for the URL that was previously uploaded. to PAN OS. | Optional | 
| description | Description of the EDL. | Optional | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of theEDL. | 
| Panorama.EDL.Type | string | Type of the EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-edl
***
Modifies an element of an external dynamic list.


#### Base Command

`panorama-edit-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the external dynamic list to edit. | Required | 
| element_to_change | The element to change (“url”, “recurring”, “certificate_profile”, “description”). Possible values are: url, recurring, certificate_profile, description. | Required | 
| element_value | The element value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.URL | string | URL where the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-edl
***
Deletes an external dynamic list.


#### Base Command

`panorama-delete-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL to delete. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL that was deleted. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-refresh-edl
***
Refreshes the specified external dynamic list.


#### Base Command

`panorama-refresh-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 
| edl_type | The type of the EDL. Required when refreshing an EDL object which is configured on Panorama. Possible values are: ip, url, domain. | Optional | 
| location | The location of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 
| vsys | The Vsys of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-rule
***
Creates a policy rule.


#### Base Command

`panorama-create-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to create. | Optional | 
| description | Description of the rule to create. | Optional | 
| action | Action for the rule. Can be "allow", "deny", or "drop". Possible values are: allow, deny, drop. | Required | 
| source | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| destination | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| source_zone | A comma-separated list of source zones. | Optional | 
| destination_zone | A comma-separated list of destination zones. | Optional | 
| negate_source | Whether to negate the source (address, address group). Can be "Yes" or "No". Possible values are: Yes, No. | Optional | 
| negate_destination | Whether to negate the destination (address, address group). Can be "Yes" or "No". Possible values are: Yes, No. | Optional | 
| service | Service object names for the rule (service object) to create. | Optional | 
| disable | Whether to disable the rule. Can be "Yes" or "No" (default is "No"). Possible values are: Yes, No. Default is No. | Optional | 
| application | A comma-separated list of application object namesfor the rule to create. Default is any. | Optional | 
| source_user | Source user for the rule to create. Default is any. | Optional | 
| pre_post | Pre rule or Post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | Log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | Rule tags to create. | Optional | 
| category | A comma-separated list of URL categories. | Optional | 
| profile_setting | A profile setting group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Description | string | Rule description. | 
| Panorama.SecurityRule.Action | string | Action for the rule. | 
| Panorama.SecurityRule.Source | string | Source address. | 
| Panorama.SecurityRule.Destination | string | Destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | Service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | Application for the rule. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.LogForwarding | string | Log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | Rule tags. | 
| Panorama.SecurityRules.ProfileSetting | String | Profile setting group. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-custom-block-rule
***
Creates a custom block policy rule.


#### Base Command

`panorama-custom-block-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the custom block policy rule to create. | Optional | 
| object_type | Object type to block in the policy rule. Can be "ip", "address-group", "edl", or "custom-url-category". Possible values are: ip, address-group, application, url-category, edl. | Required | 
| object_value | A comma-separated list of object values for the object_type argument. | Required | 
| direction | Direction to block. Can be "to", "from", or "both". Default is "both". This argument is not applicable to the "custom-url-category" object_type. Possible values are: to, from, both. Default is both. | Optional | 
| pre_post | Pre rule or Post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | Log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | Tags for which to use for the custom block policy rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Object | string | Blocked object. | 
| Panorama.SecurityRule.Direction | string | Direction blocked. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\) | 
| Panorama.SecurityRule.LogForwarding | string | Log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | Rule tags. | 
| Panorama.SecurityRules.ProfileSetting | String | Profile setting group. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-move-rule
***
Changes the location of a policy rule.


#### Base Command

`panorama-move-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to move. | Required | 
| where | Where to move the rule. Can be "before", "after", "top", or "bottom". If you specify "top" or "bottom", you need to supply the "dst" argument. Possible values are: before, after, top, bottom. | Required | 
| dst | Destination rule relative to the rule that you are moving. This field is only relevant if you specify "top" or "bottom" in the "where" argument. | Optional | 
| pre_post | Rule location. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-edit-rule
***
Edits a policy rule.


#### Base Command

`panorama-edit-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to edit. | Required | 
| element_to_change | Parameter in the security rule to change. Can be 'source', 'destination', 'application', 'action', 'category', 'description', 'disabled', 'target', 'log-forwarding', 'tag' or 'group_profile'. Possible values are: source, destination, application, action, category, description, disabled, target, log-forwarding, tag, profile-setting. | Required | 
| element_value | The new value for the parameter. | Required | 
| pre_post | Pre-rule or post-rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| behaviour | Whether to replace, add, or remove the element_value from the current rule object value. Possible values are: replace, add, remove. Default is replace. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Description | string | Rule description. | 
| Panorama.SecurityRule.Action | string | Action for the rule. | 
| Panorama.SecurityRule.Source | string | Source address. | 
| Panorama.SecurityRule.Destination | string | Destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination is negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | Service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | Application for the rule. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | Tags for the rule. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-rule
***
Deletes a policy rule.


#### Base Command

`panorama-delete-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to delete. | Required | 
| pre_post | Pre rule or Post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-applications
***
Returns a list of applications.


#### Base Command

`panorama-list-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| predefined | Whether to list predefined applications or not. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Applications.Name | string | Application name. | 
| Panorama.Applications.Id | number | Application ID. | 
| Panorama.Applications.Category | string | Application category. | 
| Panorama.Applications.SubCategory | string | Application sub-category. | 
| Panorama.Applications.Technology | string | Application technology. | 
| Panorama.Applications.Risk | number | Application risk \(1 to 5\). | 
| Panorama.Applications.Description | string | Application description. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-commit-status
***
Returns commit status for a configuration.


#### Base Command

`panorama-commit-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | Job ID of the configuration to be committed. | 
| Panorama.Commit.Status | string | Commit status. | 
| Panorama.Commit.Details | string | Job ID details. | 
| Panorama.Commit.Warnings | String | Job ID warnings | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-push-status
***
Returns the push status for a configuration.


#### Base Command

`panorama-push-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | string | Device group to which the policies were pushed. | 
| Panorama.Push.JobID | number | Job ID of the configuration to be pushed. | 
| Panorama.Push.Status | string | Push status. | 
| Panorama.Push.Details | string | Job ID details. | 
| Panorama.Push.Warnings | String | Job ID warnings | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-pcap
***
Returns information for a Panorama PCAP file. The recommended maximum file size is 5 MB. If the limit is exceeded, you might need to SSH the firewall and run the scp export command to export the PCAP file. For more information, see the Palo Alto Networks documentation.


#### Base Command

`panorama-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | Type of Packet Capture. Possible values are: application-pcap, filter-pcap, threat-pcap, dlp-pcap. | Required | 
| from | The file name for the PCAP type ('dlp-pcap', 'filters-pcap', or 'application-pcap'). | Optional | 
| localName | The new name for the PCAP file after downloading. If this argument is not specified, the file name is the PCAP file name set in the firewall. | Optional | 
| serialNo | Serial number for the request. For further information, see the Panorama XML API Documentation. | Optional | 
| searchTime | The Search time for the request. For example: "2019/12/26 00:00:00", "2020/01/10". For more information, see the Panorama XML API documentation. | Optional | 
| pcapID | The ID of the PCAP for the request. For further information, see the Panorama XML API Documentation. | Optional | 
| password | Password for Panorama, needed for the 'dlp-pcap' PCAP type only. | Optional | 
| deviceName | The Device Name on which the PCAP is stored. For further information, see the Panorama XML API Documentation. | Optional | 
| sessionID | The Session ID of the PCAP. For further information, see the Panorama XML API Documentation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.Name | string | File name. | 
| File.Type | string | File type. | 
| File.Info | string | File info. | 
| File.Extension | string | File extension. | 
| File.EntryID | string | FIle entryID. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.SHA512 | string | SHA512 hash of the file. | 
| File.SSDeep | string | SSDeep hash of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-pcaps
***
Returns a list of all PCAP files by PCAP type.


#### Base Command

`panorama-list-pcaps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | Type of Packet Capture. Possible values are: application-pcap, filter-pcap, threat-pcap, dlp-pcap. | Required | 
| password | Password for Panorama. Relevant for the 'dlp-pcap' PCAP type. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-register-ip-tag
***
Registers IP addresses to a tag.


#### Base Command

`panorama-register-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to register IP addresses. | Required | 
| IPs | IP addresses to register. | Required | 
| persistent | Whether the IP addresses remain registered to the tag after the device reboots ('true':persistent, 'false':non-persistent). Default is 'true'. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | Name of the tag. | 
| Panorama.DynamicTags.IPs | string | Registered IP addresses. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-unregister-ip-tag
***
Unregisters IP addresses from a tag.


#### Base Command

`panorama-unregister-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to unregister IP addresses. | Required | 
| IPs | IP addresses to unregister. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-register-user-tag
***
Registers users to a tag. This command is only available for PAN-OS version 9.x and above.


#### Base Command

`panorama-register-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to register users. | Required | 
| Users | A comma-separated list of users to register. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | Name of the tag. | 
| Panorama.DynamicTags.Users | string | List of registered users. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-unregister-user-tag
***
Unregisters users from a tag. This command is only available for PAN-OS version 9.x and above.


#### Base Command

`panorama-unregister-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag from which to unregister users. | Required | 
| Users | A comma-separated list of users to unregister. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-list-rules
***
Returns a list of predefined Security Rules.


#### Base Command

`panorama-list-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | Rules location. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the rules. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | String | Rule name. | 
| Panorama.SecurityRule.Action | String | Action for the rule. | 
| Panorama.SecurityRule.Location | String | Rule location. | 
| Panorama.SecurityRule.Category | String | Rule category. | 
| Panorama.SecurityRule.Application | String | Application for the rule. | 
| Panorama.SecurityRule.Destination | String | Destination address. | 
| Panorama.SecurityRule.From | String | Rule from. | 
| Panorama.SecurityRule.Service | String | Service for the rule. | 
| Panorama.SecurityRule.To | String | Rule to. | 
| Panorama.SecurityRule.Source | String | Source address. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | Rule tags. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-query-logs
***
Query logs in Panorama.


#### Base Command

`panorama-query-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log-type | The log type. Can be "threat", "traffic", "wildfire", "url", or "data". Possible values are: threat, traffic, wildfire, url, data. | Required | 
| query | The query string by which to match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs. | Optional | 
| time-generated | The time that the log was generated from the timestamp and prior to it.<br/>e.g "2019/08/11 01:10:44". | Optional | 
| addr-src | Source address. | Optional | 
| addr-dst | Destination address. | Optional | 
| ip | Source or destination IP address. | Optional | 
| zone-src | Source zone. | Optional | 
| zone-dst | Destination Source. | Optional | 
| action | Rule action. | Optional | 
| port-dst | Destination port. | Optional | 
| rule | Rule name, e.g "Allow all outbound". | Optional | 
| url | URL, e.g "safebrowsing.googleapis.com". | Optional | 
| filedigest | File hash (for WildFire logs only). | Optional | 
| number_of_logs | Maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | Job ID of the logs query. | 
| Panorama.Monitor.Status | String | Status of the logs query. | 
| Panorama.Monitor.Message | String | Message of the logs query. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-check-logs-status
***
Checks the status of a logs query.


#### Base Command

`panorama-check-logs-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | Job ID of the logs query. | 
| Panorama.Monitor.Status | String | Status of the logs query. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-logs
***
Retrieves the data of a logs query.


#### Base Command

`panorama-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 
| ignore_auto_extract | Whether to auto-enrich the War Room entry. If "true", entry is not auto-enriched. If "false", entry is auto-extracted. Default is "true". Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.Logs.Action | String | Action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | 
| Panorama.Monitor.Logs.Application | String | Application associated with the session. | 
| Panorama.Monitor.Logs.Category | String | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware"’, or "benign". For other subtypes, the value is "any". | 
| Panorama.Monitor.Logs.DeviceName | String | The hostname of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.DestinationAddress | String | Original session destination IP address. | 
| Panorama.Monitor.Logs.DestinationUser | String | Username of the user to which the session was destined. | 
| Panorama.Monitor.Logs.DestinationCountry | String | Destination country or internal region for private addresses. Maximum length is 32 bytes. | 
| Panorama.Monitor.Logs.DestinationPort | String | Destination port utilized by the session. | 
| Panorama.Monitor.Logs.FileDigest | String | Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. | 
| Panorama.Monitor.Logs.FileName | String | File name or file type when the subtype is file.
File name when the subtype is virus.
File name when the subtype is wildfire-virus.
File name when the subtype is wildfire. | 
| Panorama.Monitor.Logs.FileType | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the type of file that the firewall forwarded for WildFire analysis. | 
| Panorama.Monitor.Logs.FromZone | String | The zone from which the session was sourced. | 
| Panorama.Monitor.Logs.URLOrFilename | String | The actual URL when the subtype is url.
File name or file type when the subtype is file.
File name when the subtype is virus.
File name when the subtype is wildfire-virus.
File name when the subtype is wildfire.
URL or file name when the subtype is vulnerability \(if applicable\). | 
| Panorama.Monitor.Logs.NATDestinationIP | String | If destination NAT performed, the post-NAT destination IP address. | 
| Panorama.Monitor.Logs.NATDestinationPort | String | Post-NAT destination port. | 
| Panorama.Monitor.Logs.NATSourceIP | String | If source NAT performed, the post-NAT source IP address. | 
| Panorama.Monitor.Logs.NATSourcePort | String | Post-NAT source port. | 
| Panorama.Monitor.Logs.PCAPid | String | The packet capture \(pcap\) ID is a 64 bit unsigned integral denoting
an ID to correlate threat pcap files with extended pcaps taken as a part of
that flow. All threat logs will contain either a pcap_id of 0 \(no associated
pcap\), or an ID referencing the extended pcap file. | 
| Panorama.Monitor.Logs.IPProtocol | String | IP protocol associated with the session. | 
| Panorama.Monitor.Logs.Recipient | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.Rule | String | Name of the rule that the session matched. | 
| Panorama.Monitor.Logs.RuleID | String | ID of the rule that the session matched. | 
| Panorama.Monitor.Logs.ReceiveTime | String | Time the log was received at the management plane. | 
| Panorama.Monitor.Logs.Sender | String | Only for the WildFire subtype; all other types do not use this field.
Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.SessionID | String | An internal numerical identifier applied to each session. | 
| Panorama.Monitor.Logs.DeviceSN | String | The serial number of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.Severity | String | Severity associated with the threat. Can be "informational", "low",
"medium", "high", or "critical". | 
| Panorama.Monitor.Logs.SourceAddress | String | Original session source IP address. | 
| Panorama.Monitor.Logs.SourceCountry | String | Source country or internal region for private addresses. Maximum
length is 32 bytes. | 
| Panorama.Monitor.Logs.SourceUser | String | Username of the user who initiated the session. | 
| Panorama.Monitor.Logs.SourcePort | String | Source port utilized by the session. | 
| Panorama.Monitor.Logs.ThreatCategory | String | Describes threat categories used to classify different types of
threat signatures. | 
| Panorama.Monitor.Logs.Name | String | Palo Alto Networks identifier for the threat. It is a description
string followed by a 64-bit numerical identifier | 
| Panorama.Monitor.Logs.ID | String | Palo Alto Networks ID for the threat. | 
| Panorama.Monitor.Logs.ToZone | String | The zone to which the session was destined. | 
| Panorama.Monitor.Logs.TimeGenerated | String | Time that the log was generated on the dataplane. | 
| Panorama.Monitor.Logs.URLCategoryList | String | A list of the URL filtering categories that the firewall used to
enforce the policy. | 
| Panorama.Monitor.Logs.Bytes | String | Total log bytes. | 
| Panorama.Monitor.Logs.BytesReceived | String | Log bytes received. | 
| Panorama.Monitor.Logs.BytesSent | String | Log bytes sent. | 
| Panorama.Monitor.Logs.Vsys | String | Vsys on the firewall that generated the log. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-security-policy-match
***
Checks whether a session matches a specified security policy. This command is only available on Firewall instances.


#### Base Command

`panorama-security-policy-match`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application | The application name. | Optional | 
| category | The category name. | Optional | 
| destination | The destination IP address. | Required | 
| destination-port | The destination port. | Optional | 
| from | The from zone. | Optional | 
| to | The to zone. | Optional | 
| protocol | The IP protocol value. | Required | 
| source | The source IP address. | Required | 
| source-user | The source user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityPolicyMatch.Query | String | Query for the session to test. | 
| Panorama.SecurityPolicyMatch.Rules.Name | String | The matching rule name. | 
| Panorama.SecurityPolicyMatch.Rules.Action | String | The matching rule action. | 
| Panorama.SecurityPolicyMatch.Rules.Category | String | The matching rule category. | 
| Panorama.SecurityPolicyMatch.Rules.Destination | String | The matching rule destination. | 
| Panorama.SecurityPolicyMatch.Rules.From | String | The matching rule from zone. | 
| Panorama.SecurityPolicyMatch.Rules.Source | String | The matching rule source. | 
| Panorama.SecurityPolicyMatch.Rules.To | String | The matching rule to zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.Application | String | The application name. | 
| Panorama.SecurityPolicyMatch.QueryFields.Category | String | The category name. | 
| Panorama.SecurityPolicyMatch.QueryFields.Destination | String | The destination IP address. | 
| Panorama.SecurityPolicyMatch.QueryFields.DestinationPort | Number | The destination port. | 
| Panorama.SecurityPolicyMatch.QueryFields.From | String | The query fields from zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.To | String | The query fields to zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.Protocol | String | The IP protocol value. | 
| Panorama.SecurityPolicyMatch.QueryFields.Source | String | The destination IP address. | 
| Panorama.SecurityPolicyMatch.QueryFields.SourceUser | String | The source user. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-list-static-routes
***
Lists the static routes of a virtual router.


#### Base Command

`panorama-list-static-routes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | The name of the virtual router for which to list the static routes. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 
| show_uncommitted | Whether to show an uncommitted configuration. Default is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of a static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Uncommitted | Boolean | Whether the static route is committed. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-static-route
***
Returns the specified static route of a virtual router.


#### Base Command

`panorama-get-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | Name of the virtual router for which to display the static route. | Required | 
| static_route | Name of the static route to display. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-add-static-route
***
Adds a static route.


#### Base Command

`panorama-add-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | Virtual router to which the routes will be added. | Required | 
| static_route | The name of the static route to add. The argument is limited to a maximum of 31 characters, is case-sensitive, and supports letters, numbers, spaces, hyphens, and underscores. | Required | 
| destination | The IP address and network mask in Classless Inter-domain Routing (CIDR) notation: ip_address/mask. For example, 192.168.0.1/24 for IPv4 or 2001:db8::/32 for IPv6). | Required | 
| nexthop_type | The type for the next hop. Can be: "ip-address", "next-vr", "fqdn", or "discard". Possible values are: ip-address, next-vr, fqdn, discard. | Required | 
| nexthop_value | The next hop value. | Required | 
| metric | The metric port for the static route (1-65535). | Optional | 
| interface | The interface name in which to add the static route. | Optional | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-delete-static-route
***
Deletes a static route.


#### Base Command

`panorama-delete-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| route_name | The name of the static route to delete. | Required | 
| virtual_router | The virtual router from which the routes will be deleted. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route to delete. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Deleted | Boolean | Whether the static route was deleted. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-show-device-version
***
Show firewall device software version.


#### Base Command

`panorama-show-device-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Serial number of the target device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Device.Info.Devicename | String | Device name of the PAN-OS. | 
| Panorama.Device.Info.Model | String | Model of the PAN-OS. | 
| Panorama.Device.Info.Serial | String | Serial number of the PAN-OS. | 
| Panorama.Device.Info.Version | String | Version of the PAN-OS. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-download-latest-content-update
***
Downloads the latest content update.


#### Base Command

`panorama-download-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which to download the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | Job ID of the content download. | 
| Panorama.Content.Download.Status | String | Content download status. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-content-update-download-status
***
Checks the download status of a content update.


#### Base Command

`panorama-content-update-download-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which the content update is downloading. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | Job ID to monitor. | 
| Panorama.Content.Download.Status | String | Download status. | 
| Panorama.Content.Download.Details | String | Job ID details. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-install-latest-content-update
***
Installs the latest content update.


#### Base Command

`panorama-install-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to install the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | Job ID of the installation. | 
| Content.Install.Status | String | Installation status. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-content-update-install-status
***
Gets the installation status of the content update.


#### Base Command

`panorama-content-update-install-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to check the installation status of the content update. | Optional | 
| job_id | Job ID of the content installation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | Job ID of the content installation. | 
| Panorama.Content.Install.Status | String | Content installation status. | 
| Panorama.Content.Install.Details | String | Content installation status details. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-check-latest-panos-software
***
Checks the PAN-OS software version from the repository.


#### Base Command

`panorama-check-latest-panos-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the PAN-OS software version. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-download-panos-version
***
Downloads the target PAN-OS software version to install on the target device.


#### Base Command

`panorama-download-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to download the PAN-OS software version. | Optional | 
| target_version | The target version number to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | number | Job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | Status of the PAN-OS download. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-download-panos-status
***
Gets the download status of the target PAN-OS software.


#### Base Command

`panorama-download-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the download status. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | string | Job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | PAN-OS download status. | 
| Panorama.PANOS.Download.Details | String | PAN-OS download details. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-install-panos-version
***
Installs the target PAN-OS version on the specified target device.


#### Base Command

`panorama-install-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device on which to install the target PAN-OS software version. | Optional | 
| target_version | Target PAN-OS version to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | string | Job ID of the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | Status of the PAN-OS installation. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-install-panos-status
***
Gets the installation status of the PAN-OS software.


#### Base Command

`panorama-install-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the installation status. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | number | Job ID of the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | Status of the PAN-OS installation. | 
| Panorama.PANOS.Install.Details | String | PAN-OS installation details. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-device-reboot
***
Reboots the Firewall device.


#### Base Command

`panorama-device-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device on which to reboot the firewall. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-show-location-ip
***
Gets location information for an IP address.


#### Base Command

`panorama-show-location-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address from which to return information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Location.IP.country_code | String | The IP address location country code. | 
| Panorama.Location.IP.country_name | String | The IP address location country name. | 
| Panorama.Location.IP.ip_address | String | The IP address. | 
| Panorama.Location.IP.Status | String | Whether the IP address was found. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-licenses
***
Gets information about available PAN-OS licenses and their statuses.


#### Base Command

`panorama-get-licenses`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.License.Authcode | String | The authentication code of the license. | 
| Panorama.License.Base-license-name | String | The base license name. | 
| Panorama.License.Description | String | The description of the license. | 
| Panorama.License.Expired | String | Whether the license has expired. | 
| Panorama.License.Expires | String | When the license will expire. | 
| Panorama.License.Feature | String | The feature of the license. | 
| Panorama.License.Issued | String | When the license was issued. | 
| Panorama.License.Serial | String | The serial number of the license. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-security-profiles
***
Gets information for the specified security profile.


#### Base Command

`panorama-get-security-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_profile | The security profile for which to get information. Can be "data-filtering", "file-blocking", "spyware", "url-filtering", "virus", "vulnerability", or "wildfire-analysis". Possible values are: data-filtering, file-blocking, spyware, url-filtering, virus, vulnerability, wildfire-analysis. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.Name | String | The profile name. | 
| Panorama.Spyware.Rules.Action | String | The rule action. | 
| Panorama.Spyware.Rules.Category | String | The category for which to apply the rule. | 
| Panorama.Spyware.Rules.Name | String | The rule name. | 
| Panorama.Spyware.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.Rules.Severity | String | The rule severity. | 
| Panorama.Spyware.Rules.Threat-name | String | The threat name for which to apply the rule. | 
| Panorama.URLFilter.Name | String | The profile name. | 
| Panorama.URLFilter.Rules.Category.Action | String | The rule action to apply to the category. | 
| Panorama.URLFilter.Rules.Category.Name | String | The category name. | 
| Panorama.WildFire.Name | String | The WildFire profile name. | 
| Panorama.WildFire.Rules.Analysis | String | The rule analysis. | 
| Panorama.WildFire.Rules.Application | String | The application for which to apply the rule. | 
| Panorama.WildFire.Rules.File-type | String | The file type for which to apply the rule. | 
| Panorama.WildFire.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Name | String | The vulnerability profile name. | 
| Panorama.Vulnerability.Rules.Vendor-id | String | The vendor ID for which to apply the rule. | 
| Panorama.Vulnerability.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Vulnerability.Rules.Host | String | The rule host. | 
| Panorama.Vulnerability.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Rules.Category | String | The category for which to apply the rule. | 
| Panorama.Vulnerability.Rules.CVE | String | The CVE for which to apply the rule. | 
| Panorama.Vulnerability.Rules.Action | String | The rule action. | 
| Panorama.Vulnerability.Rules.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rules.Threat-name | String | The threat for which to apply the rule. | 
| Panorama.Antivirus.Name | String | The Antivirus profile name. | 
| Panorama.Antivirus.Rules.Action | String | The rule action. | 
| Panorama.Antivirus.Rules.Name | String | The rule name. | 
| Panorama.Antivirus.Rules.WildFire-action | String | The WildFire action. | 
| Panorama.FileBlocking.Name | String | The file blocking profile name. | 
| Panorama.FileBlocking.Rules.Action | String | The rule action. | 
| Panorama.FileBlocking.Rules.Application | String | The application for which to apply the rule. | 
| Panorama.FileBlocking.Rules.File-type | String | The file type to apply the rule. | 
| Panorama.FileBlocking.Rules.Name | String | The rule name. | 
| Panorama.DataFiltering.Name | String | The data filtering profile name. | 
| Panorama.DataFiltering.Rules.Alert-threshold | String | The alert threshold. | 
| Panorama.DataFiltering.Rules.Application | String | The application to apply the rule. | 
| Panorama.DataFiltering.Rules.Block-threshold | String | The block threshold. | 
| Panorama.DataFiltering.Rules.Data-object | String | The data object. | 
| Panorama.DataFiltering.Rules.Direction | String | The rule direction. | 
| Panorama.DataFiltering.Rules.File-type | String | The file type for which to apply the rule. | 
| Panorama.DataFiltering.Rules.Log-severity | String | The log severity. | 
| Panorama.DataFiltering.Rules.Name | String | The rule name. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-apply-security-profile
***
Apply a security profile to specific rules or rules with a specific tag.


#### Base Command

`panorama-apply-security-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_type | Security profile type. Can be 'data-filtering', 'file-blocking', 'spyware', 'url-filtering', 'virus, 'vulnerability', or wildfire-analysis.'. Possible values are: data-filtering, file-blocking, spyware, url-filtering, virus, vulnerability, wildfire-analysis. | Required | 
| rule_name | The rule name to apply. | Required | 
| profile_name | The profile name to apply to the rule. | Required | 
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-get-ssl-decryption-rules
***
Get SSL decryption rules.


#### Base Command

`panorama-get-ssl-decryption-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SSLRule.From | String | The SSL rule from the source. | 
| Panorama.SSLRule.Name | String | The name of the SSL rule. | 
| Panorama.SSLRule.Destination | String | The destination of the SSL rule. | 
| Panorama.SSLRule.Target | String | The target of the SSL rule. | 
| Panorama.SSLRule.Service | String | The SSL rule service. | 
| Panorama.SSLRule.Action | String | The SSL rule action. | 
| Panorama.SSLRule.Type | String | The SSL rule type. | 
| Panorama.SSLRule.Source | String | The source of the SSL rule. | 
| Panorama.SSLRule.To | String | The SSL rule to destination. | 
| Panorama.SSLRule.UUID | String | The SSL rule UUID. | 
| Panorama.SSLRule.Description | String | The SSL rule description. | 
| Panorama.SSLRule.Source-user | String | The SSL rule source user. | 
| Panorama.SSLRule.Category | String | The SSL rule category. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-wildfire-configuration
***
Retrieves the Wildfire configuration.


#### Base Command

`panorama-get-wildfire-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.WildFire.Name | String | The file type. | 
| Panorama.WildFire.Size-limit | String | The file size limit. | 
| Panorama.WildFire.recurring | String | The schedule that is recurring. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-url-filtering-block-default-categories
***
Set default categories to block in the URL filtering profile.


#### Base Command

`panorama-url-filtering-block-default-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The url-filtering profile name. Get the name by running the get-security-profiles command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-get-anti-spyware-best-practice
***
Get anti-spyware best practices.


#### Base Command

`panorama-get-anti-spyware-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.BotentDomain.Name | String | The botnet domain name. | 
| Panorama.Spyware.BotentDomain.Action | String | The botnet domain action. | 
| Panorama.Spyware.BotentDomain.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv4-address | String | The botnet domain IPv4 address. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv6-address | String | The Botnet domain IPv6 address. | 
| Panorama.Spyware.Rule.Category | String | The rule category. | 
| Panorama.Spyware.Rule.Action | String | The rule action. | 
| Panorama.Spyware.Rule.Name | String | The rule name. | 
| Panorama.Spyware.Rule.Severity | String | The rule severity. | 
| Panorama.Spyware.Rule.Threat-name | String | The rule threat name. | 
| Panorama.Spyware.BotentDomain.Max_version | String | The botnet domain max version. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-file-blocking-best-practice
***
Get file-blocking best practices.


#### Base Command

`panorama-get-file-blocking-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.FileBlocking.Rule.Action | String | The rule action. | 
| Panorama.FileBlocking.Rule.Application | String | The rule application. | 
| Panorama.FileBlocking.Rule.File-type | String | The rule file type. | 
| Panorama.FileBlocking.Rule.Name | String | The rule name. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-antivirus-best-practice
***
Get anti-virus best practices.


#### Base Command

`panorama-get-antivirus-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Antivirus.Decoder.Action | String | The rule action. | 
| Panorama.Antivirus.Decoder.Name | String | The rule name. | 
| Panorama.Antivirus.Decoder.WildFire-action | String | The WildFire action. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-vulnerability-protection-best-practice
***
Get vulnerability-protection best practices.


#### Base Command

`panorama-get-vulnerability-protection-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.Rule.Action | String | The rule action. | 
| Panorama.Vulnerability.Rule.CVE | String | The rule CVE. | 
| Panorama.Vulnerability.Rule.Category | String | The rule category. | 
| Panorama.Vulnerability.Rule.Host | String | The rule host. | 
| Panorama.Vulnerability.Rule.Name | String | The rule name. | 
| Panorama.Vulnerability.Rule.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rule.Threat-name | String | The threat name. | 
| Panorama.Vulnerability.Rule.Vendor-id | String | The vendor ID. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-wildfire-best-practice
***
View WildFire best practices.


#### Base Command

`panorama-get-wildfire-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.WildFire.Analysis | String | The WildFire analysis. | 
| Panorama.WildFire.Application | String | The WildFire application. | 
| Panorama.WildFire.File.File-size | String | The recommended file size. | 
| Panorama.WildFire.File.Name | String | The file name. | 
| Panorama.WildFire.File-type | String | The WildFire profile file type. | 
| Panorama.WildFire.Name | String | The WildFire profile name. | 
| Panorama.WildFire.SSLDecrypt | String | The SSL decrypt content. | 
| Panorama.WildFire.Schedule.Action | String | The WildFire schedule action. | 
| Panorama.WildFire.Schedule.Recurring | String | The WildFire schedule recurring. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-get-url-filtering-best-practice
***
View URL filtering best practices.


#### Base Command

`panorama-get-url-filtering-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Category.Action | String | The action to perform on the category. | 
| Panorama.URLFilter.Category.Name | String | The category name. | 
| Panorama.URLFilter.DeviceGroup | String | The device group name. | 
| Panorama.URLFilter.Name | String | The Profile name. | 
| Panorama.URLFilter.Header.log-container-page-only | String | The log container page only. | 
| Panorama.URLFilter.Header.log-http-hdr-referer | String | The log HTTP header referer. | 
| Panorama.URLFilter.Header.log-http-hdr-user | String | The log HTTP header user. | 
| Panorama.URLFilter.Header.log-http-hdr-xff | String | The log HTTP header xff. | 


#### Command Example
``` ```

#### Human Readable Output



### panorama-enforce-wildfire-best-practice
***
Enforces wildfire best practices to upload files to the maximum size, forwards all file types, and updates the schedule.


#### Base Command

`panorama-enforce-wildfire-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-antivirus-best-practice-profile
***
Creates an antivirus best practice profile.


#### Base Command

`panorama-create-antivirus-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-anti-spyware-best-practice-profile
***
Creates an Anti-Spyware best practice profile.


#### Base Command

`panorama-create-anti-spyware-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-vulnerability-best-practice-profile
***
Creates a vulnerability protection best practice profile.


#### Base Command

`panorama-create-vulnerability-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-url-filtering-best-practice-profile
***
Creates a URL filtering best practice profile.


#### Base Command

`panorama-create-url-filtering-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-file-blocking-best-practice-profile
***
Creates a file blocking best practice profile.


#### Base Command

`panorama-create-file-blocking-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-create-wildfire-best-practice-profile
***
Creates a WildFire analysis best practice profile.


#### Base Command

`panorama-create-wildfire-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-upload-content-update-file
***
Uploads content file to Panorama


#### Base Command

`panorama-upload-content-update-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry id of the file to upload. | Required | 
| category | The file type. Possible values are: wildfire, anti-virus, content. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### panorama-install-file-content-update
***
Installs specific content update file.


#### Base Command

`panorama-install-file-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version_name | Update file name to be installed on Panorama. | Required | 
| category | The file type. Possible values are: wildfire, anti-virus, content. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | string | JobID of the installation. | 
| Content.Install.Status | string | Installation status. | 


#### Command Example
``` ```

#### Human Readable Output


