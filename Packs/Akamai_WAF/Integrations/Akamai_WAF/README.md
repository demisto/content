Manage a common set of lists for use in various Akamai security products such as Kona Site Defender, Web App Protector,
and Bot Manager. This integration was integrated and tested with [Network Lists API v2.0](https://developer.akamai.com/api/cloud_security/network_lists/v2.html)

##  Playbooks

* Akamai WAF Network list activate generic polling.

## Use Cases

*   Get network list details - activations status, elements etc
*   Create or remove network lists.
*   Network list editing - add or remove elements.
*   Network list activation.

## Detailed Description

The Akamai WAF integration allows you to manage a common set of lists for use in various Akamai security products such as Kona Site Defender, Web App Protector, and Bot Manager. Network lists are shared sets of IP addresses, CIDR blocks, or broad geographic areas. Along with managing your own lists, you can also access read-only lists that Akamai dynamically updates for you.

## API keys generating steps

1.  [Open Control panel](https://control.akamai.com/) and login with admin account.
2.  Open `identity and access management` menu.
3.  Create `new api client for me`
4.  Assign API key to the relevant users group, and assign on next page `Read/Write` access for `Network Lists`.
5.  Save configuration and go to API detail you created.
6. Press `new credentials` and download or copy it.
7. Now use the credentials for configure Akamai WAF in Cortex XSOAR

## Configure Akamai WAF on Cortex XSOAR

1.  Navigate to **Settings** > **Integrations**  > **Servers & Services**.
2.  Search for Akamai WAF.
3.  Click **Add instance** to create and configure a new integration instance.
    *   **Name**: a textual name for the integration instance.
    *   **Server URL (e.g., https://example.net)**
    *   **Client token**
    *   **Access token**
    *   **Client secret**
    *   **Trust any certificate (not secure)**
    *   **Use system proxy settings**
4.  Click **Test** to validate the new instance.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Returns a list of all network lists available for an authenticated user who belongs to a group: [akamai-get-network-lists](#akamai-get-network-lists)
2.  Gets a network list by the network list ID: [akamai-get-network-list-by-id](###akamai-get-network-lists)
3.  Creates a new network list. Supports TXT file upload for elements: [akamai-create-network-list](###akamai-create-network-list)
4.  Deletes the specified network list: [akamai-delete-network-list](###akamai-delete-network-list)
5.  Activates a network list on the specified environment: [akamai-activate-network-list](###akamai-activate-network-list)
6.  Adds elements to the specified network list: [akamai-add-elements-to-network-list](###akamai-add-elements-to-network-list)
7.  Removes elements from the specified network list: [akamai-remove-element-from-network-list](###akamai-remove-element-from-network-list)
8.  Production or staging:[Get network list activation status in akamai-get-network-list-activation-status](###akamai-get-network-list-activation-status)

* * *

### akamai-get-network-lists

Returns a list of all network lists available for an authenticated user who belongs to a group.

##### Base Command

`akamai-get-network-lists`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|list_type|The network list type by which to filter the results. Can be "IP" or "GEO".|Optional|
|search|The query by which to search for list names and list items.|Optional|
|extended|When enabled, provides additional response data identifying who created and updated the list and when, and the network list’s deployment status in both STAGING and PRODUCTION environments. This data takes longer to provide. Possible values are: true, false. Default is true.|Optional|
|include_elements|If enabled, the response list includes all items. For large network lists, this may slow responses and yield large response objects. The default false value when listing more than one network list omits the network list’s elements and only provides higher-level metadata. Possible values are: true, false. Default is true.|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. |
| Akamai.NetworkLists.Lists.Type | String | The network list type. |
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. |
| Akamai.NetworkLists.Lists.ElementCount | String | The network list elements count. |
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. |
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. |
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. |
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. |
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. |
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. |
| Akamai.NetworkLists.Lists.UpdateDate | String | The date that the network list was updated. |
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user that updated the network list. |
| Akamai.NetworkLists.Lists.Elements | String | The number of elements in the list. |

##### Command Example

`!akamai-get-network-lists` 

`!akamai-get-network-lists type=IP search="192.168.0.1"`

 `!akamai-get-network-lists type=GEO search=IL`

##### Context Example

```
{
    "Akamai":{
        "NetworkLists":{ 
        	"Lists": [
              {
                  "CreatedBy": "user",
                  "ElementCount": 2,
                  "Elements": [
                      "8.8.8.8",
                      "8.8.8.8"
                  ],
                  "ExpeditedProductionActivationStatus": "INACTIVE",
                  "ExpeditedStagingActivationStatus": "INACTIVE",
                  "Name": "Test",
                  "ProductionActivationStatus": "PENDING_ACTIVATION",
                  "StagingActivationStatus": "INACTIVE",
                  "Type": "IP",
                  "UniqueID": "uniq_id",
                  "UpdateDate": "2020-01-13T18:57:05.99Z",
                  "UpdatedBy": "user"
              },
              {
                  "CreatedBy": "akamai",
                  "ElementCount": 18,
                  "Elements": [
                      "iq",
                      "mm",
                      "ir",
                      "ye",
                      "so",
                      "sd"
                  ],
                  "ExpeditedProductionActivationStatus": "INACTIVE",
                  "ExpeditedStagingActivationStatus": "INACTIVE",
                  "Name": "Test",
                  "ProductionActivationStatus": "PENDING_ACTIVATION",
                  "StagingActivationStatus": "INACTIVE",
                  "Type": "IP",
                  "UniqueID": "uniq_id",
                  "UpdateDate": "2020-01-13T18:57:05.99Z",
                  "UpdatedBy": "user"
              }
          ]
       }
    }
}
```

##### Human Readable Output

### Akamai WAF - network lists

|**Element count**|**Name**|**The production Activation Status**|**The staging Activation Status**|**Type**|**Unique ID**|**Updated by**|
|--- |--- |--- |--- |--- |--- |--- |
|2|Test|PENDING_ACTIVATION|INACTIVE|IP|uniqe_id|user|
|1|test|INACTIVE|INACTIVE|IP|uniqe_id|user|

* * *

### akamai-get-network-list-by-id

Gets a network list by the network list ID.

##### Base Command

`akamai-get-network-list-by-id`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_id|The network list ID|Required|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. |
| Akamai.NetworkLists.Lists.Type | String | The network list type. |
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. |
| Akamai.NetworkLists.Lists.ElementCount | String | The network list elements. |
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. |
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. |
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. |
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. |
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. |
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. |
| Akamai.NetworkLists.Lists.UpdateDate | String | The date that the network list was updated. |
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user that updated the network list. |
| Akamai.NetworkLists.Lists.Elements | String | The number of elements in the list. |


##### Command Example

`!akamai-get-network-list-by-id network_list_id=69988_TEST`

##### Context Example

```
{ 
	"Akamai": {
		"NetworkLists": {
			"Lists": [
            {
              "CreatedBy": "user",
              "ElementCount": 2,
              "Elements": [
              "8.8.8.8",
              "8.8.8.8"
              ],
              "ExpeditedProductionActivationStatus": "INACTIVE",
              "ExpeditedStagingActivationStatus": "INACTIVE",
              "Name": "Test",
              "ProductionActivationStatus": "PENDING_ACTIVATION",
              "StagingActivationStatus": "INACTIVE",
              "Type": "IP",
              "UniqueID": "unique_id",
              "UpdateDate": "2020-01-13T18:57:05.99Z",
              "UpdatedBy": "user"
            }
        ]    
    }
}
```

##### Human Readable Output

### Akamai WAF - network list 69988_TEST

|**Element count**|**Name**|**The production Activation Status**|**The staging Activation Status**|**Type**|**Unique ID**|**Updated by**|
|--- |--- |--- |--- |--- |--- |--- |
|2|Test|PENDING_ACTIVATION|INACTIVE|IP|uique_id|user|

* * *

### akamai-create-network-list

Creates a new network list. Supports TXT file upload for elements.

##### Base Command

`akamai-create-network-list`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|list_name|The network list name|Required|
|list_type|The network list type|Required|
|elements|The network list elements|Optional|
|entry_id|The War Room entry ID of the sample file.|Optional|
|description|The network list description|Optional|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. |
| Akamai.NetworkLists.Lists.UniqueID | String | The ID of the network list to create. |
| Akamai.NetworkLists.Lists.Type | String | The network list type. |
| Akamai.NetworkLists.Lists.ElementCount | Number | Number of element in the list. |
| Akamai.NetworkLists.Lists.Elements | String | Elements in the list. |

##### Command Example

`!akamai-create-network-list list_name=test list_type=IP description=test elements=8.8.8.8`

##### Context Example

```
{
    "Akamai": {
        "NetworkLists": [
            {
                "Elements": [
                    "8.8.8.8"
                ],
                "Name": "test",
                "Type": "IP",
                "UniqueID": "70548_TEST"
            }
        ]
    }
}
```

##### Human Readable Output

### Akamai WAF - network list test created successfully

|**Name**|**Type**|**Unique ID**|
|--- |--- |--- |
|test|IP|70548_TEST|

* * *

### akamai-delete-network-list

Deletes the specified network list.

##### Base Command

`akamai-delete-network-list`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_id|The ID of the network list to delete.|Required|


##### Context Output

There are no context output for this command.

##### Command Example

`!akamai-delete-network-list network_list_id=69856_NEW`

##### Context Example

```
{}
```

##### Human Readable Output

Akamai WAF - network list **69856_NEW** deleted.

* * *

### akamai-activate-network-list

Activates a network list on the specified environment.

##### Base Command

`akamai-activate-network-list`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_id|The ID of the network to activate-can be list of network lists|Required|
|env|The environment type to activate the network list. Can be "STAGING" OR 'PRODUCTION".|Required|
|comment|A comment to be logged.|Optional|
|notify|A comma-separated list of email addresses.|Optional|

##### Context Output

There are no context output for this command.

##### Command Example

`!akamai-activate-network-list network_list_id=69988_TEST,69989_TEST env=PRODUCTION comment=test`

##### Context Example

```
{}
```

##### Human Readable Output

Akamai WAF - network list **69988_TEST** activated on **PRODUCTION** successfully
Akamai WAF  - network list **69989_TEST** already active on **PRODUCTION**

* * *

### akamai-add-elements-to-network-list

Adds elements to the specified network list.

##### Base Command

`akamai-add-elements-to-network-list`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_id|The network list ID|Required|
|entry_id|The War Room entry ID of the sample file.|Optional|
|elements| A comma-separated list of elements to add to the network list.|Optional|


##### Context Output

There are no context output for this command.

##### Command Example

`!akamai-add-elements-to-network-list network_list_id=69988_TEST elements="8.8.8.8, 9.9.9.9"`

##### Context Example

```
{}
```

##### Human Readable Output

### Akamai WAF - elements added to network list 69988_TEST successfully

|**elements**|
|--- |
|8.8.8.8, 9.9.9.9|

* * *

### akamai-remove-element-from-network-list

Removes elements from the specified network list.

##### Base Command

`akamai-remove-element-from-network-list`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_id|The ID of the network list from which to remove elements.|Required|
|element|The element to remove from the network list.|Required|

##### Context Output

There are no context output for this command.

##### Command Example

`!akamai-remove-element-from-network-list network_list_id=69988_TEST element=8.8.8.8`

##### Context Example

```
{}
```

##### Human Readable Output

Akamai WAF - element **8.8.8.8** removed from network list **69988_TEST** successfully

* * *

### akamai-get-network-list-activation-status

Gets the activation status of the specified network list.

##### Base Command

`akamai-get-network-list-activation-status`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_ids|The ID of the network list for which to get the activation status - Accept list of network lists|Required|
|env|The environment type. Can be "PRODUCTION" or "STAGING".|Required|

##### Context Output

|**Path**|**Type**|**Description**|
| --- | --- | --- |
| Akamai.NetworkLists.ActivationStatus.UniqueID | String | The network list name. |
| Akamai.NetworkLists.ActivationStatus.StagingStatus | String | The network list environment activation status. |
| Akamai.NetworkLists.ActivationStatus.ProductionStatus | String | The network list environment. |

##### Command Example

`!akamai-get-network-list-activation-status network_list_id=69988_TEST env=PRODUCTION`

`!akamai-get-network-list-activation-status network_list_id=69988_TEST, 69989_TEST env=PRODUCTION`

##### Context Example

```
{
    "Akamai": {
        "NetworkLists": {
            "ActivationStatus": {
                "Status": "PENDING_ACTIVATION",
                "UniqueID": "69988_TEST"
            }
        }
    }
}
```

##### Human Readable Output

Akamai WAF - network list **69988_TEST** is **PENDING_ACTIVATION** in **PRODUCTION**
Akamai WAF - network list **69989_TEST** canot be found
### akamai-update-network-list-elements
***
Updates list elements of a network list


#### Base Command

`akamai-update-network-list-elements`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list to update. | Required | 
| elements | Comma separated list of elements. Use BLANK to empty a list. | Required | 


#### Context Output

There is no context output for this command.
### akamai-check-group
***
Check exist group within the context of your account.


#### Base Command

`akamai-check-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checking_group_name | Group Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.CheckGroup | unknown | Group ID | 
| Akamai.CheckGroup.Found | unknown | Found or not - Bool | 
| Akamai.CheckGroup.groupName | unknown | groupName | 
| Akamai.CheckGroup.parentGroupId | unknown | parentGroupId | 
| Akamai.CheckGroup.groupId | unknown | groupId | 
| Akamai.CheckGroup.checking_group_name | unknown | INPUT checking_group_name | 
### akamai-create-group
***
Create a new group under a parent gid


#### Base Command

`akamai-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_path | group_path - split with &gt;. | Required | 


#### Context Output

There is no context output for this command.
### akamai-create-enrollment
***
Create a new enrollment


#### Base Command

`akamai-create-enrollment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| country | Country. Default is US. | Required | 
| company | Company. | Required | 
| organizational_unit | Organizational Unit. | Required | 
| city | City of Admin Contract. | Required | 
| contract_id | Contract ID. | Required | 
| certificate_type | Certificate Type. Default is third-party. | Optional | 
| csr_cn | Common Name. | Required | 
| admin_contact_address_line_one | Address of Admin Contact. | Required | 
| admin_contact_first_name | Firstname of Admin Contact. | Required | 
| admin_contact_last_name | Lastname of Admin Contact. | Required | 
| admin_contact_email | Email of Admin Contact. | Required | 
| admin_contact_phone | Phone of Admin Contact. | Required | 
| tech_contact_first_name | Fistname of Tech Contact. | Required | 
| tech_contact_last_name | Lastname of Tech Contact. | Required | 
| tech_contact_email | Email of Tech Contact. | Required | 
| tech_contact_phone | Phone of Tech Contact. | Required | 
| org_name | Orgnization name. | Required | 
| org_country | Orgnization Country. | Required | 
| org_city | Orgnization City. | Required | 
| org_region | Orgnization Region. | Required | 
| org_postal_code | Orgnization PostalCode. | Required | 
| org_phone | Orgnization Phone. | Required | 
| org_address_line_one | Orgnization Address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment | string | Enrollment_path | 
### akamai-list-enrollments
***
List enrollments of a specific contract


#### Base Command

`akamai-list-enrollments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 


#### Context Output

There is no context output for this command.
### akamai-create-domain
***
Create a domain with properties and DC


#### Base Command

`akamai-create-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | domainName. | Required | 
| group_id | Group ID. | Required | 


#### Context Output

There is no context output for this command.
### akamai-update-property
***
Update a property for a specific domain


#### Base Command

`akamai-update-property`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The domain Name that the new property is added to. | Required | 
| property_name | New property name. | Required | 
| property_type | property type. | Required | 
| static_type | "CNAME" or "A". | Optional | 
| static_server | static_server. | Optional | 
| server_1 | server_1. | Optional | 
| server_2 | server_2. | Optional | 
| weight_1 | weight_1. | Optional | 
| weight_2 | weight_2. | Optional | 


#### Context Output

There is no context output for this command.
### akamai-get-change
***
Get the cps code


#### Base Command

`akamai-get-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_path | Enrollment path. | Required | 
| allowed_input_type_param | . Default is third-party-csr. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Change | unknown | CSR | 
### akamai-update-change
***
Update the certs and trustchains


#### Base Command

`akamai-update-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_path | The path of the changed certificate. | Required | 
| allowed_input_type_param | third-party-cert-and-trust-chain. Default is third-party-cert-and-trust-chain. | Optional | 
| certificate | The updated certificate. | Optional | 
| trust_chain | The updated trust chain. | Optional | 


#### Context Output

There is no context output for this command.
### akamai-get-enrollment-by-cn
***
Get enrollment by CName


#### Base Command

`akamai-get-enrollment-by-cn`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| target_cn | CName. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment | unknown | Akamai.Get_Enrollment | 
| Akamai.Enrollment.target_cn | unknown | Target CName | 
### akamai-list-groups
***
Lists groups of Akamai


#### Base Command

`akamai-list-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Group | unknown | Akmai Group | 
### akamai-get-group
***
Get group


#### Base Command

`akamai-get-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID. Default is 0. | Required | 


#### Context Output

There is no context output for this command.
### akamai-get-domain
***
GET a specific GTM domain


#### Base Command

`akamai-get-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain Name to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Domain | unknown | Akamai Domain | 
### akamai-create-datacenter
***
Create datacenter


#### Base Command

`akamai-create-datacenter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain Name. | Required | 
| dc_name | DC Name. | Required | 
| dc_country |  Country Name. Default is US. | Optional | 


#### Context Output

There is no context output for this command.
### akamai-clone-papi-property
***
Clone a new papi property


#### Base Command

`akamai-clone-papi-property`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for specific Akamai product. | Required | 
| property_name | PAPI (Ion Standard) Property Name. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| property_id | PAPI (Ion Standard) Property ID. | Required | 
| version | Property Version. | Required | 
| check_existence_before_create | Continue execution if a Existing Record found without creating an new record. Default is yes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.PropertyName | unknown | PAPI \(Ion Standard\) Property Name | 
| Akamai.PapiProperty.PropertyId | unknown | PAPI \(Ion Standard\) Property ID | 
| Akamai.PapiProperty.AssetId | unknown | PAPI \(Ion Standard\) Property Asset ID | 
### akamai-add-papi-property-hostname
***
add hostnames to papi property


#### Base Command

`akamai-add-papi-property-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| property_version | PAPI (Ion Standard) Property Version. Default is 1. | Required | 
| property_id | PAPI (Ion Standard) Property ID. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| validate_hostnames | validate Hostnames. | Optional | 
| include_cert_status | include the certificate status for the hostname. | Optional | 
| cname_from | URL of Common Name. | Required | 
| edge_hostname_id | Edge Hostname Id. | Required | 
| sleep_time | Sleep time in seconds between each iteration. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | Etag for Concurrency control | 
### akamai-new-papi-edgehostname
***
add a papi Edge Hostname


#### Base Command

`akamai-new-papi-edgehostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for specific Akamai product. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| options | Comma-separated list of options to enable; mapDetails enables extra mapping-related information. | Optional | 
| domain_prefix | URL of Domain Name. | Required | 
| domain_suffix | URL of partial Domain Name append by Akamai. | Required | 
| ip_version_behavior | IP version, IPv4, IPv6 or IPv4 plus IPv6. | Required | 
| secure | SSL secured URL. | Optional | 
| secure_network | SSL secured protocol options. | Optional | 
| cert_enrollment_id | Certificate EnrollmentID for the Domain URL. | Optional | 
| check_existence_before_create | Continue execution if a Existing Record found without creating an new record. Default is yes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.EdgeHostnames.EdgeHostnameId | unknown | Edge Hostname ID | 
| Akamai.PapiProperty.EdgeHostnames.DomainPrefix | unknown | Edge Hostname Domain Prefex URL | 
### akamai-get-cps-enrollmentid-by-cnname
***
get cps certificate enrollmentID by common name


#### Base Command

`akamai-get-cps-enrollmentid-by-cnname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| cnname | URL of Common Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Cps.Enrollment.EnrollmentId | unknown | Certificate Enrollment ID | 
| Akamai.Cps.Enrollment.CN | unknown | Certificate Enrollment Common Name | 
### akamai-new-papi-cpcode
***
create a new papi cpcode


#### Base Command

`akamai-new-papi-cpcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for specific Akamai product. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| cpcode_name | Content Provider codes Name. | Required | 
| check_existence_before_create | Continue execution if a Existing Record found without creating an new record. Default is yes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiCpcode.CpcodeId | unknown | Content Provider Code ID | 
### akamai-patch-papi-property-rule-cpcode
***
patch papi property default rule with a cpcode


#### Base Command

`akamai-patch-papi-property-rule-cpcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| property_id | PAPI (Ion Standard) Property ID. | Required | 
| property_version | PAPI (Ion Standard) Property Version. | Optional | 
| validate_rules | Whether to validate the Rules. | Optional | 
| operation | Json Patch Operation. Add, Remove, Replace. | Optional | 
| path | Dictionary Path. | Optional | 
| cpcode_id | Content Provider Code ID. | Optional | 
| name | Content Provider Code Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | Etag for Concurrency Control | 
### akamai-patch-papi-property-rule-origin
***
patch papi property default rule with a origin


#### Base Command

`akamai-patch-papi-property-rule-origin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| property_id | PAPI (Ion Standard) Property ID. | Required | 
| property_version | PAPI (Ion Standard) Property Version. | Required | 
| validate_rules | Whether to validate the Rules. | Required | 
| operation | Json Patch Operation. Add, Remove, Replace. | Required | 
| path | Dictionary Path. | Required | 
| origin | value. | Required | 
| external_url | External URL FQDN. | Required | 
| gzip_compression | Gzip Compression. | Optional | 
| sleep_time | sleep time between each iteration. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | Etag for Concurrency Control | 
### akamai-activate-papi-property
***
activate a papi property


#### Base Command

`akamai-activate-papi-property`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration Group ID. | Required | 
| property_id | PAPI (Ion Standard) Property ID. | Required | 
| network | STAGING or PRODUCTION. | Optional | 
| notify_emails | Notification Emails. | Optional | 
| property_version | PAPI (Ion Standard) Property Verseion. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Staging.ActivationId | unknown | Staging Activation ID | 
| Akamai.PapiProperty.Production.ActivationId | unknown | Production Activation ID | 
### akamai-clone-security-policy
***
AppSec_clone security policy


#### Base Command

`akamai-clone-security-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec Configration ID. | Required | 
| config_version | AppSec Configration Version. | Required | 
| create_from_security_policy | Baseline Security Policy ID. | Required | 
| policy_name | New Security Policy Name. | Required | 
| policy_prefix | Security Policy ID Prefix. | Optional | 
| check_existence_before_create | Continue execution if a Existing Record found without creating an new record. Default is yes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security Policy Name | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Security Policy ID | 
### akamai-new-match-target
***
AppSec_create match target


#### Base Command

`akamai-new-match-target`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec Configration ID. | Required | 
| config_version | AppSec Configration Version. | Required | 
| policy_id | Security Policy ID. | Required | 
| match_type | Website. | Required | 
| hostnames | list of hostnames URL, split in comma. | Required | 
| bypass_network_lists | List of BypassNetwork, split in comma. | Required | 
| file_paths | default is /*. | Required | 
| default_file | default is noMatch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security Policy Name | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Security Policy ID | 
| Akamai.AppSecConfig.Policy.TargetId | unknown | Match Target ID | 
### akamai-activate-appsec-config-version
***
AppSec_activate appsec config version


#### Base Command

`akamai-activate-appsec-config-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec Configration ID. | Required | 
| config_version | AppSec Configration Version. | Required | 
| acknowledged_invalid_hosts | default is N/A. | Required | 
| notification_emails | List of Notification Emails. | Required | 
| action | Activate. | Required | 
| network | STAGING or PRODUCTION. | Required | 
| note | note to describe the activity. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Staging.ActivationId | unknown | Security Configration Staging Activation ID | 
| Akamai.AppSecConfig.Production.ActivationId | unknown | Security Configration Production Activation ID | 
### akamai-get-appsec-config-activation-status
***
AppSec_get appsec config activation status


#### Base Command

`akamai-get-appsec-config-activation-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activation_id | Security Configration Activation ID. | Required | 
| sleep_time | Number of seconds to wait before the next consistency check. | Required | 
| retries | Number of retries of the consistency check to be conducted. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Staging | unknown | Staging Security Configration | 
| Akamai.AppSecConfig.Production | unknown | Production Security Configration | 
### akamai-get-appsec-config-latest-version
***
AppSec_get appsec config latest version


#### Base Command

`akamai-get-appsec-config-latest-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sec_config_name | Name of the Security Configuration. | Required | 
| sleep_time | Number of seconds to wait before the next consistency check. | Required | 
| retries | Number of retries of the consistency check to be conducted. | Required | 
| skip_consistency_check | Do not conduction LatestVersion, Staging Version, Production Version consistency check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.LatestVersion | unknown | Security Configuration Latest Version Number | 
### akamai-get-security-policy-id-by-name
***
AppSec_get security policy id by name


#### Base Command

`akamai-get-security-policy-id-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Security Policy Name. | Required | 
| config_id | AppSec Configration ID. | Required | 
| config_version | AppSec Configration Version. | Required | 
| is_baseline_policy | is Baseline Security Policy or Not. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.BasePolicyName | unknown | Baseline Security Policy Name | 
| Akamai.AppSecConfig.BasePolicyId | unknown | Baseline Security Policy Id | 
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security Policy Name | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Baseline Security Policy Id | 
| Akamai.AppSecConfig.Id | unknown | AppSec Security Configuration Id | 
### akamai-clone-appsec-config-version
***
AppSec_clone appsec config version


#### Base Command

`akamai-clone-appsec-config-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec Configration ID. | Required | 
| create_from_version | AppSec Configration Version. | Required | 
| do_not_clone | Do not clone to create a new version, use in the test. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Name | unknown | AppSec Configration Version | 
| Akamai.AppSecConfig.Id | unknown | AppSec Configration ID | 
| Akamai.AppSecConfig.NewVersion | unknown | AppSec Configration New Version | 
### akamai-patch-papi-property-rule-httpmethods
***
patch papi property rule http methods


#### Base Command

`akamai-patch-papi-property-rule-httpmethods`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Group ID. | Required | 
| property_id | Property ID. | Required | 
| property_version | Property Version. | Optional | 
| validate_rules | Whether to validate the Rules. | Required | 
| operation | The operation to execute. | Required | 
| path | The path of the rule. | Required | 
| value | . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | Etag for Concurrency Control | 
### akamai-get-papi-property-activation-status-command
***
get papi property activation status until it is active


#### Base Command

`akamai-get-papi-property-activation-status-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activation_id | Ion Property Activation ID. | Required | 
| property_id | Ion Property ID. | Required | 
| sleep_time | Sleep time in between reties. | Required | 
| retries | number of retires. | Required | 


#### Context Output

There is no context output for this command.
### akamai-get-papi-edgehostname-creation-status-command
***
get papi edgehostname creation status command until it is created


#### Base Command

`akamai-get-papi-edgehostname-creation-status-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Group ID. | Required | 
| edgehostname_id | Edgehostname ID. | Required | 
| options | options - mapDetails. | Required | 
| sleep_time | Sleep time between iterations. | Required | 
| retries | number of retries. | Required | 


#### Context Output

There is no context output for this command.
### akamai-acknowledge-warning-command
***
Acknowledge the warning message for uploading the certs and trust chains of enrollments.


#### Base Command

`akamai-acknowledge-warning-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_path | The path of the changed certificate. | Required | 


#### Context Output

There is no context output for this command.
### akamai-get-domains
***
Get GTM domains


#### Base Command

`akamai-get-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Domain | unknown | Akamai Domain | 
