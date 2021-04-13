Manage a common set of lists for use in various Akamai security products such as Kona Site Defender, Web App Protector,
and Bot Manager. This integration was integrated and tested with [Network Lists API v2.0](https://developer.akamai.com/api/cloud_security/network_lists/v2.html)

##  Playbooks

* Akamai WAF Network list activate generic polling

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
7. Now use the credentials for configure Akamai WAF in Demisto

## Configure Akamai WAF on Demisto

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

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Returns a list of all network lists available for an authenticated user who belongs to a group: [akamai-get-network-lists](#akamai-get-network-lists)
2.  Gets a network list by the network list ID: [akamai-get-network-list-by-id](###akamai-get-network-lists)
3.  Creates a new network list. Supports TXT file upload for elements: [akamai-create-network-list](###akamai-create-network-list)
4.  Deletes the specified network list: [akamai-delete-network-list](###akamai-delete-network-list)
5.  Activates a network list on the specified environment: [akamai-activate-network-list](###akamai-activate-network-list)
6.  Adds elements to the specified network list: [akamai-add-elements-to-network-list](###akamai-add-elements-to-network-list)
7.  Removes elements from the specified network list: [akamai-remove-element-from-network-list](###akamai-remove-element-from-network-list)
8.  Production or staging:[Get network list activation status in akamai-get-network-list-activation-status](###akamai-get-network-list-activation-status)

* * *

1. ### akamai-get-network-lists

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
|Akamai.NetworkLists.Name|String|The network list name.|
|Akamai.NetworkLists.Type|String|The network list type.|
|Akamai.NetworkLists.UniqueID|String|The network list unique ID.|
|Akamai.NetworkLists.ElementCount|String|The network list elements coun.t|
|Akamai.NetworkLists.CreateDate|Date|The network list creation date.|
|Akamai.NetworkLists.CreatedBy|String|The network list creator.|
|Akamai.NetworkLists.ExpeditedProductionActivationStatus|String|The expedited production activation status.|
|Akamai.NetworkLists.ExpeditedStagingActivationStatus|String|The expedited staging activation status.|
|Akamai.NetworkLists.ProductionActivationStatus|String|The production activation status.|
|Akamai.NetworkLists.StagingActivationStatus|String|The staging activation status.|
|Akamai.NetworkLists.UpdateDate|String|The date that the network list was updated.|
|Akamai.NetworkLists.UpdatedBy|String|The last user that updated the network list.|
|Akamai.NetworkLists.Elements|String|The number of elements in the list.|

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

2. ### akamai-get-network-list-by-id

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
|Akamai.NetworkLists.Name|String|The network list name.|
|Akamai.NetworkLists.Type|String|The network list type.|
|Akamai.NetworkLists.UniqueID|String|The network list unique ID.|
|Akamai.NetworkLists.ElementCount|String|The network list elements.|
|Akamai.NetworkLists.CreateDate|Date|The network list creation date.|
|Akamai.NetworkLists.CreatedBy|String|The network list creator.|
|Akamai.NetworkLists.ExpeditedProductionActivationStatus|String|The expedited production activation status.|
|Akamai.NetworkLists.ExpeditedStagingActivationStatus|String|The expedited staging activation status.|
|Akamai.NetworkLists.ProductionActivationStatus|String|The production activation status.|
|Akamai.NetworkLists.StagingActivationStatus|String|The staging activation status.|
|Akamai.NetworkLists.UpdateDate|String|The date that the network list was updated.|
|Akamai.NetworkLists.UpdatedBy|String|The last user that updated the network list.|
|Akamai.NetworkLists.Elements|String|The number of elements in the list.|


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

3. ### akamai-create-network-list

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
|Akamai.NetworkLists.Name|String|The network list name.|
|Akamai.NetworkLists.UniqueID|String|The ID of the network list to create.|
|Akamai.NetworkLists.Type|String|The network list type.|
|Akamai.NetworkLists.ElementCount|Number|Number of element in the list.|
|Akamai.NetworkLists.Elements|String|Elements in the list.|

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

4. ### akamai-delete-network-list

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

5. ### akamai-activate-network-list

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

6. ### akamai-add-elements-to-network-list

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

7. ### akamai-remove-element-from-network-list

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

8. ### akamai-get-network-list-activation-status

Gets the activation status of the specified network list

##### Base Command

`akamai-get-network-list-activation-status`

##### Input

|**Argument Name**|**Description**|**Required**|
|--- |--- |--- |
|network_list_ids|The ID of the network list for which to get the activation status - Accept list of network lists|Required|
|env|The environment type. Can be "PRODUCTION" or "STAGING".|Required|

##### Context Output

|**Path**|**Type**|**Description**|
|--- |--- |--- |
|Akamai.NetworkLists.ActivationStatus.UniqueID|String|The network list name.|
|Akamai.NetworkLists.ActivationStatus.Status|String|The network list enviorment activation status.|
|Akamai.NetworkLists.ActivationStatus.Enviorment|String|TThe network list enviorment.|

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