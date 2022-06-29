F5 Silverline Threat Intelligence is a cloud-based service incorporating external IP reputation and reducing threat-based communications. By identifying IP addresses and security categories associated with malicious activity, this managed service integrates dynamic lists of threatening IP addresses with the Silverline cloud-based platform, adding context-based security to policy decisions.
## Configure F5 Silverline on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for F5 Silverline.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your F5 Silverline server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-silverline-ip-objects-list
***
Gets a dynamic list of threatening IP addresses by the given list type. 


#### Base Command

`f5-silverline-ip-objects-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The dynamic lists type of threatening IP addresses. The type can be one of allowlist or denylist. Possible values are: allowlist, denylist. Note: Allowlists are named DDOS IP Allowlists in the F5 Silverline portal. | Required | 
| object_id | A comma-separated list of IP object IDs. If this argument is given, only those IP objects will be displayed. Otherwise, all IP objects that match the given list_type will be displayed. IF you don't the object ID, run this command without the object_id argument to get all the IDs. | Optional | 
| page_number | Page number to return. The first page number is 1. | Optional | 
| page_size | Number of results in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| F5Silverline.IPObjectList.id | String | The ID of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.type | String | The type of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.attributes.ip | String | The IP address of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.attributes.mask | String | The mask of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.attributes.duration | String | The duration \(in seconds\) of a particular threatening IP address object where list type is 'denylist'. | 
| F5Silverline.IPObjectList.attributes.expires_at | String | The expiration date \(timestamp\) of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.attributes.list_target | String | The list target of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.links.self | String | The F5 Silverline URL link of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.meta.note | String | The note of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.meta.tags | Unknown | The tags of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.meta.created_at | String | The creation date \(timestamp\) of a particular threatening IP address object. | 
| F5Silverline.IPObjectList.meta.updated_at | String | The last update date \(timestamp\) of a particular threatening IP address object. | 
| F5Silverline.Paging.last_page_number | Number | The last page number that exists. | 
| F5Silverline.Paging.current_page_size | Number | The number of IP objects to be returned on each page. | 
| F5Silverline.Paging.current_page_number | Number | The number of the requested page. | 


#### Command Example
```!f5-silverline-ip-objects-list list_type=denylist```

#### Context Example
```json
{
    "F5Silverline": {
        "IPObjectList": [
            {
                "attributes": {
                    "duration": 0,
                    "expires_at": null,
                    "ip": "1.2.3.5",
                    "list_target": "proxy",
                    "mask": "32"
                },
                "id": "822f2572-ddc4-4eb1-84ab-f27e4095c8c4",
                "links": {
                    "self": "https://portal.f5silverline.com/api/v1/ip_lists/denylist/ip_objects/822f2572-ddc4-4eb1-84ab-f27e4095c8c4?list_target=proxy"
                },
                "meta": {
                    "created_at": "2021-05-20T10:25:32.694Z",
                    "note": null,
                    "tags": [],
                    "updated_at": "2021-05-20T10:25:32.694Z"
                },
                "type": "ip_objects"
            },
            {
                "attributes": {
                    "duration": 0,
                    "expires_at": null,
                    "ip": "14.16.1.0",
                    "list_target": "proxy",
                    "mask": "32"
                },
                "id": "66202ba3-04f1-4f7c-b1a8-9a49776a96a4",
                "links": {
                    "self": "https://portal.f5silverline.com/api/v1/ip_lists/denylist/ip_objects/66202ba3-04f1-4f7c-b1a8-9a49776a96a4?list_target=proxy"
                },
                "meta": {
                    "created_at": "2021-06-09T07:59:31.772Z",
                    "note": "",
                    "tags": [],
                    "updated_at": "2021-06-09T07:59:31.772Z"
                },
                "type": "ip_objects"
            }
        ],
        "Paging": []
    }
}
```

#### Human Readable Output

>### F5 Silverline denylist IP Objects
>|ID|CIDR Range|Created At|Updated At|
>|---|---|---|---|
>| 822f2572-ddc4-4eb1-84ab-f27e4095c8c4 | 1.2.3.5/32 | 2021-05-20T10:25:32.694Z | 2021-05-20T10:25:32.694Z |
>| 66202ba3-04f1-4f7c-b1a8-9a49776a96a4 | 14.16.1.0/32 | 2021-06-09T07:59:31.772Z | 2021-06-09T07:59:31.772Z |


### f5-silverline-ip-object-add
***
Adds a new particular threatening IP address object by its IP address.


#### Base Command

`f5-silverline-ip-object-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The dynamic lists type of threatening IP addresses. The type can be "allowlist" or "denylist". Note: Allowlists are named DDOS IP Allowlists in the F5 Silverline portal. Possible values are: allowlist, denylist. | Required | 
| list_target | This argument can be supplied to target either the proxy or routed denylist. If list_target is not specifiedm it will assume both proxy and routed are requested (i.e., proxy-routed). Possible values are: "proxy", "routed", or "proxy-routed". This argument limits the denylist type but is ignored for allowlist. Possible values are: proxy, routed, proxy-routed. | Optional | 
| cidr_range | The CIDR range of a potentially threatening IP address. object (i.e IP address/ mask) in CSV format. For example, "1.2.3.4/32,2.3.4.5". In case only IP address is given, the default mask is 32. | Required | 
| duration | The duration (in seconds) of a new particular threatening IP address object where the list type is 'denylist'. Setting the duration to 0 (default) means the new IP address object will never expire. This feature has been removed for allowlist. | Optional | 
| note | The note of a new particular threatening IP address object. Default is empty. | Optional | 
| tags | A comma-separated list of tags of a new particular threatening IP address object. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!f5-silverline-ip-object-add cidr_range=2.5.3.4 list_type=denylist```

#### Human Readable Output

>IP object with CIDR range address: 2.5.3.4/32 added successfully into the denylist list.

### f5-silverline-ip-object-delete
***
Deletes an existing particular threatening IP address object by its object ID or by its IP address.


#### Base Command

`f5-silverline-ip-object-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The dynamic lists type of threatening IP addresses. The type can be one of allowlist or denylist. Possible values are: allowlist, denylist. Note: Allowlists are named DDOS IP Allowlists in the F5 Silverline portal. | Required | 
| object_id | The object ID of a particular threatening IP address object that should be deleted. | Optional | 
| object_ip | The IP address of an existing threatening IP address object that should be deleted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!f5-silverline-ip-object-delete list_type=denylist object_id=66202ba3-04f1-4f7c-b1a8-9a49776a96a4```

#### Human Readable Output

>IP object with ID: 66202ba3-04f1-4f7c-b1a8-9a49776a96a4 deleted successfully from the denylist list.


## Fetch F5 Silverline alerts

| **F5 Silverline supported alert type** | **Incident Type** | 
| --- | --- |
| WAF logs | F5 Silverline WAF Events |
| L7 DDoS logs | F5 Silverline L7 DDoS Events |  
| Threat Intelligence logs | F5 Silverline Threat Intelligence Events |  
| iRule logs | F5 Silverline iRule Events |  


As F5 Silverline API does not support fetch incidents for now, we retrieve alerts via a log collector.   
In order to fetch alerts, follow the instructions below:
1. In Cortex XSOAR, install the F5 Silverline integration.
2. In the F5 Silverline portal, go to **Config** > **Log Export** .
3. Configure the F5 Silverline "Log Export". Follow the instructions here: https://support.f5silverline.com/hc/en-us/articles/214152048. The "Host" destination must support TLS+TCP communication. 
4. In Cortex XSOAR, go to **Settings** > **Integrations**.
5. Search for Syslog. (This integration is installed by  default).
6. Configure the Syslog instance with your log receiver details:
   * Click "Fetches incidents".
   * Set the Classifier to "F5 Silverline Classifier". 
   * Set the Mapper to "F5 Silverline Mapper".
   * IP address - specify the IP address of your log receiver host.
   * Port - specify the port of your log receiver host.
   * Protocol - choose TCP or UDP.
   * Format - specify to 'Auto'.

Once the log receiver is configured it will forward the logs in TCP or UDP to Cortex XSOAR - Syslog integration and you will see that incidents were successfully pulled.

* After incidents are created, you can go to the incidents page and sort them by their type.
* You can go to an incident info tab (by clicking on an incident) and see all of the incident fields (under the Case Details header). 
