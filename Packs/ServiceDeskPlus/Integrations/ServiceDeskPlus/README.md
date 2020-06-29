IT Service Management
This integration was integrated and tested with version xx of ServiceDeskPlus
## Configure ServiceDeskPlus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceDeskPlus.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server_url | Data Center Location: Select the domain location that is applicable for you application | True |
| client_id | Client ID | True |
| client_secret | Client Secret | True |
| refresh_token | Refresh Token | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_status | The status of the requests that should be fetched. Multiple status can be entered, separated by a comma. | False |
| fetch_time | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| fetch_limit | The maximum number of incidents that should be fetched each time | False |
| fetch_filter | Use this field to filter the incidents that are being fetched according to any of the request properties. Filter should be in the format "\{field':&lt;field\_name&gt;, 'condition':&lt;condition&gt;, 'values':'val\_1,val\_2', 'logical\_operator':&lt;op&gt;\}". Multiple filters can be applied seperated with a comma, e.g. \{"field":"technician.name", "condition":"is", "values":"tech\_1\_name,tech\_2\_name", "logical\_operator":"AND"\}, \{"field":"due\_by\_time", "condition":"greater than", "values":"1592946000000", "logical\_operator":"OR"\}. Overrides the status filter, if given. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### service-desk-plus-requests-list
***
View the details of requests. If no parameters are given the details of all requests will be shown.


#### Base Command

`service-desk-plus-requests-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The unique request id of the request that should be shown. | Optional | 
| start_index | Use this to get a list of tasks starting from this index.<br/>e.g: 6 | Optional | 
| page_size | Use this to mention the number of requests that needs to be returned.<br/>e.g: 15. By default, will return only the first 10 requests. | Optional | 
| search_fields | The column name and value to be searched for in the format of a json object. e.g {“subject”:“Change like this”,“priority.name”:“High”} | Optional | 
| filter_by | The name of the filter that should be used. e.g {“name”:“My_Open”} | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceDeskPlus.Request.Requester | Unknown | The requester of the request | 
| ServiceDeskPlus.Request.CreatedTime | Date | The time the request was created | 
| ServiceDeskPlus.Request.Template | Unknown | The template that was used to create the request | 
| ServiceDeskPlus.Request.DisplayId | String | The display id of the request | 
| ServiceDeskPlus.Request.Id | String | The unique id of the request | 
| ServiceDeskPlus.Request.Subject | String | The subject of the request | 
| ServiceDeskPlus.Request.Technician | String | The technician that was assigned to the request | 
| ServiceDeskPlus.Request.Status | String | The status of the request | 
| ServiceDeskPlus.Request.DueByTime | Date | The due date of the request | 
| ServiceDeskPlus.Request.Group | String | The group to which the request belongs | 
| ServiceDeskPlus.Request.IsServiceRequest | Boolean | Indicates whether the request is a service request or not | 
| ServiceDeskPlus.Request.CancellationRequested | Boolean | Indicates whether a cancellation was requested | 
| ServiceDeskPlus.Request.HasNotes | Boolean | Indicates whether the command has notes or not | 


#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-delete
***
Delete the request with the given id.


#### Base Command

`service-desk-plus-request-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request that should be deleted | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-create
***
Create new requests


#### Base Command

`service-desk-plus-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subject | Subject of this request | Required | 
| description | Description of this request | Optional | 
| request_type | Type of this request. Choose one of the listed options or provide a dictionary representing a request_type object. | Optional | 
| impact | Impact of this request. Choose one of the listed options or provide a dictionary representing an impact object. | Optional | 
| status | Indicates the current status of this request. Choose one of the listed options or provide a dictionary representing a status object. | Optional | 
| mode | The mode in which the request is created. Choose one of the listed options or provide a dictionary representing a mode object. | Optional | 
| level | Level of the request. Choose one of the listed options or provide a dictionary representing a level object. | Optional | 
| urgency | Urgency of the request. Choose one of the listed options or provide a dictionary representing an urgency object. | Optional | 
| priority | Priority of the request. Choose one of the listed options or provide a dictionary representing a priority object. | Optional | 
| service_category | Service category to which this request belongs. String representing the category's name. | Optional | 
| requester | Indicates the requester of this request. Type the name of the requester as a string or a dictionary representing a requester object. | Optional | 
| assets | Array of asset objects associated to this request | Optional | 
| site | Denotes the site to which this request belongs. Type a site name or provide a dictionary representing a site object. | Optional | 
| group | Group to which this request belongs. Type the name of the group or a dictionary representing a group object. | Optional | 
| technician | Technician assigned to this request. Type the name of the technician or a dictoinary representing a technician object. | Optional | 
| category | Category to which the request belongs. Fill in the name of the category or a dictionary representing a category object. | Optional | 
| subcategory | Subcategory to which this request belongs. Fill in the name of the subcategory or a dictionary representing a subcategory object. | Optional | 
| item | Item of this request. Fill in the item's name or a dictionary representing an item object. | Optional | 
| email_ids_to_notify | Array of Email ids, which nedds to be notified about the happenings of this request | Optional | 
| is_fcr | Boolean value indicating if the request has been marked as First Call Resolution | Optional | 
| resources | Holds the resource data mapped to the request | Optional | 
| udf_fields | Holds udf fields' values associated with the request. Fill in a dictionary with the udf fileds and values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceDeskPlus.Request.Requester | Unknown | The requester of the request | 
| ServiceDeskPlus.Request.CreatedTime | Date | The time the request was created | 
| ServiceDeskPlus.Request.Template | Unknown | The template that was used to create the request | 
| ServiceDeskPlus.Request.DisplayId | String | The display id of the request | 
| ServiceDeskPlus.Request.Id | String | The unique id of the request | 
| ServiceDeskPlus.Request.Subject | String | The subject of the request | 
| ServiceDeskPlus.Request.Technician | String | The technician that was assigned to the request | 
| ServiceDeskPlus.Request.Status | String | The status of the request | 
| ServiceDeskPlus.Request.DueByTime | Date | The due date of the request | 
| ServiceDeskPlus.Request.Group | String | The group to which the request belongs | 
| ServiceDeskPlus.Request.IsServiceRequest | Boolean | Indicates whether the request is a service request or not | 
| ServiceDeskPlus.Request.CancellationRequested | Boolean | Indicates whether a cancellation was requested | 
| ServiceDeskPlus.Request.HasNotes | Boolean | Indicates whether the command has notes or not | 


#### Command Example
```!service-desk-plus-request-create subject="Request for docs"```

#### Context Example
```
{
    "ServiceDeskPlus": {
        "Request": {
            "CancellationRequested": false,
            "CreatedBy": {
                "department": null,
                "email_id": "akrupnik@paloaltonetworks.com",
                "id": "123640000000142582",
                "is_technician": true,
                "is_vip_user": false,
                "mobile": null,
                "name": "Arseny Krupnik",
                "phone": null,
                "photo_url": "https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60",
                "sms_mail": null
            },
            "CreatedTime": "2020-06-29T14:06:31.000Z",
            "DisplayId": "133",
            "HasAttachments": false,
            "HasLinkedRequests": false,
            "HasNotes": false,
            "HasProblem": false,
            "HasProject": false,
            "HasRequestInitiatedChange": false,
            "Id": "123640000000268021",
            "IsEscalated": false,
            "IsFcr": false,
            "IsFirstResponseOverdue": false,
            "IsOverdue": false,
            "IsRead": false,
            "IsReopened": false,
            "IsServiceRequest": false,
            "IsTrashed": false,
            "LastUpdatedTime": "2020-06-29T14:06:32.000Z",
            "Requester": {
                "department": null,
                "email_id": "akrupnik@paloaltonetworks.com",
                "id": "123640000000142582",
                "is_technician": true,
                "is_vip_user": false,
                "mobile": null,
                "name": "Arseny Krupnik",
                "phone": null,
                "photo_url": "https://contacts.zoho.com/file?exp=10&ID=712874208&t=user&height=60&width=60",
                "sms_mail": null
            },
            "Status": "Open",
            "Subject": "Request for docs",
            "Template": {
                "id": "123640000000006655",
                "name": "Default Request"
            },
            "TimeElapsed": "0",
            "UnrepliedCount": 0
        }
    }
}
```

#### Human Readable Output

>### Service Desk Plus request was successfully created
>|CreatedTime|Id|Requester|Status|Subject|
>|---|---|---|---|---|
>| 2020-06-29T14:06:31.000Z | 123640000000268021 | Arseny Krupnik | Open | Request for docs |


### service-desk-plus-request-update
***
Update the request with the given request id.


#### Base Command

`service-desk-plus-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of this request | Required | 
| subject | Subject of this request | Optional | 
| description | Description of this request | Optional | 
| request_type | Type of this request. Choose one of the listed options or provide a dictionary representing a request_type object. | Optional | 
| impact | Impact of this request. Choose one of the listed options or provide a dictionary representing an impact object. | Optional | 
| status | Indicates the current status of this request. Choose one of the listed options or provide a dictionary representing a status object. | Optional | 
| mode | The mode in which the request is created. Choose one of the listed options or provide a dictionary representing a mode object. | Optional | 
| level | Level of the request. Choose one of the listed options or provide a dictionary representing a level object. | Optional | 
| urgency | Urgency of the request. Choose one of the listed options or provide a dictionary representing an urgency object. | Optional | 
| priority | Priority of the request. Choose one of the listed options or provide a dictionary representing a priority object. | Optional | 
| service_category | Service category to which this request belongs. String representing the category's name. | Optional | 
| requester | Indicates the requester of this request. Type the name of the requester as a string or a dictionary representing a requester object. | Optional | 
| assets | Array of asset objects associated to this request | Optional | 
| site | Denotes the site to which this request belongs. Type a site name or provide a dictionary representing a site object. | Optional | 
| group | Group to which this request belongs. Type the name of the group or a dictionary representing a group object. | Optional | 
| technician | Technician assigned to this request. Type the name of the technician or a dictoinary representing a technician object. | Optional | 
| category | Category to which the request belongs. Fill in the name of the category or a dictionary representing a category object. | Optional | 
| subcategory | Subcategory to which this request belongs. Fill in the name of the subcategory or a dictionary representing a subcategory object. | Optional | 
| item | Item of this request. Fill in the item's name or a dictionary representing an item object. | Optional | 
| email_ids_to_notify | Array of Email ids, which nedds to be notified about the happenings of this request | Optional | 
| is_fcr | Boolean value indicating if the request has been marked as First Call Resolution | Optional | 
| resources | Holds the resource data mapped to the request | Optional | 
| udf_fields | Holds udf fields' values associated with the request. Fill in a dictionary with the udf fileds and values. | Optional | 
| update_reason | The reason for updating this request | Optional | 
| status_change_comments | Comments added while changing the request's status | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceDeskPlus.Request.Requester | Unknown | The requester of the request | 
| ServiceDeskPlus.Request.CreatedTime | Date | The time the request was created | 
| ServiceDeskPlus.Request.Template | Unknown | The template that was used to create the request | 
| ServiceDeskPlus.Request.DisplayId | String | The display id of the request | 
| ServiceDeskPlus.Request.Id | String | The unique id of the request | 
| ServiceDeskPlus.Request.Subject | String | The subject of the request | 
| ServiceDeskPlus.Request.Technician | String | The technician that was assigned to the request | 
| ServiceDeskPlus.Request.Status | String | The status of the request | 
| ServiceDeskPlus.Request.DueByTime | Date | The due date of the request | 
| ServiceDeskPlus.Request.Group | String | The group to which the request belongs | 
| ServiceDeskPlus.Request.IsServiceRequest | Boolean | Indicates whether the request is a service request or not | 
| ServiceDeskPlus.Request.CancellationRequested | Boolean | Indicates whether a cancellation was requested | 
| ServiceDeskPlus.Request.HasNotes | Boolean | Indicates whether the command has notes or not | 


#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-assign
***
Assignes the request with the given request id to a technician/group


#### Base Command

`service-desk-plus-request-assign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request that should be assigned | Required | 
| technician | The name of the technician that should be assigned to the request | Optional | 
| group | The name of the group that should be assigned to the request | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-pickup
***
Allows the technician to pickup the request with the given request id on his name.


#### Base Command

`service-desk-plus-request-pickup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request that should be picked up | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-linked-request-list
***
Gets a list with all the linked requests under a request


#### Base Command

`service-desk-plus-linked-request-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The request for which the linked requests are requested | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceDeskPlus.Request.LinkRequests.Comments | Unknown | The comment that was added to the linked request | 
| ServiceDeskPlus.Request.LinkRequests.LinkedRequest | Unknown | The linked request information | 


#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-resolution-add
***
Adds a resolution to the given request


#### Base Command

`service-desk-plus-request-resolution-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request for which the resolution should be added | Required | 
| resolution_content | The content of the resolution that should be added to the request | Optional | 
| add_to_linked_requests | A boolean value indicating whether the same resolution should be added to all linked request of the request | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-resolutions-list
***
Gets the resolution to the given request


#### Base Command

`service-desk-plus-request-resolutions-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request for which the resolution is desired | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceDeskPlus.Request.Resolution.Content | Unknown | The content of the resolution of the request | 
| ServiceDeskPlus.Request.Resolution.SubmittedBy | Unknown | The detailes of who submitted the resolution | 
| ServiceDeskPlus.Request.Resolution.SubmittedOn | Unknown | The date the resolution was submitted | 
| ServiceDeskPlus.Request.Resolution.ResolutionAttachments | Unknown | The attachments that were added to the resolution | 


#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-generate-refresh-token
***
This function generates the refresh token that should be used in the instance configurations


#### Base Command

`service-desk-plus-generate-refresh-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | The code received when creating the application | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-link-request-modify
***
Link or Unlink multiple commands


#### Base Command

`service-desk-plus-link-request-modify`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The id of the request for which the links should be modified | Required | 
| action | Link / Unlink this request with the given requests | Required | 
| linked_requests_id | The IDs of the requests that should be linked to the given request. Multiple IDs can be passed, seperated by a comma | Required | 
| comment | The comment that should be added when linking requests (optional). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### service-desk-plus-request-close
***
Close the existing request with the given request id


#### Base Command

`service-desk-plus-request-close`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| closure_comments | The comments that should be added when closing the request | Optional | 
| closure_code | A dictionary that represents the closure code that should be added to the request. For example, {"name": "success"} | Optional | 
| requester_ack_comments | The requester comments that should be added to the request | Optional | 
| requester_ack_resolution | Boolean. | Optional | 
| request_id | The id of the request that should be closed | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


