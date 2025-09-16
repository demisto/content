# Akamai WAF \- Client List Design

[Link to jira ticket](https://jira-dc.paloaltonetworks.com/browse/CIAC-14273)

# Integration

Pack (exist): Akamai WAF  
Integration (exist): Akamai WAF  

# Definition Of Done:

* Deprecate all network list commands  
* Add commands to support Client List 

# Documentation:

[link to documentation](https://techdocs.akamai.com/client-lists/reference/api)

# Instance Access:

The API documentation and the product instance are available on this url : [https://control.akamai.com/](https://control.akamai.com/).  
**In order to get access for this service the lab needs to add the developer as a user.**

# Commands Deprecation:

* akamai-create-network-list \- refer to “akamai-create-client-list”  
* Akamai-delete-network-list \- refer to “akamai-delete-client-list”  
* akamai-get-network-list-by-id \- refer to “akamai-get-client-list”  
* Akamai-get-network-lists \- refer to “akamai-get-client-list”  
* Akamai-activate-network-list \- refer to “akamai-activate-client-list”  
* akamai-get-network-list-activation-status  
* akamai-add-elements-to-network-list \- refer to “akamai-add-client-list-entry”  
* akamai-remove-element-from-network-list \- refer to “akamai-remove-client-list-entry”  
* akamai-update-network-list-elements

# Integration Commands

## akamai-get-contract-group

API: GET /client-list/v1/contracts-groups \[[Link](https://techdocs.akamai.com/client-lists/reference/get-contracts-groups) to API\]

Inputs:  
**No inputs needed**  
Context output base path: Akamai.ContractGroup  
Outputs: All response data  
HR: All response data  
---

## akamai-get-client-list

API: GET /client-list/v1/lists \[[Link](%20https://techdocs.akamai.com/client-lists/reference/get-lists) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **client\_list\_id** | String | No | No | An optional URL parameter to [get a specific client list.](https://techdocs.akamai.com/client-lists/reference/get-list)  |
| **name** | String | No | No | Filters the output to lists matching a name. |
| **include\_items** | Boolean | No | No | **Default false** |
| **include\_deprecated** | Boolean | No | No | **Default false** |
| **search** | String | No | No | Returns results that match the specified substring in any client list's details or entry details. |
| **type** | String | Yes | No | Filters the output to lists of specified types Repeat the parameter to filter on more than one type. **Valid values:** IP, GEO, ASN, TLS\_FINGERPRINT,FILE\_HASH.  |
| **include\_network\_list** | Boolean | No | No | **Default false** |
| **sort** | List:\- ASC \- DESC | No | No | **Default ASC** |
| **page** | Number | No | No | **Default 0** |
| **page\_size** | Number | No | No | **Default 50** |
| **limit** | Number | No | No | **Default 50** |

Context output base path: Akamai.ClientList  
Outputs: All data \- Make sure to save the data of the included properties as well (network list, items, etc)  
HR: As the UI.  
---

## akamai-create-client-list

API: POST /client-list/v1/lists \[[Link](https://techdocs.akamai.com/client-lists/reference/post-create-list) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **name** | String | No | Yes |  |
| **type** | List: \- IP \- GEO \- ASN \-TLS\_FINGERPRINT \- FILE\_HASH \- USER | No | Yes |  |
| **contract\_id** | String | No | Yes | Add note that this value can be retrieved by running the command :”akamai-get-contract-group” |
| **group\_Id** | number | No | Yes | Add note that this value can be retrieved by running the command :”akamai-get-contract-group” |
| **notes** | String | No | No |  |
| **tags** | String | Yes | No |  |
| **entry\_value** | String | No | No | **Will be sent as a single object in the “items” array.** |
| **entry\_description** | String | No | No |  |
| **entry\_expiration\_date** | Date | No | No |  |
| **entry\_tags** | String | Yes | No |  |

Context output base path: Akamai.ClientList  
Outputs: All data   
HR: Show a message that the object was created successfully \+ list\_id  
---

## akamai-update-client-list

API: PUT /client-list/v1/lists/{list\_id} \[[Link](https://techdocs.akamai.com/client-lists/reference/put-update-list) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **name** | String | No | Yes |  |
| **notes** | String | No | No |  |
| **tags** | String | Yes | No |  |

Context output base path: Akamai.ClientList  
Outputs: All data   
HR: Show a message that the object was updated successfully \+ list\_id  
---

## akamai-delete-client-list

API: DELETE /client-list/v1/lists/{list\_id} \[[Link](https://techdocs.akamai.com/client-lists/reference/delete-list) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |

Context output base path: No need  
Outputs: No need  
HR: Show a message that the object was deleted successfully \+ list\_id  
---

## akamai-activate-client-list

API: POST /client-list/v1/lists/{list\_id}/activations \[[Link](https://techdocs.akamai.com/client-lists/reference/post-activate-list) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **action** |  |  |  | **DONT** expose this argument, need to send “ACTIVATE” as hard coded |
| **network\_environment** | List:\- STAGING \- PRODUCTION | No | Yes |  |
| **comments** | String | No | No |  |
| **notification\_recipients** | String | Yes | No | **An email array** |
| **siebel\_ticket\_id** | String | No | No |  |
| **include\_polling** | Boolean | No | No | **Default value True** |
| **interval\_in\_sconds** | Number | No | No | **Default 30** |

Context output base path: Akamai.Activation  
Outputs: All the response  
HR: Show a message that the object was activated successfully \+ list\_id

**Polling Logic:**  
In case the argument “include\_polling” \= true, we will call the [“get an activation status”](https://techdocs.akamai.com/client-lists/reference/get-activation-status) api request with the interval that is defined in the argument “interval\_in\_seconds”.  
We will keep calling this request until the field “activationStatus” will change from “PENDING\_ACTIVATION” to any other status.  
Once this value was changed we will print a  HR message with the new activation status.

---

## akamai-dectivate-client-list

API: POST /client-list/v1/lists/{list\_id}/activations \[[Link](https://techdocs.akamai.com/client-lists/reference/post-activate-list) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **action** |  |  |  | **DONT** expose this argument, need to send “DEACTIVATE” as hard coded |
| **network\_environment** | List:\- STAGING \- PRODUCTION | No | Yes |  |
| **comments** | String | No | No |  |
| **notification\_recipients** | String | Yes | No |  |
| **siebel\_ticket\_id** | String | No | No |  |
| **include\_polling** | Boolean | No | No | **Default value True** |
| **interval\_in\_sconds** | Number | No | No | **Default 30** |

Context output base path: Akamai.Activation  
Outputs: All the response  
HR: Show a message that the object was dectivated successfully \+ list\_id

**Polling Logic:**  
In case the argument “include\_polling” \= true, we will call the [“get an activation status”](https://techdocs.akamai.com/client-lists/reference/get-activation-status) api request with the interval that is defined in the argument “interval\_in\_seconds”.  
We will keep calling this request until the field “activationStatus” will change from “PENDING\_DEACTIVATION” to any other status.  
Once this value was changed we will print a  HR message with the new activation status.  
---

## akamai-add-client-list-entry

API: POST /client-list/v1/lists/{list\_id}/items \[[Link](https://techdocs.akamai.com/client-lists/reference/post-update-items) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **value** | String | No | Yes | **Will be sent as a single object in the “append” array** |
| **description**  | String | No | No |  |
| **expiration\_date** | Date | No | No |  |
| **tags** | String | Yes | No |  |

Context output base path: No need  
Outputs: No need  
HR: Show a message that the object was added successfully \+ list\_id \+ value

---

## akamai-remove-client-list-entry

API: POST /client-list/v1/lists/{list\_id}/items \[[Link](https://techdocs.akamai.com/client-lists/reference/post-update-items) to API\]

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **value** | String | Yes | Yes | **Will be sent as a multiple objects in the “delete” array** |

Context output base path: No need  
Outputs: No need  
HR: Show a message that the object was removed successfully \+ list\_id \+ value

---

## akamai-update-client-list-entry

API: POST /client-list/v1/lists/{list\_id}/items \[[Link](https://techdocs.akamai.com/client-lists/reference/post-update-items) to API\]

**Initial GET request:**  
This API overwrites all the values that were not provided, for example the user provided just “tags” so the API will delete the existing value of “description” since we did not send it well.  
In order to prevent it, we will run initial get-client-list command to retrieve all the existing values, and will build the full object \+ the value the user provided.   
So in our example that just the “tags” were provided we will add the description (and other fields) from the GET request as part of the full object.

Inputs:

| Argument name | Possible Values | Is Array  | Required | Note |
| ----- | ----- | ----- | ----- | ----- |
| **list\_id** | String | No | Yes |  |
| **value** | String | No | Yes | **Will be sent as a single object in the “update” array** |
| **description**  | String | No | No |  |
| **expiration\_date** | Date | No | No |  |
| **tags** | String | Yes | No |  |
| **is\_override** | Boolean | No | No | **Default false.** |

Context output base path: No need  
Outputs: No need  
HR: Show a message that the object was updated successfully \+ list\_id \+ value

---

