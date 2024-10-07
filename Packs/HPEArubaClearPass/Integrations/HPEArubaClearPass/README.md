Aruba ClearPass Policy Manager provides role and device-based network access control for employees, contractors, and guests across any multi-vendor wired, wireless, and VPN infrastructure.
This integration was integrated and tested with version 6.9 of HPE Aruba ClearPass.
## Configure HPE Aruba ClearPass in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL (e.g., https://example.net) |  | True |
| Client ID | HPE Aruba ClearPass client identifier. | True |
| Client Secret | HPE Aruba ClearPass client secret. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aruba-clearpass-endpoints-list
***
Get a list of endpoints. An endpoint device is an Internet-capable hardware device on a TCP/IP network (e.g. laptops, smart phones, tablets, etc.)


#### Base Command

`aruba-clearpass-endpoints-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac_address | MAC address of the required endpoint. If not given, all the endpoints will be returned. | Optional | 
| status | Status of the required endpoint. Possible values: Known, Unknown, Disabled. | Optional | 
| offset | Zero based offset to start from. Defaut is 0. | Optional | 
| limit | Maximum number of items to return in the range of 1 – 1000. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Endpoints.id | Number | The ID of the endpoint. | 
| HPEArubaClearPass.Endpoints.mac_address | string | The MAC address of the endpoint. | 
| HPEArubaClearPass.Endpoints.description | string | The description of the endpoint. | 
| HPEArubaClearPass.Endpoints.status | string | The status of the endpoint. | 
| HPEArubaClearPass.Endpoints.device_insight_tags | Unknown | List of Device Insight Tags. | 
| HPEArubaClearPass.Endpoints.attributes | Unknown | Additional attributes \(key/value pairs\) that may be stored with the endpoint. | 


#### Command Example
```!aruba-clearpass-endpoints-list```

#### Context Example
```json
{
    "HPEArubaClearPass": {
        "endpoints": [
            {
                "attributes": {
                    "A": "B",
                    "C": "D",
                    "test": "b",
                    "test": "bad"
                },
                "description": "test",
                "id": 3001,
                "mac_address": "005056894ae2",
                "status": "Known"
            },
            {
                "attributes": {
                    "test": "aaaaa"
                },
                "description": "aaaa",
                "id": 3002,
                "mac_address": "001b44113ab7",
                "status": "Known"
            }
        ]
    }
}
```

#### Human Readable Output

>### HPE Aruba ClearPass endpoints
>|attributes|description|id|mac_address|status|
>|---|---|---|---|---|
>| A: B<br/>C: D<br/>test: bad<br/>test: b | test | 3001 | 005056894ae2 | Known |
>| test: aaaaa | aaaa | 3002 | 001b44113ab7 | Known |


### aruba-clearpass-endpoint-update
***
Updates some fields of an endpoint.


#### Base Command

`aruba-clearpass-endpoint-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | Numeric ID of the endpoint. | Required | 
| mac_address | MAC address of the endpoint to be set. If not given, all the endpoints will be returned. | Optional | 
| status | Status of the endpoint to be set. Can be Known/Unknown/Disabled. Possible values: Known, Unknown, Disabled. | Optional | 
| description | Description of the endpoint to be set. | Optional | 
| device_insight_tags | A comma-separated list of Device Insight Tags. | Optional | 
| attributes | Additional attributes (key/value pairs) that may be stored with the endpoint. For example: [{"test1": "aaaaa"},{"test2":"good"}]. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Endpoints.id | Number | The ID of the endpoint. | 
| HPEArubaClearPass.Endpoints.mac_address | string | The MAC address of the endpoint. | 
| HPEArubaClearPass.Endpoints.description | string | The description of the endpoint. | 
| HPEArubaClearPass.Endpoints.status | string | The status of the endpoint. | 
| HPEArubaClearPass.Endpoints.device_insight_tags | Unknown | List of Device Insight Tags. | 
| HPEArubaClearPass.Endpoints.attributes | Unknown | Additional attributes \(key/value pairs\) that may be stored with the endpoint. | 


#### Command Example
```!aruba-clearpass-endpoint-update endpoint_id=3001 description="test" status=Known```

#### Context Example
```json
{
    "HPEArubaClearPass": {
        "endpoints": {
            "attributes": {
                "A": "B",
                "C": "D",
                "test1": "b",
                "test2": "bad"
            },
            "description": "test",
            "id": 3001,
            "mac_address": "005056894ae2",
            "status": "Known"
        }
    }
}
```

#### Human Readable Output

>### HPE Aruba ClearPass endpoints
>|attributes|description|id|mac_address|status|
>|---|---|---|---|---|
>| A: B<br/>C: D<br/>test1: bad<br/>test2: b | test | 3001 | 005056894ae2 | Known |


### aruba-clearpass-attributes-list
***
Get a list of attributes. Attributes allows you to specify unique sets of criteria for local users, guest users, endpoints, and devices. If no arguments were given, all of the attributes will be displayed.


#### Base Command

`aruba-clearpass-attributes-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_id | Numeric ID of the required attribute. | Optional | 
| name | Name of the required attribute. | Optional | 
| entity_name | Entity name of the required attribute. Possible values are: Device, LocalUser, GuestUser, Endpoint, Onboard. | Optional | 
| offset | Zero-based offset to start from. Default is 0. | Optional | 
| limit | Maximum number of items to return in the range of 1 – 1000. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Attributes.id | Number | The ID of the attribute. | 
| HPEArubaClearPass.Attributes.name | string | The name of the attribute. | 
| HPEArubaClearPass.Attributes.entity_name | string | The entity name of the attribute. | 
| HPEArubaClearPass.Attributes.data_type | string | The data type of the attribute \(can be one of the following - Boolean, Date, Day, IPv4Address, Integer32, List, MACAddress, String, Text, Time, TimeOfDay\). | 
| HPEArubaClearPass.Attributes.mandatory | Boolean | Whether this attribute is mandatory for the given entity_name. | 
| HPEArubaClearPass.Attributes.default_value | Unknown | Default value of the attribute. | 
| HPEArubaClearPass.Attributes.allow_multiple | Boolean | Whether to allow multiple values of the attribute with data type String only \(API limitation\). | 
| HPEArubaClearPass.Attributes.allowed_value | Unknown | The allowed value for attribute with data type List \(e.g., example1,example2,example3\). | 


#### Command Example
```!aruba-clearpass-attributes-list```

#### Context Example
```json
{
    "HPEArubaClearPass": {
        "attributes": [
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 35,
                "mandatory": false,
                "name": "Controller Id"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 32,
                "mandatory": false,
                "name": "Device Vendor"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 34,
                "mandatory": false,
                "name": "Location"
            },
            {
                "allow_multiple": false,
                "data_type": "Boolean",
                "entity_name": "Device",
                "id": 3011,
                "mandatory": false,
                "name": "new123"
            },
            {
                "allow_multiple": false,
                "data_type": "Boolean",
                "entity_name": "Device",
                "id": 3043,
                "mandatory": false,
                "name": "new_attribute_aviya"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 31,
                "mandatory": false,
                "name": "new_name"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 33,
                "mandatory": false,
                "name": "OS Version"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 38,
                "mandatory": false,
                "name": "sysContact"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 37,
                "mandatory": false,
                "name": "sysLocation"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "Device",
                "id": 36,
                "mandatory": false,
                "name": "sysName"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 5,
                "mandatory": false,
                "name": "Department"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 6,
                "mandatory": false,
                "name": "Designation"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 2,
                "mandatory": false,
                "name": "Email"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 1,
                "mandatory": false,
                "name": "Phone"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 3,
                "mandatory": false,
                "name": "Sponsor"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "LocalUser",
                "id": 4,
                "mandatory": false,
                "name": "Title"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 41,
                "mandatory": false,
                "name": "airgroup_enable"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 42,
                "mandatory": false,
                "name": "airgroup_shared"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 46,
                "mandatory": false,
                "name": "airgroup_shared_group"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 45,
                "mandatory": false,
                "name": "airgroup_shared_location"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 44,
                "mandatory": false,
                "name": "airgroup_shared_role"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 47,
                "mandatory": false,
                "name": "airgroup_shared_time"
            },
            {
                "allow_multiple": false,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 43,
                "mandatory": false,
                "name": "airgroup_shared_user"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 16,
                "mandatory": false,
                "name": "Company Name"
            },
            {
                "allow_multiple": true,
                "data_type": "String",
                "entity_name": "GuestUser",
                "id": 15,
                "mandatory": false,
                "name": "Designation"
            }
        ]
    }
}
```

#### Human Readable Output

>### HPE Aruba ClearPass attributes
>|allow_multiple|data_type|entity_name|id|mandatory|name|
>|---|---|---|---|---|---|
>| true | String | Device | 35 | false | Controller Id |
>| true | String | Device | 32 | false | Device Vendor |
>| true | String | Device | 34 | false | Location |
>| false | Boolean | Device | 3011 | false | new123 |
>| false | Boolean | Device | 3043 | false | new_attribute_aviya |
>| true | String | Device | 31 | false | new_name |
>| true | String | Device | 33 | false | OS Version |
>| true | String | Device | 38 | false | sysContact |
>| true | String | Device | 37 | false | sysLocation |
>| true | String | Device | 36 | false | sysName |
>| true | String | LocalUser | 5 | false | Department |
>| true | String | LocalUser | 6 | false | Designation |
>| true | String | LocalUser | 2 | false | Email |
>| true | String | LocalUser | 1 | false | Phone |
>| true | String | LocalUser | 3 | false | Sponsor |
>| true | String | LocalUser | 4 | false | Title |
>| false | String | GuestUser | 41 | false | airgroup_enable |
>| false | String | GuestUser | 42 | false | airgroup_shared |
>| false | String | GuestUser | 46 | false | airgroup_shared_group |
>| false | String | GuestUser | 45 | false | airgroup_shared_location |
>| false | String | GuestUser | 44 | false | airgroup_shared_role |
>| false | String | GuestUser | 47 | false | airgroup_shared_time |
>| false | String | GuestUser | 43 | false | airgroup_shared_user |
>| true | String | GuestUser | 16 | false | Company Name |
>| true | String | GuestUser | 15 | false | Designation |


### aruba-clearpass-attribute-create
***
Create a new attribute.


#### Base Command

`aruba-clearpass-attribute-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the attribute to be set. | Required | 
| entity_name | Entity name of the attribute to be set. Possible values: Device, LocalUser, GuestUser, Endpoint, Onboard. | Required | 
| data_type | Data Type of the attribute to be set. Possible values: Boolean, Date, Day, IPv4Address, Integer32, List, MACAddress, String, Text, Time, TimeOfDay. | Required | 
| mandatory | Whether to make this attribute mandatory for the given entity_name. Default is False. Possible values are: True, False. | Optional | 
| default_value | Default value of the attribute. Default is an empty string. | Optional | 
| allow_multiple | Whether to allow multiple values of the attribute with data type String only (API limitation). Default is False. Possible values are: True, False. | Optional | 
| allowed_value | Possible value for attribute with data type List only (API limitation) (e.g., example1,example2,example3). Default is an empty string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Attributes.id | Number | The ID of the attribute. | 
| HPEArubaClearPass.Attributes.name | string | The name of the attribute. | 
| HPEArubaClearPass.Attributes.entity_name | string | The entity name of the attribute. | 
| HPEArubaClearPass.Attributes.data_type | string | The data type of the attribute. Can be one of the following: Boolean, Date, Day, IPv4Address, Integer32, List, MACAddress, String, Text, Time, TimeOfDay. | 
| HPEArubaClearPass.Attributes.mandatory | Boolean | Whether this attribute is mandatory for the given entity_name. | 
| HPEArubaClearPass.Attributes.default_value. | Unknown | Default value of the attribute. | 
| HPEArubaClearPass.Attributes.allow_multiple | Boolean | Whether to allow multiple values of the attribute with data type String only \(API limitation\). | 
| HPEArubaClearPass.Attributes.allowed_value | Unknown | The allowed value for attribute with data type List \(e.g., example1,example2,example3\). | 


#### Command Example
```!aruba-clearpass-attribute-create data_type=Boolean entity_name=Device name="new_attribute"```

#### Context Example
```json
{
    "HPEArubaClearPass": {
        "attributes": {
            "allow_multiple": false,
            "data_type": "Boolean",
            "entity_name": "Device",
            "id": 3044,
            "mandatory": false,
            "name": "new_attribute"
        }
    }
}
```

#### Human Readable Output

>### HPE Aruba ClearPass new attribute
>|allow_multiple|data_type|entity_name|id|mandatory|name|
>|---|---|---|---|---|---|
>| false | Boolean | Device | 3044 | false | new_attribute |


### aruba-clearpass-attribute-update
***
Update some fields of an attribute by the attribute's ID.


#### Base Command

`aruba-clearpass-attribute-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_id | Numeric ID of the attribute to be updated. | Required | 
| name | Name of the attribute to be set. | Optional | 
| entity_name | Entity Name of the attribute to be set. Possible values: Device, LocalUser, GuestUser, Endpoint, Onboard. | Optional | 
| data_type | Data type of the attribute to be set. Possible values are: Boolean, Date, Day, IPv4Address, Integer32, List, MACAddress, String, Text, Time, TimeOfDay. | Optional | 
| mandatory | Whether to make this attribute mandatory for the given entity_name. Default is False. Possible values are: True, False. | Optional | 
| default_value | Default value of the attribute. Default is an empty string. | Optional | 
| allow_multiple | Whether to allow multiple values of the attribute with data type String only (API limitation). Default is False. Possible values are: True, False. | Optional | 
| allowed_value | Possible value for attribute with data type List only (API limitation) (e.g., example1,example2,example3). Default is an empty string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Attributes.id | Number | The ID of the attribute. | 
| HPEArubaClearPass.Attributes.name | string | The name of the attribute. | 
| HPEArubaClearPass.Attributes.entity_name | string | The entity name of the attribute. | 
| HPEArubaClearPass.Attributes.data_type | string | The data type of the attribute. Can be one of the following: Boolean, Date, Day, IPv4Address, Integer32, List, MACAddress, String, Text, Time, TimeOfDay. | 
| HPEArubaClearPass.Attributes.mandatory | Boolean | Whether this attribute is mandatory for the given entity_name. | 
| HPEArubaClearPass.Attributes.default_value. | Unknown | Default value of the attribute. | 
| HPEArubaClearPass.Attributes.allow_multiple | Boolean | Whether to allow multiple values of the attribute with data type String only \(API limitation\). | 
| HPEArubaClearPass.Attributes.allowed_value | Unknown | The allowed value for attribute with data type List \(e.g., example1,example2,example3\). | 


#### Command Example
```!aruba-clearpass-attribute-update attribute_id=31 name="Device Type" data_type=String```

#### Context Example
```json
{
    "HPEArubaClearPass": {
        "attributes": {
            "allow_multiple": true,
            "data_type": "String",
            "entity_name": "Device",
            "id": 31,
            "mandatory": false,
            "name": "Device Type"
        }
    }
}
```

#### Human Readable Output

>### HPE Aruba ClearPass update attribute
>|allow_multiple|data_type|entity_name|id|mandatory|name|
>|---|---|---|---|---|---|
>| true | String | Device | 31 | false | Device Type |


### aruba-clearpass-attribute-delete
***
Delete an attribute.


#### Base Command

`aruba-clearpass-attribute-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_id | Numeric ID of the attribute. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aruba-clearpass-attribute-delete attribute_id=3043```

#### Human Readable Output

>HPE Aruba ClearPass attribute with ID: 3043 deleted successfully.

### aruba-clearpass-active-sessions-list
***
Get a list of active sessions.


#### Base Command

`aruba-clearpass-active-sessions-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | ID of the active session. | Optional | 
| device_ip | IP address of the client. | Optional | 
| device_mac_address | MAC address of the client device. | Optional | 
| visitor_phone | The visitor’s phone number. | Optional | 
| limit | Maximum number of items to return in the range of 1 – 1000. Default is 25. | Optional | 



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Sessions.ID | String | ID of the active session. | 
| HPEArubaClearPass.Sessions.Device_IP | String | IP address of the client. | 
| HPEArubaClearPass.Sessions.Device_mac_address | String | MAC address of the client device. | 
| HPEArubaClearPass.Sessions.state | String | The current state of the session \(active, stale, closed\). | 
| HPEArubaClearPass.Sessions.Visitor_phone | String | The visitor’s phone number. | 


#### Command Example
```!aruba-clearpass-active-sessions-list```



### aruba-clearpass-active-session-disconnect
***
Disconnect active session.


#### Base Command

`aruba-clearpass-active-session-disconnect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | ID of the session to disconnect. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HPEArubaClearPass.Sessions.Error_code | Number | Error status code of the response \(non-zero if a problem occurred\). | 
| HPEArubaClearPass.Sessions.Response_message | String | Describes the result of the disconnected operation. | 


#### Command Example
```!aruba-clearpass-active-session-disconnect session_id=123```



