Cloud-based continuous vulnerability management and penetration testing solution.
This integration was integrated and tested with version xx of Edgescan
## Configure Edgescan on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Edgescan.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | API Key |  | True |
    | Max number of incidents to fetch at once |  | False |
    | Fetch vulnerabilities with CVSS | This has to be an exact value. No filter operator available. | False |
    | Fetch vulnerabilities with risk more than |  | False |
    | First fetch time | How many days to fetch back on first run. | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### edgescan-host-get-hosts
***
Get a list of all hosts


#### Base Command

`edgescan-host-get-hosts`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGetHosts | Unknown | List of all hosts | 


#### Command Example
```!edgescan-host-get-hosts```

#### Human Readable Output

>### Hosts
>**No entries.**


### edgescan-host-get
***
Get detailed information about a host.


#### Base Command

`edgescan-host-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The host id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGet | Unknown | Detailed host information | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-host-get-export
***
Get a list of hosts in export format.


#### Base Command

`edgescan-host-get-export`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGetExport | Unknown | Export host information | 


#### Command Example
```!edgescan-host-get-export```

#### Human Readable Output

>### Hosts export
>**No entries.**


### edgescan-host-get-query
***
Get a list of hosts by query


#### Base Command

`edgescan-host-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID. | Optional | 
| os_name | The Operating System name. | Optional | 
| label | The asset label. | Optional | 
| status | The asset status. | Optional | 
| id | The host id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGetQuery | Unknown | The result of a host query | 


#### Command Example
```!edgescan-host-get-query os_name=Linux asset_id=5 id=6 ```

#### Human Readable Output

>### Hosts query
>**No entries.**


### edgescan-host-update
***
Update a host


#### Base Command

`edgescan-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The host label. | Optional | 
| id | The host id to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostUpdate | Unknown | Information returned after host update | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-get-assets
***
Get the full list of assets


#### Base Command

`edgescan-asset-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detail_level | The detail level of the metadata. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGetAssets | Unknown | List of all assets | 


#### Command Example
```!edgescan-asset-get-assets detail_level=5```

#### Context Example
```json
{
    "Edgescan": {
        "AssetGetAssets": [
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": false,
                "blocked_status": "unblocked",
                "created_at": "2021-04-02T15:35:25.988Z",
                "current_assessment": null,
                "host_count": 768,
                "hostname": "192.168.0.0/24, 10.0.0.0/24, 172.16.0.0/24",
                "id": 164,
                "last_assessment_date": "2021-03-23T12:10:54.815Z",
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [
                    {
                        "id": 191,
                        "location": "192.168.0.0/24",
                        "location_type": "cidr"
                    },
                    {
                        "id": 192,
                        "location": "10.0.0.0/24",
                        "location_type": "cidr"
                    },
                    {
                        "id": 193,
                        "location": "172.16.0.0/24",
                        "location_type": "cidr"
                    }
                ],
                "name": "Edgescan Internal Server Farm",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 4,
                "tags": [],
                "type": "net",
                "updated_at": "2021-06-11T08:37:55.243Z"
            },
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": true,
                "blocked_status": "unblocked",
                "created_at": "2021-04-02T15:35:27.441Z",
                "current_assessment": null,
                "host_count": 1,
                "hostname": "https://stage.auth.api.edgebank.com, http://stage.api.edgebank.com/, stage.api.edgebank.com, https://live.edgescan.com/api.wsdl",
                "id": 165,
                "last_assessment_date": "2020-10-22T21:00:52.124Z",
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [
                    {
                        "id": 194,
                        "location": "https://stage.auth.api.edgebank.com",
                        "location_type": "url"
                    },
                    {
                        "id": 195,
                        "location": "http://stage.api.edgebank.com/",
                        "location_type": "url"
                    },
                    {
                        "id": 196,
                        "location": "stage.api.edgebank.com",
                        "location_type": "hostname"
                    },
                    {
                        "id": 197,
                        "location": "https://live.edgescan.com/api.wsdl",
                        "location_type": "api_descriptor"
                    }
                ],
                "name": "Edgebank API",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 9,
                "tags": [],
                "type": "app",
                "updated_at": "2021-06-11T08:37:55.374Z"
            },
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": true,
                "blocked_status": "unblocked",
                "created_at": "2021-04-02T15:35:28.372Z",
                "current_assessment": null,
                "host_count": 1,
                "hostname": "https://edgeasset.edgescan.com, edgeasset.edgescan.com",
                "id": 166,
                "last_assessment_date": null,
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [
                    {
                        "id": 198,
                        "location": "https://edgeasset.edgescan.com",
                        "location_type": "url"
                    },
                    {
                        "id": 199,
                        "location": "edgeasset.edgescan.com",
                        "location_type": "hostname"
                    }
                ],
                "name": "Edgeasset",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 5,
                "tags": [],
                "type": "app",
                "updated_at": "2021-04-02T15:35:28.409Z"
            },
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": false,
                "blocked_status": "unblocked",
                "created_at": "2021-04-02T15:35:28.427Z",
                "current_assessment": null,
                "host_count": 1,
                "hostname": "http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com",
                "id": 167,
                "last_assessment_date": "2021-02-22T14:25:03.092Z",
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [
                    {
                        "id": 200,
                        "location": "http://juice.edgebank.com",
                        "location_type": "url"
                    },
                    {
                        "id": 201,
                        "location": "juice.edgebank.com",
                        "location_type": "hostname"
                    },
                    {
                        "id": 202,
                        "location": "https://juice.edgebank.com",
                        "location_type": "url"
                    }
                ],
                "name": "Edgebank - Juiceshop - Updated",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 4,
                "tags": [],
                "type": "app",
                "updated_at": "2021-07-07T09:43:39.673Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Assets
>|id|name|asset_status|blocked_status|hostname|
>|---|---|---|---|---|
>| 164 | Edgescan Internal Server Farm | onboarding | unblocked | 192.168.0.0/24, 10.0.0.0/24, 172.16.0.0/24 |
>| 165 | Edgebank API | onboarding | unblocked | https://stage.auth.api.edgebank.com, http://stage.api.edgebank.com/, stage.api.edgebank.com, https://live.edgescan.com/api.wsdl |
>| 166 | Edgeasset | onboarding | unblocked | https://edgeasset.edgescan.com, edgeasset.edgescan.com |
>| 167 | Edgebank - Juiceshop - Updated | onboarding | unblocked | http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com |


### edgescan-asset-get
***
Get asset details


#### Base Command

`edgescan-asset-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGet | Unknown | Detailed information about an asset | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-get-query
***
Query the asset database


#### Base Command

`edgescan-asset-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID. | Optional | 
| name | The asset name. | Optional | 
| hostname | The asset hostname. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticated | Authentication status. | Optional | 
| host_count | Number of hosts. | Optional | 
| created_at | Creation date. | Optional | 
| updated_at | Last time updated at. | Optional | 
| id | Asset id. | Optional | 
| location | Asset location. | Optional | 
| location_type | Location type of an asset. | Optional | 
| pci_enabled | PCI compliance status. | Optional | 
| last_host_scan | Last host scan date. | Optional | 
| network_access | Asset network access. | Optional | 
| current_assessment | Asset assesment. | Optional | 
| next_assessment_date | Asset next assesment date. | Optional | 
| active_licence | Asset license state. | Optional | 
| blocked_status | Asset lock status. | Optional | 
| last_assessment_date | Date of last asset assesment. | Optional | 
| asset_status | The asset status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGetQuery | Unknown | Output of an asset query | 


#### Command Example
```!edgescan-asset-get-query id=167 active_licence=null asset_status=onboarding blocked_status=unblocked```

#### Context Example
```json
{
    "Edgescan": {
        "AssetGetQuery": [
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": false,
                "blocked_status": "unblocked",
                "created_at": "2021-04-02T15:35:28.427Z",
                "current_assessment": null,
                "host_count": 1,
                "hostname": "http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com",
                "id": 167,
                "last_assessment_date": "2021-02-22T14:25:03.092Z",
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [
                    {
                        "id": 200,
                        "location": "http://juice.edgebank.com",
                        "location_type": "url"
                    },
                    {
                        "id": 201,
                        "location": "juice.edgebank.com",
                        "location_type": "hostname"
                    },
                    {
                        "id": 202,
                        "location": "https://juice.edgebank.com",
                        "location_type": "url"
                    }
                ],
                "name": "Edgebank - Juiceshop - Updated",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 4,
                "tags": [],
                "type": "app",
                "updated_at": "2021-07-07T09:43:39.673Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Assets query
>|id|name|asset_status|blocked_status|hostname|
>|---|---|---|---|---|
>| 167 | Edgebank - Juiceshop - Updated | onboarding | unblocked | http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com |


### edgescan-asset-create
***
Create an asset


#### Base Command

`edgescan-asset-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Optional | 
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetCreate | Unknown | Information about asset creation | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-update
***
Update an asset


#### Base Command

`edgescan-asset-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 
| id | The asset ID to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetUpdate | Unknown | Information about asset update | 


#### Command Example
```!edgescan-asset-update id=167 name="Edgebank - Juiceshop - Updated" priority=4```

#### Context Example
```json
{
    "Edgescan": {
        "AssetUpdate": {
            "active_licence": null,
            "api_descriptor": null,
            "assessment_count": 0,
            "assessments": [],
            "asset_status": "onboarding",
            "authenticated": false,
            "blocked_reason": null,
            "blocked_status": "unblocked",
            "container_images": [],
            "created_at": "2021-04-02T15:35:28.427Z",
            "current_assessment": null,
            "host_count": 1,
            "hostname": "http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com",
            "id": 167,
            "last_assessment_date": "2021-02-22T14:25:03.092Z",
            "last_host_scan": null,
            "linked_assets": [],
            "location_specifiers": [
                {
                    "id": 200,
                    "location": "http://juice.edgebank.com",
                    "location_type": "url"
                },
                {
                    "id": 201,
                    "location": "juice.edgebank.com",
                    "location_type": "hostname"
                },
                {
                    "id": 202,
                    "location": "https://juice.edgebank.com",
                    "location_type": "url"
                }
            ],
            "name": "Edgebank - Juiceshop - Updated",
            "network_access": "external",
            "next_assessment_date": null,
            "next_host_scan": null,
            "pci_enabled": null,
            "points_of_contact": [],
            "priority": 4,
            "schedule": [],
            "tags": [],
            "type": "app",
            "updated_at": "2021-07-07T09:43:39.673Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|active_licence|api_descriptor|assessment_count|assessments|asset_status|authenticated|blocked_reason|blocked_status|container_images|created_at|current_assessment|host_count|hostname|id|last_assessment_date|last_host_scan|linked_assets|location_specifiers|name|network_access|next_assessment_date|next_host_scan|pci_enabled|points_of_contact|priority|schedule|tags|type|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 0 |  | onboarding | false |  | unblocked |  | 2021-04-02T15:35:28.427Z |  | 1 | http://juice.edgebank.com, juice.edgebank.com, https://juice.edgebank.com | 167 | 2021-02-22T14:25:03.092Z |  |  | {'id': 200, 'location': 'http://juice.edgebank.com', 'location_type': 'url'},<br/>{'id': 201, 'location': 'juice.edgebank.com', 'location_type': 'hostname'},<br/>{'id': 202, 'location': 'https://juice.edgebank.com', 'location_type': 'url'} | Edgebank - Juiceshop - Updated | external |  |  |  |  | 4 |  |  | app | 2021-07-07T09:43:39.673Z |


### edgescan-asset-delete
***
Delete an asset


#### Base Command

`edgescan-asset-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 
| id | The asset id to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetDelete | Unknown | Information about asset deletion | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-get-users
***
Get the full user list


#### Base Command

`edgescan-user-get-users`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetusers | Unknown | The list of all users | 


#### Command Example
```!edgescan-user-get-users```

#### Context Example
```json
{
    "Edgescan": {
        "UserGetUsers": [
            {
                "account_locked": false,
                "created_at": "2021-03-10T13:56:59.307Z",
                "email": "pierreb@starsgroup.com",
                "email_confirmed": true,
                "first_name": "Pierre",
                "id": 586,
                "is_super": true,
                "last_login_time": "2021-06-01T15:26:51.525Z",
                "last_name": "Buckleigh",
                "last_password_reset_time": "2021-03-10T14:47:28.853Z",
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": false,
                "mfa_method": "sms",
                "phone_number": "",
                "phone_number_confirmed": false,
                "updated_at": "2021-06-01T15:26:51.530Z",
                "username": "pierreb@starsgroup.com.8494"
            },
            {
                "account_locked": false,
                "created_at": "2021-06-01T14:46:49.429Z",
                "email": "mdrobniuch@paloaltonetworks.com",
                "email_confirmed": true,
                "first_name": "Maciej",
                "id": 606,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Drobniuch",
                "last_password_reset_time": "2021-06-01T14:47:09.192Z",
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "0048696894057",
                "phone_number_confirmed": true,
                "updated_at": "2021-06-01T14:51:31.263Z",
                "username": "mdrobniuch@paloaltonetworks.com.0938"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>|id|username|email|phone_number|mfa_enabled|
>|---|---|---|---|---|
>| 586 | pierreb@starsgroup.com.8494 | pierreb@starsgroup.com |  | false |
>| 606 | mdrobniuch@paloaltonetworks.com.0938 | mdrobniuch@paloaltonetworks.com | 0048696894057 | true |


### edgescan-user-get
***
Get user details


#### Base Command

`edgescan-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user ID to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGet | Unknown | Detailed user information | 


#### Command Example
```!edgescan-user-get id=586```

#### Context Example
```json
{
    "Edgescan": {
        "UserGet": {
            "account_locked": false,
            "created_at": "2021-03-10T13:56:59.307Z",
            "email": "pierreb@starsgroup.com",
            "email_confirmed": true,
            "first_name": "Pierre",
            "id": 586,
            "is_super": true,
            "last_login_time": "2021-06-01T15:26:51.525Z",
            "last_name": "Buckleigh",
            "last_password_reset_time": "2021-03-10T14:47:28.853Z",
            "lock_reason": null,
            "lock_time": null,
            "mfa_enabled": false,
            "mfa_method": "sms",
            "permissions": [
                "view",
                "edit",
                "create",
                "delete"
            ],
            "phone_number": "",
            "phone_number_confirmed": false,
            "updated_at": "2021-06-01T15:26:51.530Z",
            "username": "pierreb@starsgroup.com.8494"
        }
    }
}
```

#### Human Readable Output

>### User
>|id|username|email|phone_number|mfa_enabled|
>|---|---|---|---|---|
>| 586 | pierreb@starsgroup.com.8494 | pierreb@starsgroup.com |  | false |


### edgescan-user-get-query
***
Query for a user


#### Base Command

`edgescan-user-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Optional | 
| username | The username. | Optional | 
| phone_number | The user's phone number. | Optional | 
| phone_number_confirmed | User's phone number confirmation. | Optional | 
| mfa_enabled | User's Multi Factor Authentication Status. | Optional | 
| mfa_method | User's Multi Factor Authentication Method. | Optional | 
| email | User's E-Mail Address. | Optional | 
| email_confirmed | Email confirmation status. | Optional | 
| created_at | User creation date. | Optional | 
| updated_at | Last user update. | Optional | 
| is_super | Superuser status. | Optional | 
| account_locked | User lock status. | Optional | 
| lock_reason | User lock reason. | Optional | 
| lock_time | User lock time. | Optional | 
| last_login_time | User's last login time. | Optional | 
| last_password_reset_time | User's last password reset time. | Optional | 
| first_name | User's first name. | Optional | 
| last_name | User's last name. | Optional | 
| l | Result query limit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetQuery | Unknown | Result of a user query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-create
***
Create a user


#### Base Command

`edgescan-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username. | Optional | 
| email | User's E-Mail Address. | Optional | 
| first_name | User's first name. | Optional | 
| last_name | User's last name. | Optional | 
| phone_number | User's phone number. | Optional | 
| mfa_enabled | User's Multi Factor Authentication Status. | Optional | 
| mfa_method | User's Multi Factor Authentication method. | Optional | 
| is_super | Super user status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserCreate | Unknown | Information about a created user | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-delete
***
Delete a user


#### Base Command

`edgescan-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserDelete | Unknown | Information about a deleted user | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-reset-password
***
Reset a user's password


#### Base Command

`edgescan-user-reset-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to reset the password for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserResetPassword | Unknown | Information about User password reset | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-reset-email
***
Reset a users password


#### Base Command

`edgescan-user-reset-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to reset the email for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserResetEmail | Unknown | Information about User email reset. | 


#### Command Example
```!edgescan-user-reset-email id=606```

#### Context Example
```json
{
    "Edgescan": {
        "UserResetEmail": {
            "message": "Mail delivered successfully"
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| Mail delivered successfully |


### edgescan-user-lock-account
***
Lock a user


#### Base Command

`edgescan-user-lock-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to lock. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserLockAccount | Unknown | Information about the User lock | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-unlock-account
***
Unlock a user


#### Base Command

`edgescan-user-unlock-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to unlock. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserUnlockAccount | Unknown | Information about user unlock status | 


#### Command Example
```!edgescan-user-unlock-account id=606```

#### Context Example
```json
{
    "Edgescan": {
        "UserUnlockAccount": {
            "account_locked": false,
            "created_at": "2021-06-01T14:46:49.429Z",
            "email": "mdrobniuch@paloaltonetworks.com",
            "email_confirmed": true,
            "first_name": "Maciej",
            "id": 606,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Drobniuch",
            "last_password_reset_time": "2021-06-01T14:47:09.192Z",
            "lock_reason": null,
            "lock_time": null,
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "0048696894057",
            "phone_number_confirmed": true,
            "updated_at": "2021-06-01T14:51:31.263Z",
            "username": "mdrobniuch@paloaltonetworks.com.0938"
        }
    }
}
```

#### Human Readable Output

>### User unlocked
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-06-01T14:46:49.429Z | mdrobniuch@paloaltonetworks.com | true | Maciej | 606 | false |  | Drobniuch | 2021-06-01T14:47:09.192Z |  |  | true | sms | 0048696894057 | true | 2021-06-01T14:51:31.263Z | mdrobniuch@paloaltonetworks.com.0938 |


### edgescan-user-get-permissions
***
Get user's permissions


#### Base Command

`edgescan-user-get-permissions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to get the permissions for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetPermissions | Unknown | The user permissions | 


#### Command Example
```!edgescan-user-get-permissions id=606```

#### Human Readable Output

>### User permissions
>**No entries.**


### edgescan-vulnerabilities-get
***
Get the full list of vulnerabilities


#### Base Command

`edgescan-vulnerabilities-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EdgeScan.VulnerabilitiesGet | Unknown | The list of all Vulnerabilities | 


#### Command Example
```!edgescan-vulnerabilities-get```

#### Context Example
```json
{
    "Edgescan": {
        "VulnerabilitiesGet": [
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.085Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "date_closed": "2020-02-17T11:04:20.201Z",
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 30,
                "id": 52492,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "SSL Version 2 (v2) Protocol Detection",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 4,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:26.107Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.140Z",
                "cves": [
                    "CVE-2015-0204"
                ],
                "cvss_score": 4.3,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                "cvss_version": 2,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 137,
                "id": 52493,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.020Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.206Z",
                "cves": [
                    "CVE-1999-0024"
                ],
                "cvss_score": 5,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                "cvss_version": 2,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 47,
                "id": 52494,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.2",
                "location_specifier_id": 192,
                "name": "DNS Server Recursive Query Cache Poisoning Weakness",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.035Z"
            },
            {
                "altered_score": true,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.272Z",
                "cves": [
                    "CVE-2017-0007",
                    "CVE-2017-0016",
                    "CVE-2017-0039",
                    "CVE-2017-0057",
                    "CVE-2017-0100",
                    "CVE-2017-0104"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 307,
                "id": 52495,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.5",
                "location_specifier_id": 192,
                "name": "MS17-012: Security Update for Microsoft Windows",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.049Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.336Z",
                "cves": [
                    "CVE-2010-1917",
                    "CVE-2010-2531",
                    "CVE-2010-2939",
                    "CVE-2010-2950",
                    "CVE-2010-3709",
                    "CVE-2010-4008",
                    "CVE-2010-4156",
                    "CVE-2011-1540",
                    "CVE-2011-1541"
                ],
                "cvss_score": 10,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 308,
                "id": 52496,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "HP System Management Homepage < 6.3 Multiple Vulnerabilities",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.061Z"
            },
            {
                "altered_score": true,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.405Z",
                "cves": [
                    "CVE-2017-1000353",
                    "CVE-2017-1000354",
                    "CVE-2017-1000355",
                    "CVE-2017-1000356"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 306,
                "id": 52497,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "172.16.0.5",
                "location_specifier_id": 193,
                "name": "Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.074Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.476Z",
                "cves": [
                    "CVE-2017-3737",
                    "CVE-2018-2562",
                    "CVE-2018-2573",
                    "CVE-2018-2583",
                    "CVE-2018-2590",
                    "CVE-2018-2591",
                    "CVE-2018-2612",
                    "CVE-2018-2622",
                    "CVE-2018-2640",
                    "CVE-2018-2645",
                    "CVE-2018-2647",
                    "CVE-2018-2665",
                    "CVE-2018-2668",
                    "CVE-2018-2696",
                    "CVE-2018-2703"
                ],
                "cvss_score": 7.5,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 309,
                "id": 52498,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.9",
                "location_specifier_id": 192,
                "name": "MySQL 5.6.x < 5.6.39 Multiple Vulnerabilities (January 2018 CPU) (2936)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.091Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.539Z",
                "cves": [
                    "CVE-2012-4929",
                    "CVE-2012-4930"
                ],
                "cvss_score": 2.6,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
                "cvss_version": 2,
                "date_closed": null,
                "date_opened": "2019-08-15T10:20:51.058Z",
                "definition_id": 253,
                "id": 52499,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "172.16.0.63",
                "location_specifier_id": 193,
                "name": "Transport Layer Security (TLS) Protocol CRIME Vulnerability",
                "pci_compliance_status": "pass",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.103Z"
            },
            {
                "altered_score": true,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.621Z",
                "cves": [],
                "cvss_score": 7,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-02-17T11:04:20.201Z",
                "definition_id": 314,
                "id": 52500,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.2",
                "location_specifier_id": 192,
                "name": "Citrix NetScaler RCE Vulnerability (CTX267027) - Active Check",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.117Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.676Z",
                "cves": [],
                "cvss_score": null,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": null,
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-02-17T11:04:20.201Z",
                "definition_id": 315,
                "id": 52501,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.2",
                "location_specifier_id": 192,
                "name": "Citrix NetScaler Authentication Bypass Vulnerability",
                "pci_compliance_status": null,
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.129Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.724Z",
                "cves": [
                    "CVE-2019-0708"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 310,
                "id": 52502,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "Microsoft Windows Remote Desktop Services 'CVE-2019-0708' Remote Code Execution Vulnerability (BlueKeep) (8433973)",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.142Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.777Z",
                "cves": [],
                "cvss_score": 10,
                "cvss_v2_score": 10,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 29,
                "id": 52503,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "Unsupported Unix Operating System",
                "pci_compliance_status": "fail",
                "risk": 1,
                "severity": 3,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.154Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.827Z",
                "cves": [
                    "CVE-2010-0219"
                ],
                "cvss_score": 10,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_version": null,
                "date_closed": "2020-05-22T15:36:42.907Z",
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 302,
                "id": 52504,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "10.0.0.2",
                "location_specifier_id": 192,
                "name": "Apache Axis2 axis2-admin default credentials",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "risk_accepted",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.166Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.887Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 272,
                "id": 52505,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "TLS Version 1.0 Protocol Detection",
                "pci_compliance_status": "fail",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.178Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.937Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 30,
                "id": 52506,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "SSL Version 2 (v2) Protocol Detection",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 4,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.191Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:26.991Z",
                "cves": [],
                "cvss_score": 3.7,
                "cvss_v2_score": 4.3,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 8,
                "id": 52507,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "SSL Weak Cipher Suites Supported",
                "pci_compliance_status": "fail",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 2,
                "updated_at": "2021-06-11T08:37:55.203Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.043Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 272,
                "id": 52508,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "TLS Version 1.0 Protocol Detection",
                "pci_compliance_status": "fail",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.216Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.100Z",
                "cves": [],
                "cvss_score": null,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": null,
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 316,
                "id": 52509,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "172.16.0.5",
                "location_specifier_id": 193,
                "name": "Adobe Flash Player Security Updates(apsb19-46)-Windows",
                "pci_compliance_status": null,
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.228Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.151Z",
                "cves": [],
                "cvss_score": 7.3,
                "cvss_v2_score": 7.5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2020-04-22T15:36:42.907Z",
                "definition_id": 57,
                "id": 52510,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "Unsupported Web Server Detection",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.241Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.209Z",
                "cves": [
                    "CVE-2014-0160"
                ],
                "cvss_score": 7.5,
                "cvss_v2_score": 6.8,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss_version": 2,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 262,
                "id": 52511,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "OpenSSL Heartbeat Information Disclosure (Heartbleed)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "closed",
                "threat": 4,
                "updated_at": "2021-04-02T15:35:27.223Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.247Z",
                "cves": [
                    "CVE-2019-8917",
                    "CVE-2019-9546"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 328,
                "id": 52512,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "SolarWinds Orion NPM < 12.4 RCE Vulnerability (5796)",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "closed",
                "threat": 5,
                "updated_at": "2021-04-02T15:35:27.269Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.292Z",
                "cves": [],
                "cvss_score": 7.3,
                "cvss_v2_score": 7.5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvss_version": 3,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 33,
                "id": 52513,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "JBoss Administration Console Default Credentials",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "closed",
                "threat": 4,
                "updated_at": "2021-04-02T15:35:27.306Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.330Z",
                "cves": [
                    "CVE-2017-1000353",
                    "CVE-2017-1000354",
                    "CVE-2017-1000355",
                    "CVE-2017-1000356"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 306,
                "id": 52514,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "closed",
                "threat": 5,
                "updated_at": "2021-04-02T15:35:27.344Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.368Z",
                "cves": [
                    "CVE-1999-0517"
                ],
                "cvss_score": 7.5,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "cvss_version": 2,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 41,
                "id": 52515,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "SNMP Agent Default Community Name (public)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "closed",
                "threat": 4,
                "updated_at": "2021-04-02T15:35:27.382Z"
            },
            {
                "altered_score": false,
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.404Z",
                "cves": [
                    "CVE-2019-0708"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": "2021-03-23T12:10:53.359Z",
                "date_opened": "2021-03-23T12:09:41.810Z",
                "definition_id": 310,
                "id": 52516,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "192.168.0.102",
                "location_specifier_id": 191,
                "name": "Microsoft Windows Remote Desktop Services 'CVE-2019-0708' Remote Code Execution Vulnerability (BlueKeep) (8433973)",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "closed",
                "threat": 5,
                "updated_at": "2021-04-02T15:35:27.418Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.553Z",
                "cves": [
                    "CVE-2012-2733",
                    "CVE-2012-3546",
                    "CVE-2012-4431",
                    "CVE-2012-4534",
                    "CVE-2012-5885",
                    "CVE-2012-5886",
                    "CVE-2013-2067"
                ],
                "cvss_score": 6.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "cvss_version": 2,
                "date_closed": null,
                "date_opened": "2018-08-26T15:48:14.313Z",
                "definition_id": 176,
                "id": 52517,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "api.edgebank.com",
                "location_specifier_id": null,
                "name": "HSTS Missing From HTTPS Server",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.253Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.612Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2018-08-26T15:48:14.313Z",
                "definition_id": 272,
                "id": 52518,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "api.edgebank.com",
                "location_specifier_id": null,
                "name": "TLS Version 1.0 Protocol Detection",
                "pci_compliance_status": "fail",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 2,
                "updated_at": "2021-06-11T08:37:55.266Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.666Z",
                "cves": [
                    "CVE-2016-2183",
                    "CVE-2016-6329"
                ],
                "cvss_score": 7.5,
                "cvss_v2_score": 5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2018-08-26T15:48:14.313Z",
                "definition_id": 266,
                "id": 52519,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "api.edgebank.com",
                "location_specifier_id": null,
                "name": "SSL 64-bit Block Size Cipher Suites Supported (SWEET32)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.277Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.728Z",
                "cves": [],
                "cvss_score": 5,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_version": null,
                "date_closed": "2020-02-17T10:56:11.557Z",
                "date_opened": "2018-10-23T15:48:14.313Z",
                "definition_id": 112,
                "id": 52520,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/Passwordreset",
                "location_specifier_id": null,
                "name": "Password field submitted using GET method",
                "pci_compliance_status": "fail",
                "risk": 2,
                "severity": 2,
                "status": "closed",
                "threat": 2,
                "updated_at": "2021-04-02T15:35:27.757Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.795Z",
                "cves": [],
                "cvss_score": 5.5,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/Au:S/C:P/I:P/A:N",
                "cvss_version": 2,
                "date_closed": null,
                "date_opened": "2018-12-27T15:48:14.313Z",
                "definition_id": 294,
                "id": 52521,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createToken",
                "location_specifier_id": null,
                "name": "API Token Brute Force",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.296Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.863Z",
                "cves": [],
                "cvss_score": 7.5,
                "cvss_v2_score": 6.4,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2018-12-27T15:48:14.313Z",
                "definition_id": 66,
                "id": 52522,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/Transactions",
                "location_specifier_id": null,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.309Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.934Z",
                "cves": [],
                "cvss_score": 10,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2018-12-27T15:48:14.313Z",
                "definition_id": 251,
                "id": 52523,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank.com/api/v1/users.json",
                "location_specifier_id": null,
                "name": "Unencrypted communications",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.321Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:27.993Z",
                "cves": [],
                "cvss_score": 2,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2019-08-15T09:43:11.938Z",
                "definition_id": 305,
                "id": 52524,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createToken",
                "location_specifier_id": null,
                "name": "Lack of Input Validation(stored)",
                "pci_compliance_status": "pass",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 2,
                "updated_at": "2021-06-11T08:37:55.333Z"
            },
            {
                "altered_score": false,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:28.061Z",
                "cves": [
                    "CVE-2013-2566",
                    "CVE-2015-2808"
                ],
                "cvss_score": 5.9,
                "cvss_v2_score": 4.3,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss_version": 3,
                "date_closed": "2020-02-17T10:56:11.557Z",
                "date_opened": "2019-11-01T09:57:01.592Z",
                "definition_id": 7,
                "id": 52525,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "api.edgebank.com",
                "location_specifier_id": null,
                "name": "SSL RC4 Cipher Suites Supported",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:28.104Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:28.152Z",
                "cves": [],
                "cvss_score": 7.1,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-02-17T10:56:11.557Z",
                "definition_id": 311,
                "id": 52526,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank.com/v1/updatebalance",
                "location_specifier_id": null,
                "name": "Mass Assignment",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.345Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:28.214Z",
                "cves": [],
                "cvss_score": 4.3,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-02-17T10:56:11.557Z",
                "definition_id": 312,
                "id": 52527,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/Transactions",
                "location_specifier_id": null,
                "name": "Broken object level authorization",
                "pci_compliance_status": "fail",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 2,
                "updated_at": "2021-06-11T08:37:55.357Z"
            },
            {
                "altered_score": true,
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "confidence": null,
                "created_at": "2021-04-02T15:35:28.281Z",
                "cves": [],
                "cvss_score": 4.9,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2020-02-17T10:56:11.557Z",
                "definition_id": 313,
                "id": 52528,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createuser",
                "location_specifier_id": null,
                "name": "Lack of Resources & Rate Limiting",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.371Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.510Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 4.3,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 251,
                "id": 52529,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/",
                "location_specifier_id": 200,
                "name": "Unencrypted communications",
                "pci_compliance_status": "fail",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.388Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.566Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52530,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.477Z"
            },
            {
                "altered_score": true,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.648Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 6.4,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 66,
                "id": 52531,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Addresss/7",
                "location_specifier_id": 200,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.490Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.748Z",
                "cves": [],
                "cvss_score": 7.5,
                "cvss_v2_score": 6.4,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 66,
                "id": 52532,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Cards/",
                "location_specifier_id": 200,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.502Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.816Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52533,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Challenges/",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:28.839Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.883Z",
                "cves": [],
                "cvss_score": 7.5,
                "cvss_v2_score": 6.4,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 66,
                "id": 52534,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Complaints/",
                "location_specifier_id": 200,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4,
                "updated_at": "2021-06-11T08:37:55.516Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:28.951Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52535,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Quantitys/",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:28.979Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.020Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52536,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/assets/i18n/en.json",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.050Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.086Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52537,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/main-es2018.js",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.112Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.147Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52538,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/polyfills-es2018.js",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.170Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.204Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52539,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.227Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.257Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": null,
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 128,
                "id": 52540,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 200,
                "name": "Private IP addresses disclosed",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.528Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.315Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52541,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/admin/application-version",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.337Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.369Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52542,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/products/search",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.391Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.447Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52543,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/saveLoginIp",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.471Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.498Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 5,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 72,
                "id": 52544,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/saveLoginIp",
                "location_specifier_id": 200,
                "name": "Email addresses disclosed",
                "pci_compliance_status": "fail",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.540Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 31,
                "created_at": "2021-04-02T15:35:29.558Z",
                "cves": [],
                "cvss_score": 10,
                "cvss_v2_score": 10,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 79,
                "id": 52545,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/user/login",
                "location_specifier_id": 200,
                "name": "SQL injection",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.552Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.620Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52546,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/rest/user/whoami",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.646Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.684Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52547,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/runtime-es2018.js",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.708Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.743Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52548,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/socket.io/",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.766Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.794Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": 0,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:N/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 80,
                "id": 52549,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/socket.io/",
                "location_specifier_id": 200,
                "name": "HTML does not specify charset",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.565Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.856Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52550,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/vendor-es2018.js",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:29.881Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.917Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 276,
                "id": 52551,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/",
                "location_specifier_id": 202,
                "name": "Strict transport security not enforced",
                "pci_compliance_status": "pass",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.578Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:29.976Z",
                "cves": [],
                "cvss_score": 3.7,
                "cvss_v2_score": 2.6,
                "cvss_v2_vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 68,
                "id": 52552,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/",
                "location_specifier_id": 202,
                "name": "Cacheable HTTPS response",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.592Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.047Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 325,
                "id": 52553,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/",
                "location_specifier_id": 202,
                "name": "TLS certificate",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.606Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.104Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52554,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.620Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.161Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52555,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.187Z"
            },
            {
                "altered_score": true,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.229Z",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_v2_score": 6.4,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 66,
                "id": 52556,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Challenges/",
                "location_specifier_id": 202,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.633Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.287Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52557,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Challenges/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.320Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.347Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52558,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Challenges/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.375Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.409Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52559,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Feedbacks/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.434Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.462Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52560,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Feedbacks/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.486Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 31,
                "created_at": "2021-04-02T15:35:30.513Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 324,
                "id": 52561,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Feedbacks/",
                "location_specifier_id": 202,
                "name": "HTTP request smuggling",
                "pci_compliance_status": "pass",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.647Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.573Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52562,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Quantitys/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.596Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.623Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52563,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/api/Quantitys/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.668Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.702Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52564,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/i18n/en.json",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.729Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.755Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52565,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/i18n/en.json",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.781Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.815Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52566,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/public/images/products/assets/public/favicon_js.ico",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.838Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.864Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52567,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/public/images/products/assets/public/favicon_js.ico",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.887Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.921Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52568,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/public/images/products/null",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.944Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:30.971Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52569,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/assets/public/images/products/null",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:30.995Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.033Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52570,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.057Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.085Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52571,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.114Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.151Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52572,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.177Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.205Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52573,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.230Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.270Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52574,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/quarantine",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.296Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.323Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52575,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/quarantine",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.347Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.387Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 276,
                "id": 52576,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/polyfills-es2018.js",
                "location_specifier_id": 202,
                "name": "Strict transport security not enforced",
                "pci_compliance_status": "pass",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.660Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.450Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": null,
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 128,
                "id": 52577,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 202,
                "name": "Private IP addresses disclosed",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.672Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.517Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52578,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.543Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.575Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52579,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.600Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.635Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52580,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-version",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.700Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.728Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52581,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-version",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.758Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.797Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52582,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/captcha/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.822Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.848Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52583,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/captcha/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.878Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.936Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52584,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/continue-code",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:31.961Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:31.988Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52585,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/continue-code",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.023Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.066Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52586,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/140/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.092Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.120Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52587,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/140/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.145Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.180Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52588,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/192/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.204Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.231Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52589,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/192/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.257Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.297Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52590,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/206/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.322Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.350Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52591,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/206/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.373Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.411Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52592,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/208/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.436Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.462Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52593,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/208/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.486Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.522Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52594,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/3/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.547Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.577Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52595,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/3/reviews",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.602Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.643Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52596,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/search",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.697Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.744Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52597,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/products/search",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.802Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.839Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52598,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/user/whoami",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.865Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.892Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52599,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/user/whoami",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:32.920Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:32.956Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": 0,
                "cvss_v2_vector": "AV:N/AC:L/Au:N/C:N/I:N/A:N",
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cvss_version": 3,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 102,
                "id": 52600,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/robots.txt",
                "location_specifier_id": 202,
                "name": "Robots.txt file",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 1,
                "updated_at": "2021-06-11T08:37:55.684Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.014Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52601,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/robots.txt",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.038Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.065Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52602,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/robots.txt",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.091Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.131Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 276,
                "id": 52603,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/runtime-es2018.js",
                "location_specifier_id": 202,
                "name": "Strict transport security not enforced",
                "pci_compliance_status": "pass",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.695Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.207Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 326,
                "id": 52604,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io/",
                "location_specifier_id": 202,
                "name": "TLS cookie without secure flag set",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.707Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.292Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52605,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.318Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.357Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52606,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.386Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.426Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 326,
                "id": 52607,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io",
                "location_specifier_id": 202,
                "name": "TLS cookie without secure flag set",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.727Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.487Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 323,
                "id": 52608,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.513Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": 91,
                "created_at": "2021-04-02T15:35:33.542Z",
                "cves": [],
                "cvss_score": 0,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "",
                "cvss_version": null,
                "date_closed": "2021-02-22T14:25:01.502Z",
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 322,
                "id": 52609,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/socket.io",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3,
                "updated_at": "2021-04-02T15:35:33.569Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": null,
                "created_at": "2021-04-02T15:35:33.599Z",
                "cves": [],
                "cvss_score": 9.6,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 327,
                "id": 52610,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Complaints/",
                "location_specifier_id": 200,
                "name": "XML external entity injection",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.745Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": null,
                "created_at": "2021-04-02T15:35:33.669Z",
                "cves": [],
                "cvss_score": null,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": null,
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T13:58:30.990Z",
                "definition_id": 300,
                "id": 52611,
                "label": null,
                "last_pci_exception": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/bank/transaction",
                "location_specifier_id": 200,
                "name": "Lack Of Authorization Controls",
                "pci_compliance_status": null,
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 3,
                "updated_at": "2021-06-11T08:37:55.759Z"
            },
            {
                "altered_score": false,
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "confidence": null,
                "created_at": "2021-04-02T15:35:33.749Z",
                "cves": [
                    "CVE-2019-8917",
                    "CVE-2019-9546"
                ],
                "cvss_score": 9.8,
                "cvss_v2_score": null,
                "cvss_v2_vector": null,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "date_closed": null,
                "date_opened": "2021-02-22T14:08:34.970Z",
                "definition_id": 328,
                "id": 52612,
                "label": null,
                "last_pci_exception": null,
                "layer": "network",
                "location": "juice.edgebank.com",
                "location_specifier_id": 201,
                "name": "SolarWinds Orion NPM < 12.4 RCE Vulnerability (5796)",
                "pci_compliance_status": "fail",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5,
                "updated_at": "2021-06-11T08:37:55.772Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Vulnerabilities
>|id|asset_id|name|severity|cvss_score|
>|---|---|---|---|---|
>| 52492 | 164 | SSL Version 2 (v2) Protocol Detection | 4 | 5.3 |
>| 52493 | 164 | SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK) | 3 | 4.3 |
>| 52494 | 164 | DNS Server Recursive Query Cache Poisoning Weakness | 3 | 5.0 |
>| 52495 | 164 | MS17-012: Security Update for Microsoft Windows | 4 | 9.8 |
>| 52496 | 164 | HP System Management Homepage < 6.3 Multiple Vulnerabilities | 5 | 10.0 |
>| 52497 | 164 | Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities | 4 | 9.8 |
>| 52498 | 164 | MySQL 5.6.x < 5.6.39 Multiple Vulnerabilities (January 2018 CPU) (2936) | 3 | 7.5 |
>| 52499 | 164 | Transport Layer Security (TLS) Protocol CRIME Vulnerability | 2 | 2.6 |
>| 52500 | 164 | Citrix NetScaler RCE Vulnerability (CTX267027) - Active Check | 4 | 7.0 |
>| 52501 | 164 | Citrix NetScaler Authentication Bypass Vulnerability | 4 |  |
>| 52502 | 164 | Microsoft Windows Remote Desktop Services 'CVE-2019-0708' Remote Code Execution Vulnerability (BlueKeep) (8433973) | 5 | 9.8 |
>| 52503 | 164 | Unsupported Unix Operating System | 3 | 10.0 |
>| 52504 | 164 | Apache Axis2 axis2-admin default credentials | 5 | 10.0 |
>| 52505 | 164 | TLS Version 1.0 Protocol Detection | 1 | 0.0 |
>| 52506 | 164 | SSL Version 2 (v2) Protocol Detection | 4 | 5.3 |
>| 52507 | 164 | SSL Weak Cipher Suites Supported | 2 | 3.7 |
>| 52508 | 164 | TLS Version 1.0 Protocol Detection | 1 | 0.0 |
>| 52509 | 164 | Adobe Flash Player Security Updates(apsb19-46)-Windows | 4 |  |
>| 52510 | 164 | Unsupported Web Server Detection | 3 | 7.3 |
>| 52511 | 164 | OpenSSL Heartbeat Information Disclosure (Heartbleed) | 4 | 7.5 |
>| 52512 | 164 | SolarWinds Orion NPM < 12.4 RCE Vulnerability (5796) | 5 | 9.8 |
>| 52513 | 164 | JBoss Administration Console Default Credentials | 4 | 7.3 |
>| 52514 | 164 | Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities | 5 | 9.8 |
>| 52515 | 164 | SNMP Agent Default Community Name (public) | 4 | 7.5 |
>| 52516 | 164 | Microsoft Windows Remote Desktop Services 'CVE-2019-0708' Remote Code Execution Vulnerability (BlueKeep) (8433973) | 5 | 9.8 |
>| 52517 | 165 | HSTS Missing From HTTPS Server | 3 | 6.8 |
>| 52518 | 165 | TLS Version 1.0 Protocol Detection | 2 | 5.3 |
>| 52519 | 165 | SSL 64-bit Block Size Cipher Suites Supported (SWEET32) | 4 | 7.5 |
>| 52520 | 165 | Password field submitted using GET method | 2 | 5.0 |
>| 52521 | 165 | API Token Brute Force | 3 | 5.5 |
>| 52522 | 165 | Cross-site scripting (reflected) | 4 | 7.5 |
>| 52523 | 165 | Unencrypted communications | 5 | 10.0 |
>| 52524 | 165 | Lack of Input Validation(stored) | 2 | 2.0 |
>| 52525 | 165 | SSL RC4 Cipher Suites Supported | 3 | 5.9 |
>| 52526 | 165 | Mass Assignment | 4 | 7.1 |
>| 52527 | 165 | Broken object level authorization | 2 | 4.3 |
>| 52528 | 165 | Lack of Resources & Rate Limiting | 3 | 4.9 |
>| 52529 | 167 | Unencrypted communications | 2 | 5.3 |
>| 52530 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52531 | 167 | Cross-site scripting (reflected) | 3 | 5.3 |
>| 52532 | 167 | Cross-site scripting (reflected) | 4 | 7.5 |
>| 52533 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52534 | 167 | Cross-site scripting (reflected) | 4 | 7.5 |
>| 52535 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52536 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52537 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52538 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52539 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52540 | 167 | Private IP addresses disclosed | 1 | 0.0 |
>| 52541 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52542 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52543 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52544 | 167 | Email addresses disclosed | 1 | 5.3 |
>| 52545 | 167 | SQL injection | 5 | 10.0 |
>| 52546 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52547 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52548 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52549 | 167 | HTML does not specify charset | 1 | 0.0 |
>| 52550 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52551 | 167 | Strict transport security not enforced | 2 | 0.0 |
>| 52552 | 167 | Cacheable HTTPS response | 1 | 3.7 |
>| 52553 | 167 | TLS certificate | 1 | 0.0 |
>| 52554 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52555 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52556 | 167 | Cross-site scripting (reflected) | 3 | 5.3 |
>| 52557 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52558 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52559 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52560 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52561 | 167 | HTTP request smuggling | 4 | 0.0 |
>| 52562 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52563 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52564 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52565 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52566 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52567 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52568 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52569 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52570 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52571 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52572 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52573 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52574 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52575 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52576 | 167 | Strict transport security not enforced | 2 | 0.0 |
>| 52577 | 167 | Private IP addresses disclosed | 1 | 0.0 |
>| 52578 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52579 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52580 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52581 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52582 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52583 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52584 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52585 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52586 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52587 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52588 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52589 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52590 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52591 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52592 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52593 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52594 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52595 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52596 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52597 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52598 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52599 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52600 | 167 | Robots.txt file | 1 | 0.0 |
>| 52601 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52602 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52603 | 167 | Strict transport security not enforced | 2 | 0.0 |
>| 52604 | 167 | TLS cookie without secure flag set | 1 | 0.0 |
>| 52605 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52606 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52607 | 167 | TLS cookie without secure flag set | 1 | 0.0 |
>| 52608 | 167 | Cross-origin resource sharing: arbitrary origin trusted | 1 | 0.0 |
>| 52609 | 167 | Cross-origin resource sharing | 1 | 0.0 |
>| 52610 | 167 | XML external entity injection | 5 | 9.6 |
>| 52611 | 167 | Lack Of Authorization Controls | 4 |  |
>| 52612 | 167 | SolarWinds Orion NPM < 12.4 RCE Vulnerability (5796) | 5 | 9.8 |


### edgescan-vulnerabilities-get-export
***
Get the full list of vulnerabilities for export


#### Base Command

`edgescan-vulnerabilities-get-export`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetExport | Unknown | The vulnerabilities export list | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-get-details
***
Get vulnerability details


#### Base Command

`edgescan-vulnerabilities-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability details to get details for. Possible values are: . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetDetails | Unknown | The vulnerability details | 


#### Command Example
```!edgescan-vulnerabilities-get-details id=52493```

#### Context Example
```json
{
    "Edgescan": {
        "VulnerabilitiesGetDetails": {
            "altered_score": false,
            "altered_score_reasons": [],
            "asset_id": 164,
            "asset_name": "Edgescan Internal Server Farm",
            "base_score": {},
            "confidence": null,
            "created_at": "2021-04-02T15:35:26.140Z",
            "cves": [
                "CVE-2015-0204"
            ],
            "cvss_score": 4.3,
            "cvss_v2_score": null,
            "cvss_v2_vector": null,
            "cvss_vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
            "cvss_version": 2,
            "cwes": [
                "CWE-310"
            ],
            "date_closed": null,
            "date_opened": "2019-08-15T10:20:51.058Z",
            "definition_id": 137,
            "details": [
                {
                    "html": "<p>The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time Note the fact that the asset is Internally facing make this attack extremely unlikely. However this would equal a PCI failure</p>\n",
                    "id": 52757,
                    "original_detail_hash": "",
                    "parameter_name": null,
                    "parameter_type": null,
                    "port": null,
                    "protocol": null,
                    "screenshot_urls": [],
                    "src": "The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time Note the fact that the asset is Internally facing make this attack extremely unlikely. However this would equal a PCI failure",
                    "type": "generic"
                }
            ],
            "fingerprint": "b2007900d0c016f747ea5fb403b6d9917d73230a",
            "id": 52493,
            "label": null,
            "last_pci_exception": null,
            "layer": "network",
            "location": "192.168.0.1",
            "location_specifier_id": 191,
            "name": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
            "pci_compliance_status": "fail",
            "pci_exceptions": [],
            "risk": 3,
            "risk_acceptance_reasons": [],
            "severity": 3,
            "status": "open",
            "threat": 3,
            "tool_id": null,
            "updated_at": "2021-06-11T08:37:55.020Z"
        }
    }
}
```

#### Human Readable Output

>### Vulnerability ID:52493
>|altered_score|altered_score_reasons|asset_id|asset_name|base_score|confidence|created_at|cves|cvss_score|cvss_v2_score|cvss_v2_vector|cvss_vector|cvss_version|cwes|date_closed|date_opened|definition_id|details|fingerprint|id|label|last_pci_exception|layer|location|location_specifier_id|name|pci_compliance_status|pci_exceptions|risk|risk_acceptance_reasons|severity|status|threat|tool_id|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false |  | 164 | Edgescan Internal Server Farm |  |  | 2021-04-02T15:35:26.140Z | CVE-2015-0204 | 4.3 |  |  | AV:N/AC:M/Au:N/C:N/I:P/A:N | 2 | CWE-310 |  | 2019-08-15T10:20:51.058Z | 137 | {'id': 52757, 'type': 'generic', 'port': None, 'protocol': None, 'original_detail_hash': '', 'parameter_name': None, 'parameter_type': None, 'html': '<p>The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time Note the fact that the asset is Internally facing make this attack extremely unlikely. However this would equal a PCI failure</p>\n', 'screenshot_urls': [], 'src': 'The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time Note the fact that the asset is Internally facing make this attack extremely unlikely. However this would equal a PCI failure'} | b2007900d0c016f747ea5fb403b6d9917d73230a | 52493 |  |  | network | 192.168.0.1 | 191 | SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK) | fail |  | 3 |  | 3 | open | 3 |  | 2021-06-11T08:37:55.020Z |


### edgescan-vulnerabilities-get-query
***
Run a vulnerability query


#### Base Command

`edgescan-vulnerabilities-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_tagged_with_any | Is asset tagged with any. | Optional | 
| risk_more_than | Is risk score more than provided. | Optional | 
| date_opened | The vulnerability opened date. | Optional | 
| id | The vulnerability id. | Optional | 
| severity | The vulnerability severity. | Optional | 
| threat | The vulnerability threat level. | Optional | 
| asset_id | The asset_id associated with the vulnerability. | Optional | 
| asset_name | The asset name associated with the vulnerability. | Optional | 
| risk | The vulnerability risk level. | Optional | 
| cvss_score | The vulnerability CVSS score. | Optional | 
| cvss_vector | The vulnerability CVSS vector. | Optional | 
| cvss_v2_score | The vulnerability CVSS v2 score. | Optional | 
| cvss_version | The CVSS version to query for. | Optional | 
| altered_score | true/false. | Optional | 
| date_opened | The date on which the vulnerability was opened. | Optional | 
| date_closed | The date on which the vulnerability was closed. | Optional | 
| status | The status of the vulnerability. | Optional | 
| pci_compliance_status | The vulnerability pci complience status. | Optional | 
| location | The vulnerability location. | Optional | 
| location_specifier_id | The vulnerability location specifier id. | Optional | 
| confidence | The vulnerability confidence level. | Optional | 
| label | The vulnerability label. | Optional | 
| layer | The vulnerability level. | Optional | 
| last_pci_exception | The vulnerability last PCI exception. | Optional | 
| updated_at | The vulnerability updated at time. | Optional | 
| created_at | The vulnerability created at time. | Optional | 
| name | The vulnerability name. | Optional | 
| date_opened_after | The date the vulnerability was opened after i.e. "2021-04-01T14:27:10.900Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetQuery | Unknown | The result of a vulnerability query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-retest
***
Retest a vulnerability


#### Base Command

`edgescan-vulnerabilities-retest`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability id to retest. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesRetest | Unknown | The Vulnerability retest result | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-risk-accept
***
Rish accept a vulnerability


#### Base Command

`edgescan-vulnerabilities-risk-accept`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The risk accept value. Default is true. | Optional | 
| id | The vulnerability id to risk accept. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesRiskAccept | Unknown | The vulnerability retest result | 


#### Command Example
``` ```

#### Human Readable Output


