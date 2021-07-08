Cloud-based continuous vulnerability management and penetration testing solution.
This integration was integrated and tested with version 1.6 of Edgescan
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
```!edgescan-host-get id=5```


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
```!edgescan-host-update id=150 label=somelabel```


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
            },
            {
                "active_licence": null,
                "asset_status": "onboarding",
                "authenticated": null,
                "blocked_status": "unblocked",
                "created_at": "2021-07-08T04:39:24.284Z",
                "current_assessment": null,
                "host_count": 0,
                "hostname": "",
                "id": 177,
                "last_assessment_date": null,
                "last_host_scan": null,
                "linked_assets": [],
                "location_specifiers": [],
                "name": "EdgescanTest",
                "network_access": "external",
                "next_assessment_date": null,
                "pci_enabled": null,
                "priority": 4,
                "tags": [],
                "type": "net",
                "updated_at": "2021-07-08T04:39:24.284Z"
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
>| 177 | EdgescanTest | onboarding | unblocked |  |


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
```!edgescan-asset-get id=164```

#### Context Example
```json
{
    "Edgescan": {
        "AssetGet": {
            "active_licence": null,
            "api_descriptor": null,
            "assessment_count": 0,
            "assessments": [],
            "asset_status": "onboarding",
            "authenticated": false,
            "blocked_reason": null,
            "blocked_status": "unblocked",
            "container_images": [],
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
            "next_host_scan": null,
            "pci_enabled": null,
            "permissions": [
                "view",
                "edit",
                "create",
                "delete"
            ],
            "points_of_contact": [],
            "priority": 4,
            "schedule": [],
            "tags": [],
            "type": "net",
            "updated_at": "2021-06-11T08:37:55.243Z"
        }
    }
}
```

#### Human Readable Output

>### Asset
>|active_licence|api_descriptor|assessment_count|assessments|asset_status|authenticated|blocked_reason|blocked_status|container_images|created_at|current_assessment|host_count|hostname|id|last_assessment_date|last_host_scan|linked_assets|location_specifiers|name|network_access|next_assessment_date|next_host_scan|pci_enabled|permissions|points_of_contact|priority|schedule|tags|type|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 0 |  | onboarding | false |  | unblocked |  | 2021-04-02T15:35:25.988Z |  | 768 | 192.168.0.0/24, 10.0.0.0/24, 172.16.0.0/24 | 164 | 2021-03-23T12:10:54.815Z |  |  | {'id': 191, 'location': '192.168.0.0/24', 'location_type': 'cidr'},<br/>{'id': 192, 'location': '10.0.0.0/24', 'location_type': 'cidr'},<br/>{'id': 193, 'location': '172.16.0.0/24', 'location_type': 'cidr'} | Edgescan Internal Server Farm | external |  |  |  | view,<br/>edit,<br/>create,<br/>delete |  | 4 |  |  | net | 2021-06-11T08:37:55.243Z |


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
```!edgescan-asset-create id=168 authenticatied=false name=EdgescanTest priority=4 type=net   ```

#### Context Example
```json
{
    "Edgescan": {
        "AssetCreate": {
            "active_licence": null,
            "api_descriptor": null,
            "assessment_count": 0,
            "assessments": [],
            "asset_status": "onboarding",
            "authenticated": null,
            "blocked_reason": null,
            "blocked_status": "unblocked",
            "container_images": [],
            "created_at": "2021-07-08T04:45:01.510Z",
            "current_assessment": null,
            "host_count": 0,
            "hostname": "",
            "id": 178,
            "last_assessment_date": null,
            "last_host_scan": null,
            "linked_assets": [],
            "location_specifiers": [],
            "name": "EdgescanTest",
            "network_access": "external",
            "next_assessment_date": null,
            "next_host_scan": null,
            "pci_enabled": null,
            "points_of_contact": [],
            "priority": 4,
            "schedule": [],
            "tags": [],
            "type": "net",
            "updated_at": "2021-07-08T04:45:01.510Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|active_licence|api_descriptor|assessment_count|assessments|asset_status|authenticated|blocked_reason|blocked_status|container_images|created_at|current_assessment|host_count|hostname|id|last_assessment_date|last_host_scan|linked_assets|location_specifiers|name|network_access|next_assessment_date|next_host_scan|pci_enabled|points_of_contact|priority|schedule|tags|type|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 0 |  | onboarding |  |  | unblocked |  | 2021-07-08T04:45:01.510Z |  | 0 |  | 178 |  |  |  |  | EdgescanTest | external |  |  |  |  | 4 |  |  | net | 2021-07-08T04:45:01.510Z |


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
```!edgescan-asset-delete id=176```

#### Context Example
```json
{
    "Edgescan": {
        "AssetDelete": {
            "active_licence": null,
            "api_descriptor": null,
            "assessment_count": 0,
            "assessments": [],
            "asset_status": "onboarding",
            "authenticated": null,
            "blocked_reason": null,
            "blocked_status": "unblocked",
            "container_images": [],
            "created_at": "2021-07-08T04:32:29.512Z",
            "current_assessment": null,
            "host_count": 0,
            "hostname": "",
            "id": 176,
            "last_assessment_date": null,
            "last_host_scan": null,
            "linked_assets": [],
            "location_specifiers": [],
            "name": "EdgescanTest",
            "network_access": "external",
            "next_assessment_date": null,
            "next_host_scan": null,
            "pci_enabled": null,
            "points_of_contact": [],
            "priority": 4,
            "schedule": [],
            "tags": [],
            "type": "net",
            "updated_at": "2021-07-08T04:40:56.120Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|active_licence|api_descriptor|assessment_count|assessments|asset_status|authenticated|blocked_reason|blocked_status|container_images|created_at|current_assessment|host_count|hostname|id|last_assessment_date|last_host_scan|linked_assets|location_specifiers|name|network_access|next_assessment_date|next_host_scan|pci_enabled|points_of_contact|priority|schedule|tags|type|updated_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 0 |  | onboarding |  |  | unblocked |  | 2021-07-08T04:32:29.512Z |  | 0 |  | 176 |  |  |  |  | EdgescanTest | external |  |  |  |  | 4 |  |  | net | 2021-07-08T04:40:56.120Z |


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
                "account_locked": true,
                "created_at": "2021-06-01T14:46:49.429Z",
                "email": "mdrobniuch@paloaltonetworks.com",
                "email_confirmed": true,
                "first_name": "Maciej",
                "id": 606,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Drobniuch",
                "last_password_reset_time": "2021-06-01T14:47:09.192Z",
                "lock_reason": "Manual",
                "lock_time": "2021-07-08T04:38:56.846Z",
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "0048696894057",
                "phone_number_confirmed": true,
                "updated_at": "2021-07-08T04:38:56.850Z",
                "username": "mdrobniuch@paloaltonetworks.com.0938"
            },
            {
                "account_locked": false,
                "created_at": "2021-07-08T04:27:00.769Z",
                "email": "test@example.com",
                "email_confirmed": false,
                "first_name": "John",
                "id": 613,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Doe",
                "last_password_reset_time": null,
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "+48123123123",
                "phone_number_confirmed": true,
                "updated_at": "2021-07-08T04:27:00.796Z",
                "username": "test.5477"
            },
            {
                "account_locked": false,
                "created_at": "2021-07-08T04:38:21.840Z",
                "email": "test@example.com",
                "email_confirmed": false,
                "first_name": "John",
                "id": 614,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Doe",
                "last_password_reset_time": null,
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "+48123123123",
                "phone_number_confirmed": true,
                "updated_at": "2021-07-08T04:38:21.866Z",
                "username": "test.7119"
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
>| 613 | test.5477 | test@example.com | +48123123123 | true |
>| 614 | test.7119 | test@example.com | +48123123123 | true |


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
```!edgescan-user-get-query account_locked=false email=mdrobniuch@paloaltonetworks.com email_confirmed=true first_name=Maciej last_name=Drobniuch mfa_enabled=true mfa_method=sms phone_number=0048696894057```

#### Context Example
```json
{
    "Edgescan": {
        "UserGetQuery": [
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
                "updated_at": "2021-07-08T04:42:49.462Z",
                "username": "mdrobniuch@paloaltonetworks.com.0938"
            }
        ]
    }
}
```

#### Human Readable Output

>### User query
>|id|username|email|phone_number|mfa_enabled|
>|---|---|---|---|---|
>| 606 | mdrobniuch@paloaltonetworks.com.0938 | mdrobniuch@paloaltonetworks.com | 0048696894057 | true |


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
```!edgescan-user-create username=test email=test@example.com first_name=John is_super=false last_name=Doe mfa_enabled=true phone_number=+48123123123 mfa_method=sms```

#### Context Example
```json
{
    "Edgescan": {
        "UserCreate": {
            "account_locked": false,
            "created_at": "2021-07-08T04:43:58.682Z",
            "email": "test@example.com",
            "email_confirmed": false,
            "first_name": "John",
            "id": 615,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Doe",
            "last_password_reset_time": null,
            "lock_reason": null,
            "lock_time": null,
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "+48123123123",
            "phone_number_confirmed": true,
            "updated_at": "2021-07-08T04:43:58.706Z",
            "username": "test.2987"
        }
    }
}
```

#### Human Readable Output

>### User created
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-07-08T04:43:58.682Z | test@example.com | false | John | 615 | false |  | Doe |  |  |  | true | sms | +48123123123 | true | 2021-07-08T04:43:58.706Z | test.2987 |


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
```!edgescan-user-delete id=613```

#### Context Example
```json
{
    "Edgescan": {
        "UserDelete": {
            "account_locked": false,
            "created_at": "2021-07-08T04:27:00.769Z",
            "email": "test@example.com",
            "email_confirmed": false,
            "first_name": "John",
            "id": 613,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Doe",
            "last_password_reset_time": null,
            "lock_reason": null,
            "lock_time": null,
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "+48123123123",
            "phone_number_confirmed": true,
            "updated_at": "2021-07-08T04:44:07.723Z",
            "username": "8678.test.5477"
        }
    }
}
```

#### Human Readable Output

>### User deleted
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-07-08T04:27:00.769Z | test@example.com | false | John | 613 | false |  | Doe |  |  |  | true | sms | +48123123123 | true | 2021-07-08T04:44:07.723Z | 8678.test.5477 |


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
```!edgescan-user-reset-password id=606```

#### Context Example
```json
{
    "Edgescan": {
        "UserResetPassword": {
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
```!edgescan-user-lock-account id=606```

#### Context Example
```json
{
    "Edgescan": {
        "UserLockAccount": {
            "account_locked": true,
            "created_at": "2021-06-01T14:46:49.429Z",
            "email": "mdrobniuch@paloaltonetworks.com",
            "email_confirmed": true,
            "first_name": "Maciej",
            "id": 606,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Drobniuch",
            "last_password_reset_time": "2021-06-01T14:47:09.192Z",
            "lock_reason": "Manual",
            "lock_time": "2021-07-08T04:44:33.435Z",
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "0048696894057",
            "phone_number_confirmed": true,
            "updated_at": "2021-07-08T04:44:33.438Z",
            "username": "mdrobniuch@paloaltonetworks.com.0938"
        }
    }
}
```

#### Human Readable Output

>### User locked
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | 2021-06-01T14:46:49.429Z | mdrobniuch@paloaltonetworks.com | true | Maciej | 606 | false |  | Drobniuch | 2021-06-01T14:47:09.192Z | Manual | 2021-07-08T04:44:33.435Z | true | sms | 0048696894057 | true | 2021-07-08T04:44:33.438Z | mdrobniuch@paloaltonetworks.com.0938 |


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
            "updated_at": "2021-07-08T04:42:49.462Z",
            "username": "mdrobniuch@paloaltonetworks.com.0938"
        }
    }
}
```

#### Human Readable Output

>### User unlocked
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-06-01T14:46:49.429Z | mdrobniuch@paloaltonetworks.com | true | Maciej | 606 | false |  | Drobniuch | 2021-06-01T14:47:09.192Z |  |  | true | sms | 0048696894057 | true | 2021-07-08T04:42:49.462Z | mdrobniuch@paloaltonetworks.com.0938 |


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
```!edgescan-vulnerabilities-get-export```

#### Context Example
```json
{
    "Edgescan": {
        "VulnerabilitiesGetExport": [
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss_version": 3,
                "cwes": [],
                "date_closed": "2020-02-17 11:04:20 UTC",
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "The remote service accepts connections encrypted using SSL 2.0, which reportedly suffers from several cryptographic flaws and has been deprecated for several years. An attacker may be able to exploit these issues to conduct man-in-the-middle attacks or decrypt communications between the affected service and clients.  \n  \nSee also:  \n  \n [http://www.schneier.com/paper-ssl.pdf](http://www.schneier.com/paper-ssl.pdf)  \n [http://support.microsoft.com/kb/187498](http://support.microsoft.com/kb/187498)  \n [http://www.linux4beginners.info/node/disable-sslv2](http://www.linux4beginners.info/node/disable-sslv2)\n\n\n",
                "id": 52492,
                "label": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "SSL Version 2 (v2) Protocol Detection",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Consult the application's documentation to disable SSL 2.0 and use TLS 1.1, or higher instead. We would advise that you upgrade to the latest safe version.\n\n",
                "risk": 3,
                "severity": 4,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [
                    "CVE-2015-0204"
                ],
                "cvss_score": 4.3,
                "cvss_vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                "cvss_version": 2,
                "cwes": [
                    "CWE-310"
                ],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time. A man-in-the middle attacker may be able to downgrade the session to use EXPORT_RSA cipher suites (e.g. CVE-2015-0204). Thus, it is recommended to remove support for weak cipher suites.\n\n\n",
                "id": 52493,
                "label": null,
                "layer": "network",
                "location": "192.168.0.1",
                "location_specifier_id": 191,
                "name": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Reconfigure the service to remove support for EXPORT_RSA cipher suites.\n\n",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [
                    "CVE-1999-0024"
                ],
                "cvss_score": 5,
                "cvss_vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                "cvss_version": 2,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "It is possible to query the remote name server for third party names.  \n  \nIf this is your internal nameserver, then the attack vector may be limited to employees or guest access if allowed. If you are probing a remote nameserver, then it allows anyone to use it to resolve third party names (such as www.edgescan.com). This allows attackers to perform cache poisoning attacks against this nameserver.  \n  \nIf the host allows these recursive queries via UDP, then the host can be used to 'bounce' Denial of Service attacks against another network or system.\n\n",
                "id": 52494,
                "label": null,
                "layer": "network",
                "location": "10.0.0.2",
                "location_specifier_id": 192,
                "name": "DNS Server Recursive Query Cache Poisoning Weakness",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Restrict recursive queries to the hosts that should use this nameserver (such as those of the LAN connected to it).  \n  \nIf you are using bind 8, you can do this by using the instruction 'allow-recursion' in the 'options' section of your named.conf.  \n  \nIf you are using bind 9, you can define a grouping of internal addresses using the 'acl' command. Then, within the options block, you can explicitly state:  \n'allow-recursion { hosts\\_defined\\_in\\_acl }'  \n  \nIf you are using another name server, consult its documentation.\n\n",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [
                    "CVE-2017-0007",
                    "CVE-2017-0016",
                    "CVE-2017-0039",
                    "CVE-2017-0057",
                    "CVE-2017-0100",
                    "CVE-2017-0104"
                ],
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "cwes": [
                    "CWE-190",
                    "CWE-20",
                    "CWE-200",
                    "CWE-287",
                    "CWE-476"
                ],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "The remote Windows host is missing a security update. It is, therefore, affected by multiple vulnerabilities :\n\nA security feature bypass vulnerability exists in Device Guard due to improper validation of certain elements in a signed PowerShell script. An unauthenticated, remote attacker can exploit this vulnerability to modify the contents of a PowerShell script without invalidating the signature associated with the file, allowing the execution of a malicious script. (CVE-2017-0007)\n\nA denial of service vulnerability exists in the Microsoft Server Message Block 2.0 and 3.0 (SMBv2/SMBv3) client implementations due to improper handling of certain requests sent to the client. An unauthenticated, remote attacker can exploit this issue, via a malicious SMB server, to cause the system to stop responding until it is manually restarted. (CVE-2017-0016)\n\nA remote code execution vulnerability exists due to using an insecure path to load certain dynamic link library (DLL) files. A local attacker can exploit this, via a specially crafted library placed in the path, to execute arbitrary code. (CVE-2017-0039)\n\nAn information disclosure vulnerability exists in Windows dnsclient due to improper handling of certain requests. An unauthenticated, remote attacker can exploit this, by convincing a user to visit a specially crafted web page, to gain access to sensitive information on a targeted workstation. If the target is a server, the attacker can also exploit this issue by tricking the server into sending a DNS query to a malicious DNS server. (CVE-2017-0057)\n\nAn elevation of privilege vulnerability exists in Helppane.exe due to a failure by an unspecified DCOM object, configured to run as the interactive user, to properly authenticate the client. An authenticated, remote attacker can exploit this, via a specially crafted application, to execute arbitrary code in another user's session. (CVE-2017-0100)\n\nAn integer overflow condition exists in the iSNS Server service due to improper validation of input from the client. An unauthenticated, remote attacker can exploit this issue, via a specially crafted application that connects and issues requests to the iSNS server, to execute arbitrary code in the context of the SYSTEM account. (CVE-2017-0104)\n\n",
                "id": 52495,
                "label": null,
                "layer": "network",
                "location": "10.0.0.5",
                "location_specifier_id": 192,
                "name": "MS17-012: Security Update for Microsoft Windows",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Microsoft has released a set of patches for Windows Vista, 2008, 7, 2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
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
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_version": null,
                "cwes": [
                    "CWE-119",
                    "CWE-134",
                    "CWE-20",
                    "CWE-200",
                    "CWE-399"
                ],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "According to the web server's banner, the version of HP System Management Homepage (SMH) hosted on the remote host is earlier than 6.3. Such versions are reportedly affected by the following vulnerabilities :\n\nAn error exists in the function 'fnmatch' in the bundled version of PHP that can lead to stack exhaustion. (CVE-2010-1917)\n\nAn information disclosure vulnerability exists in the 'var_export' function in the bundled version of PHP that can be triggered when handling certain error conditions. (CVE-2010-2531)\n\nA double free vulnerability in the 'ssl3_get_key_exchange()' function in the third-party OpenSSL library could be abused to crash the application. (CVE-2010-2939)\n\nA format string vulnerability in the phar extension in the bundled version of PHP could lead to the disclosure of memory contents and possibly allow execution of arbitrary code via a specially crafted 'phar://' URI. (CVE-2010-2950)\n\nA NULL pointer dereference in 'ZipArchive::getArchiveComment' included with the bundled version of PHP can be abused to crash the application. (CVE-2010-3709)\n\nThe bundled version of libxml2 may read from invalid memory locations when processing malformed XPath expressions, resulting in an application crash.\n(CVE-2010-4008)\n\nAn error in the 'mb_strcut()' function in the bundled version of PHP can be exploited by passing a large 'length' parameter to disclose potentially sensitive information from the heap. (CVE-2010-4156)\n\nAn as-yet unspecified remote code execution vulnerability could allow an authenticated user to execute arbitrary code with system privileges.\n(CVE-2011-1540)\n\nAn as-yet unspecified, unauthorized access vulnerability could lead to a complete system compromise.\n\n\n",
                "id": 52496,
                "label": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "HP System Management Homepage < 6.3 Multiple Vulnerabilities",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Upgrade to HP System Management Homepage 6.3 or later.",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [
                    "CVE-2017-1000353",
                    "CVE-2017-1000354",
                    "CVE-2017-1000355",
                    "CVE-2017-1000356"
                ],
                "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "cwes": [
                    "CWE-287",
                    "CWE-352",
                    "CWE-502"
                ],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "The version of Jenkins running on the remote web server is prior to 2.57 or is a version of Jenkins LTS prior to 2.46.2, or else it is a version of Jenkins Enterprise that is 1.625.x.y prior to 1.625.24.1, 1.651.x.y prior to 1.651.24.1, 2.7.x.0.y prior to 2.7.24.0.1, or 2.x.y.z prior to 2.46.2.1. It is, therefore, affected by multiple vulnerabilities :\n\nA remote code execution vulnerability exists within core/src/main/java/jenkins/model/Jenkins.java that allows an untrusted serialized Java SignedObject to be transfered to the remoting-based Jenkins CLI and deserialized using a new ObjectInputStream. By using a specially crafted request, an unauthenticated, remote attacker can exploit this issue to bypass existing blacklist protection mechanisms and execute arbitrary code. (CVE-2017-1000353)\n\nA flaw exists in the remoting-based CLI, specifically in the ClientAuthenticationCache.java class, when storing the encrypted username of a successfully authenticated user in a cache file that is used to authenticate further commands. An authenticated, remote attacker who has sufficient permissions to create secrets in Jenkins and download their encrypted values can exploit this issue to impersonate any other Jenkins user on the same instance. (CVE-2017-1000354)\n\nA denial of service vulnerability exists in the XStream library. An authenticated, remote attacker who has sufficient permissions, such as creating or configuring items, views or jobs, can exploit this to crash the Java process by using specially crafted XML content.\n(CVE-2017-1000355)\n\nCross-site request forgery (XSRF) vulnerabilities exist within multiple Java classes due to a failure to require multiple steps, explicit confirmation, or a unique token when performing certain sensitive actions. An unauthenticated, remote attacker can exploit these to perform several administrative actions by convincing a user into opening a specially crafted web page.\n(CVE-2017-1000356)\n\nNote that Edgescan has not tested for these issues but has instead relied only on the application's self-reported version number.\n",
                "id": 52497,
                "label": null,
                "layer": "network",
                "location": "172.16.0.5",
                "location_specifier_id": 193,
                "name": "Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Upgrade Jenkins to version 2.57 or later, Jenkins LTS to version 2.46.2 or later, or Jenkins Enterprise to version 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 or later.",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
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
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvss_version": null,
                "cwes": [
                    "CWE-125",
                    "CWE-787"
                ],
                "date_closed": null,
                "date_opened": "2019-08-15 10:20:51 UTC",
                "description": "The version of MySQL running on the remote host is 5.6.x prior to 5.6.39. It is, therefore, affected by multiple vulnerabilities as noted in the January 2018 Critical Patch Update advisory. Please consult the CVRF details for the applicable CVEs for additional information.\n\nNote that Edgescan has not tested for these issues but has instead relied only on the application's self-reported version number.\n\n",
                "id": 52498,
                "label": null,
                "layer": "network",
                "location": "10.0.0.9",
                "location_specifier_id": 192,
                "name": "MySQL 5.6.x < 5.6.39 Multiple Vulnerabilities (January 2018 CPU) (2936)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Upgrade to MySQL version 5.6.39 or later.",
                "risk": 4,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [
                    "CVE-2019-0708"
                ],
                "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": null,
                "cwes": [
                    "CWE-416"
                ],
                "date_closed": null,
                "date_opened": "2020-04-22 15:36:42 UTC",
                "description": "By sending a crafted request the RDP service answered with a 'MCS Disconnect Provider Ultimatum PDU - 2.2.2.3' response which indicates that a RCE attack can be executed.\n\nA remote code execution vulnerability exists in Remote Desktop Services \u2013 formerly known as Terminal Services \u2013 when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests. This vulnerability is pre-authentication and requires no user interaction. An attacker who successfully exploited this vulnerability could execute arbitrary code on the target system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.\n\nFor further information:\nhttps://www.cvedetails.com/cve/CVE-2019-0708 \n\n",
                "id": 52502,
                "label": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "Microsoft Windows Remote Desktop Services 'CVE-2019-0708' Remote Code Execution Vulnerability (BlueKeep) (8433973)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "The vendor has released updates. Please see the references for more information.\n\nAs a workaround, enable Network Level Authentication (NLA) on systems running supported editions of Windows 7, Windows Server 2008, and Windows Server 2008 R2.\n\nNOTE: Even after enabling NLA, affected systems may still be vulnerable to Remote Code Execution (RCE) exploitation if the attacker has valid credentials that can be used to successfully authenticate.\n\nhttps://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708\nhttps://support.microsoft.com/help/4499164\nhttps://support.microsoft.com/help/4499175\nhttps://support.microsoft.com/help/4499149\nhttps://support.microsoft.com/help/4499180\nhttps://support.microsoft.com/help/4500331\nhttps://blogs.technet.microsoft.com/msrc/2019/05/14/prevent-a-worm-by-updating-remote-desktop-services-cve-2019-0708/\nhttps://support.microsoft.com/en-us/help/4500705/customer-guidance-for-cve-2019-0708\nhttps://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732713(v=ws.11)\nhttp://www.securityfocus.com/bid/108273\nhttp://packetstormsecurity.com/files/153133/Microsoft-Windows-Remote-Desktop-BlueKeep-Denial-Of-Service.html\nhttps://www.malwaretech.com/2019/05/analysis-of-cve-2019-0708-bluekeep.html\nhttps://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5
            },
            {
                "asset_id": 164,
                "asset_name": "Edgescan Internal Server Farm",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 10,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_version": 3,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2020-04-22 15:36:42 UTC",
                "description": "According to its version, the remote Unix operating system is obsolete and is no longer maintained by its vendor or provider. Lack of support implies that no new security patches will be released for it.\n\n\n\n\n",
                "id": 52503,
                "label": null,
                "layer": "network",
                "location": "192.168.0.101",
                "location_specifier_id": 191,
                "name": "Unsupported Unix Operating System",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Upgrade to a newer version.\n\n",
                "risk": 1,
                "severity": 3,
                "status": "open",
                "threat": 1
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 5,
                "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2020-02-17 10:56:11 UTC",
                "date_opened": "2018-10-23 15:48:14 UTC",
                "description": "The application uses the GET method to submit passwords, which are transmitted within the query string of the requested URL. Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. They may be disclosed to third parties via the Referer header when any off-site links are followed. Placing passwords into the URL increases the risk that they will be captured by an attacker.",
                "id": 52520,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/Passwordreset",
                "location_specifier_id": null,
                "name": "Password field submitted using GET method",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "All forms submitting passwords should use the POST method. To achieve this, you should specify the method attribute of the FORM tag as method=\"POST\". It may also be necessary to modify the corresponding server-side form handler to ensure that submitted passwords are properly retrieved from the message body, rather than the URL.",
                "risk": 2,
                "severity": 2,
                "status": "closed",
                "threat": 2
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 5.5,
                "cvss_vector": "AV:N/AC:L/Au:S/C:P/I:P/A:N",
                "cvss_version": 2,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2018-12-27 15:48:14 UTC",
                "description": "Tokens are signed to protect against manipulation, they are not encrypted. What this means is that a token can be easily decoded and its contents revealed if the Token is not generated to a secure standard. The API Relies on a single Token for authentication of every request sent. The Token is a string of 10 characters long, however it appears that only the final 5 characters in the String are random. Through brute forcing edgescan was able to find 3 valid tokens which were previously unknown. \n\n",
                "id": 52521,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createToken",
                "location_specifier_id": null,
                "name": "API Token Brute Force",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Token based authentication should include completely random strings of maximum possible length and where possible should change with each request and enforce best practice with regards to expiry. The API Should also implement a mechanism where brute forcing is blocked based on a number of incorrect guesses. To get started with securing your Token the following checklist should be stepped through as a minimum requirement.\n\nKeep it secret. Keep it safe. The signing key should be treated like any other credentials and revealed only to services that absolutely need it.\n\nDo not add sensitive data to the payload. Tokens are signed to protect against manipulation and are easily decoded. Add the bare minimum number of claims to the payload for best performance and security.\n\nGive tokens an expiration. Technically, once a token is signed \u2013 it is valid forever \u2013 unless the signing key is changed or expiration explicitly set. This could pose potential issues so have a strategy for expiring and/or revoking tokens\n\nEmbrace HTTPS. Do not send tokens over non-HTTPS connections as those requests can be intercepted and tokens compromised.\n\nConsider all of your authorization use cases. Adding a secondary token verification system that ensure tokens were generated from your server, for example, may not be common practice, but may be necessary to meet your requirements.\n\n",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_version": 3,
                "cwes": [
                    "CWE-79"
                ],
                "date_closed": null,
                "date_opened": "2018-12-27 15:48:14 UTC",
                "description": "Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request which, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.  \n  \nThe attacker-supplied code can perform a wide variety of actions, such as  \n- Session hijacking  \n- Site defacement potential  \n- Network scanning  \n- Undermining CSRF defenses  \n- Site redirection/phishing  \n- Data theft  \n- Keystroke logging  \n- Loading of remotely hosted scripts  \n  \n  \nUsers can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site which causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).  \n  \nThe security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality which it contains, and the other applications which belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain which can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization which owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application, and exploiting users' trust in the organization in order to capture credentials for other applications which it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk.\n\n\n\n",
                "id": 52522,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/Transactions",
                "location_specifier_id": null,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:\n\n- Input should be validated as strictly as possible on arrival, given the kind of content which it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized. \n- User input should be contextually encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc). Javascript and CSS encoding needs to also be considered. \n - JavaScript Sanitation  \nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task. - JavaScript Sanitization",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 10,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2018-12-27 15:48:14 UTC",
                "description": "The application allows users to connect to it over unencrypted connections. An attacker suitably positioned to view a legitimate user's network traffic could record and monitor their interactions with the application and obtain any information the user supplies. Furthermore, an attacker able to modify traffic could use the application as a platform for attacks against its users and third-party websites. Unencrypted connections have been exploited by ISPs and governments to track users, and to inject adverts and malicious JavaScript. Due to these concerns, web browser vendors are planning to visually flag unencrypted connections as hazardous.\n\nTo exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.\n\nPlease note that using a mixture of encrypted and unencrypted communications is an ineffective defense against active attackers, because they can easily remove references to encrypted resources when these references are transmitted over an unencrypted connection.\n\n\n",
                "id": 52523,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank.com/api/v1/users.json",
                "location_specifier_id": null,
                "name": "Unencrypted communications",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Applications should use transport-level encryption (SSL/TLS) to protect all communications passing between the client and the server. The Strict-Transport-Security HTTP header should be used to ensure that clients refuse to access the server over an insecure connection.",
                "risk": 5,
                "severity": 5,
                "status": "open",
                "threat": 5
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 2,
                "cvss_vector": "AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2019-08-15 09:43:11 UTC",
                "description": "A lack of input validation can result in a number of client-side vulnerabilities, including cross-site scripting, open redirection, content spoofing, and response header injection. Additionally, some server-side vulnerabilities such as SQL injection are often easier to identify and exploit when input is returned in responses.\n\n",
                "id": 52524,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createToken",
                "location_specifier_id": null,
                "name": "Lack of Input Validation(stored)",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Input should be validated as strictly as possible on arrival, given the kind of content which it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized.\nUser input should be contextually encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (< > etc). Javascript and CSS encoding needs to also be considered.\nJavaScript Sanitation\nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task. - JavaScript Sanitization",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 2
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [
                    "CVE-2013-2566",
                    "CVE-2015-2808"
                ],
                "cvss_score": 5.9,
                "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss_version": 3,
                "cwes": [
                    "CWE-326",
                    "CWE-327"
                ],
                "date_closed": "2020-02-17 10:56:11 UTC",
                "date_opened": "2019-11-01 09:57:01 UTC",
                "description": "The remote host supports the use of RC4 in one or more cipher suites. The RC4 cipher is flawed in its generation of a pseudo-random stream of bytes so that a wide variety of small biases are introduced into the stream, decreasing its randomness. If plaintext is repeatedly encrypted (e.g. HTTP cookies), and an attacker is able to obtain many (i.e. tens of millions) ciphertexts, the attacker may be able to derive the plaintext.  \nSome useful information about RC4 ciphers.  \n **https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf**\n\n",
                "id": 52525,
                "label": null,
                "layer": "network",
                "location": "api.edgebank.com",
                "location_specifier_id": null,
                "name": "SSL RC4 Cipher Suites Supported",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Reconfigure the affected application, if possible, to avoid use of RC4 ciphers.\n\n",
                "risk": 3,
                "severity": 3,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 165,
                "asset_name": "Edgebank API",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 4.9,
                "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2020-02-17 10:56:11 UTC",
                "description": "Quite often, APIs do not impose any restrictions on the size or number of resources that can be requested by the client/user. Not only can this impact the API server performance, leading to Denial of Service (DoS), but also leaves the door open to authentication flaws such as brute force.\n\n",
                "id": 52528,
                "label": null,
                "layer": "application",
                "location": "http://api.edgebank/v1/createuser",
                "location_specifier_id": null,
                "name": "Lack of Resources & Rate Limiting",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "-Define proper rate limiting.\n-Limit payload sizes.\n-Tailor the rate limiting to be match what API methods, clients, or addresses need or should be allowed to get.\n-Add checks on compression ratios.\n-Define limits for container resources.",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": 3,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "The application allows users to connect to it over unencrypted connections. An attacker suitably positioned to view a legitimate user's network traffic could record and monitor their interactions with the application and obtain any information the user supplies. Furthermore, an attacker able to modify traffic could use the application as a platform for attacks against its users and third-party websites. Unencrypted connections have been exploited by ISPs and governments to track users, and to inject adverts and malicious JavaScript. Due to these concerns, web browser vendors are planning to visually flag unencrypted connections as hazardous.\n\nTo exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.\n\nPlease note that using a mixture of encrypted and unencrypted communications is an ineffective defense against active attackers, because they can easily remove references to encrypted resources when these references are transmitted over an unencrypted connection.\n\n\n",
                "id": 52529,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/",
                "location_specifier_id": 200,
                "name": "Unencrypted communications",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Applications should use transport-level encryption (SSL/TLS) to protect all communications passing between the client and the server. The Strict-Transport-Security HTTP header should be used to ensure that clients refuse to access the server over an insecure connection.",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nIf another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.\n\nEven if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.\n\n",
                "id": 52530,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Any inappropriate domains should be removed from the CORS policy.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss_version": 3,
                "cwes": [
                    "CWE-79"
                ],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request which, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.  \n  \nThe attacker-supplied code can perform a wide variety of actions, such as  \n- Session hijacking  \n- Site defacement potential  \n- Network scanning  \n- Undermining CSRF defenses  \n- Site redirection/phishing  \n- Data theft  \n- Keystroke logging  \n- Loading of remotely hosted scripts  \n  \n  \nUsers can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site which causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).  \n  \nThe security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality which it contains, and the other applications which belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain which can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization which owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application, and exploiting users' trust in the organization in order to capture credentials for other applications which it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk.\n\n\n\n",
                "id": 52531,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Addresss/7",
                "location_specifier_id": 200,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:\n\n- Input should be validated as strictly as possible on arrival, given the kind of content which it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized. \n- User input should be contextually encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc). Javascript and CSS encoding needs to also be considered. \n - JavaScript Sanitation  \nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task. - JavaScript Sanitization",
                "risk": 3,
                "severity": 3,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_version": 3,
                "cwes": [
                    "CWE-79"
                ],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request which, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.  \n  \nThe attacker-supplied code can perform a wide variety of actions, such as  \n- Session hijacking  \n- Site defacement potential  \n- Network scanning  \n- Undermining CSRF defenses  \n- Site redirection/phishing  \n- Data theft  \n- Keystroke logging  \n- Loading of remotely hosted scripts  \n  \n  \nUsers can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site which causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).  \n  \nThe security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality which it contains, and the other applications which belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain which can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization which owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application, and exploiting users' trust in the organization in order to capture credentials for other applications which it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk.\n\n\n\n",
                "id": 52532,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/api/Cards/",
                "location_specifier_id": 200,
                "name": "Cross-site scripting (reflected)",
                "pci_compliance_status": "fail",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:\n\n- Input should be validated as strictly as possible on arrival, given the kind of content which it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized. \n- User input should be contextually encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc). Javascript and CSS encoding needs to also be considered. \n - JavaScript Sanitation  \nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task. - JavaScript Sanitization",
                "risk": 4,
                "severity": 4,
                "status": "open",
                "threat": 4
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nIf another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.\n\nEven if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.\n\n",
                "id": 52536,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/assets/i18n/en.json",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Any inappropriate domains should be removed from the CORS policy.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nIf another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.\n\nEven if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.\n\n",
                "id": 52537,
                "label": null,
                "layer": "application",
                "location": "http://juice.edgebank.com/main-es2018.js",
                "location_specifier_id": 200,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Any inappropriate domains should be removed from the CORS policy.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nTrusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.\n\nIf the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to bypass any IP-based access controls by proxying through users' browsers.\n\n",
                "id": 52572,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nIf another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.\n\nEven if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.\n\n",
                "id": 52573,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Any inappropriate domains should be removed from the CORS policy.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nTrusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.\n\nIf the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to bypass any IP-based access controls by proxying through users' browsers.\n\n",
                "id": 52574,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/quarantine",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing: arbitrary origin trusted",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": "2021-02-22 14:25:01 UTC",
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.\n\nIf another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.\n\nEven if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by an attacker to exploit the trust relationship and attack the application that allows access. CORS policies on pages containing sensitive information should be reviewed to determine whether it is appropriate for the application to trust both the intentions and security posture of any domains granted access.\n\n",
                "id": 52575,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/ftp/quarantine",
                "location_specifier_id": 202,
                "name": "Cross-origin resource sharing",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "Any inappropriate domains should be removed from the CORS policy.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "closed",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": "",
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "The application fails to prevent users from connecting to it over unencrypted connections. An attacker able to modify a legitimate user's network traffic could bypass the application's use of SSL/TLS encryption, and use the application as a platform for attacks against its users. This attack is performed by rewriting HTTPS links as HTTP, so that if a targeted user follows a link to the site from an HTTP page, their browser never attempts to use an encrypted connection. The sslstrip tool automates this process.\n\nTo exploit this vulnerability, an attacker must be suitably positioned to intercept and modify the victim's network traffic.This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.\n\n",
                "id": 52576,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/polyfills-es2018.js",
                "location_specifier_id": 202,
                "name": "Strict transport security not enforced",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "The application should instruct web browsers to only access the application using HTTPS. To do this, enable HTTP Strict Transport Security (HSTS) by adding a response header with the name 'Strict-Transport-Security' and the value 'max-age=expireTime', where expireTime is the time in seconds that browsers should remember that the site should only be accessed using HTTPS. Consider adding the 'includeSubDomains' flag if appropriate.\n\nNote that because HSTS is a \"trust on first use\" (TOFU) protocol, a user who has never accessed the application will never have seen the HSTS header, and will therefore still be vulnerable to SSL stripping attacks. To mitigate this risk, you can optionally add the 'preload' flag to the HSTS header, and submit the domain for review by browser vendors.\n\n",
                "risk": 2,
                "severity": 2,
                "status": "open",
                "threat": 3
            },
            {
                "asset_id": 167,
                "asset_name": "Edgebank - Juiceshop - Updated",
                "asset_tags": "",
                "cves": [],
                "cvss_score": 0,
                "cvss_vector": null,
                "cvss_version": null,
                "cwes": [],
                "date_closed": null,
                "date_opened": "2021-02-22 13:58:30 UTC",
                "description": "RFC 1918 specifies ranges of IP addresses that are reserved for use in private networks and cannot be routed on the public Internet. Although various methods exist by which an attacker can determine the public IP addresses in use by an organization, the private addresses used internally cannot usually be determined in the same ways.  \n  \nDiscovering the private addresses used within an organization can help an attacker in carrying out network-layer attacks aiming to penetrate the organization's internal infrastructure.\n\n",
                "id": 52577,
                "label": null,
                "layer": "application",
                "location": "https://juice.edgebank.com/rest/admin/application-configuration",
                "location_specifier_id": 202,
                "name": "Private IP addresses disclosed",
                "pci_compliance_status": "pass",
                "pci_exception": "none",
                "pci_exception_description": null,
                "pci_exception_expiry": null,
                "remediation": "There is not usually any good reason to disclose the internal IP addresses used within an organization's infrastructure. If these are being returned in service banners or debug messages, then the relevant services should be configured to mask the private addresses. If they are being used to track back-end servers for load balancing purposes, then the addresses should be rewritten with innocuous identifiers from which an attacker cannot infer any useful information about the infrastructure.\n\n",
                "risk": 1,
                "severity": 1,
                "status": "open",
                "threat": 3
            },

        ]
    }
}
```

#### Human Readable Output

>### Results
>|asset_id|asset_name|asset_tags|cves|cvss_score|cvss_vector|cvss_version|cwes|date_closed|date_opened|description|id|label|layer|location|location_specifier_id|name|pci_compliance_status|pci_exception|pci_exception_description|pci_exception_expiry|remediation|risk|severity|status|threat|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 164 | Edgescan Internal Server Farm |  |  | 5.3 | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 3 |  | 2020-02-17 11:04:20 UTC | 2019-08-15 10:20:51 UTC | The remote service accepts connections encrypted using SSL 2.0, which reportedly suffers from several cryptographic flaws and has been deprecated for several years. An attacker may be able to exploit these issues to conduct man-in-the-middle attacks or decrypt communications between the affected service and clients.  <br/>  <br/>See also:  <br/>  <br/> [http://www.schneier.com/paper-ssl.pdf](http://www.schneier.com/paper-ssl.pdf)  <br/> [http://support.microsoft.com/kb/187498](http://support.microsoft.com/kb/187498)  <br/> [http://www.linux4beginners.info/node/disable-sslv2](http://www.linux4beginners.info/node/disable-sslv2)<br/><br/><br/> | 52492 |  | network | 192.168.0.1 | 191 | SSL Version 2 (v2) Protocol Detection | fail | none |  |  | Consult the application's documentation to disable SSL 2.0 and use TLS 1.1, or higher instead. We would advise that you upgrade to the latest safe version.<br/><br/> | 3 | 4 | closed | 3 |
>| 164 | Edgescan Internal Server Farm |  | CVE-2015-0204 | 4.3 | AV:N/AC:M/Au:N/C:N/I:P/A:N | 2 | CWE-310 |  | 2019-08-15 10:20:51 UTC | The remote host supports EXPORT_RSA cipher suites with keys less than or equal to 512 bits. An attacker can factor a 512-bit RSA modulus in a short amount of time. A man-in-the middle attacker may be able to downgrade the session to use EXPORT_RSA cipher suites (e.g. CVE-2015-0204). Thus, it is recommended to remove support for weak cipher suites.<br/><br/><br/> | 52493 |  | network | 192.168.0.1 | 191 | SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK) | fail | none |  |  | Reconfigure the service to remove support for EXPORT_RSA cipher suites.<br/><br/> | 3 | 3 | open | 3 |
>| 164 | Edgescan Internal Server Farm |  | CVE-1999-0024 | 5.0 | AV:N/AC:L/Au:N/C:N/I:P/A:N | 2 |  |  | 2019-08-15 10:20:51 UTC | It is possible to query the remote name server for third party names.  <br/>  <br/>If this is your internal nameserver, then the attack vector may be limited to employees or guest access if allowed. If you are probing a remote nameserver, then it allows anyone to use it to resolve third party names (such as www.edgescan.com). This allows attackers to perform cache poisoning attacks against this nameserver.  <br/>  <br/>If the host allows these recursive queries via UDP, then the host can be used to 'bounce' Denial of Service attacks against another network or system.<br/><br/> | 52494 |  | network | 10.0.0.2 | 192 | DNS Server Recursive Query Cache Poisoning Weakness | fail | none |  |  | Restrict recursive queries to the hosts that should use this nameserver (such as those of the LAN connected to it).  <br/>  <br/>If you are using bind 8, you can do this by using the instruction 'allow-recursion' in the 'options' section of your named.conf.  <br/>  <br/>If you are using bind 9, you can define a grouping of internal addresses using the 'acl' command. Then, within the options block, you can explicitly state:  <br/>'allow-recursion { hosts\_defined\_in\_acl }'  <br/>  <br/>If you are using another name server, consult its documentation.<br/><br/> | 3 | 3 | open | 3 |
>| 164 | Edgescan Internal Server Farm |  | CVE-2017-0007,<br/>CVE-2017-0016,<br/>CVE-2017-0039,<br/>CVE-2017-0057,<br/>CVE-2017-0100,<br/>CVE-2017-0104 | 9.8 | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |  | CWE-190,<br/>CWE-20,<br/>CWE-200,<br/>CWE-287,<br/>CWE-476 |  | 2019-08-15 10:20:51 UTC | The remote Windows host is missing a security update. It is, therefore, affected by multiple vulnerabilities :<br/><br/>A security feature bypass vulnerability exists in Device Guard due to improper validation of certain elements in a signed PowerShell script. An unauthenticated, remote attacker can exploit this vulnerability to modify the contents of a PowerShell script without invalidating the signature associated with the file, allowing the execution of a malicious script. (CVE-2017-0007)<br/><br/>A denial of service vulnerability exists in the Microsoft Server Message Block 2.0 and 3.0 (SMBv2/SMBv3) client implementations due to improper handling of certain requests sent to the client. An unauthenticated, remote attacker can exploit this issue, via a malicious SMB server, to cause the system to stop responding until it is manually restarted. (CVE-2017-0016)<br/><br/>A remote code execution vulnerability exists due to using an insecure path to load certain dynamic link library (DLL) files. A local attacker can exploit this, via a specially crafted library placed in the path, to execute arbitrary code. (CVE-2017-0039)<br/><br/>An information disclosure vulnerability exists in Windows dnsclient due to improper handling of certain requests. An unauthenticated, remote attacker can exploit this, by convincing a user to visit a specially crafted web page, to gain access to sensitive information on a targeted workstation. If the target is a server, the attacker can also exploit this issue by tricking the server into sending a DNS query to a malicious DNS server. (CVE-2017-0057)<br/><br/>An elevation of privilege vulnerability exists in Helppane.exe due to a failure by an unspecified DCOM object, configured to run as the interactive user, to properly authenticate the client. An authenticated, remote attacker can exploit this, via a specially crafted application, to execute arbitrary code in another user's session. (CVE-2017-0100)<br/><br/>An integer overflow condition exists in the iSNS Server service due to improper validation of input from the client. An unauthenticated, remote attacker can exploit this issue, via a specially crafted application that connects and issues requests to the iSNS server, to execute arbitrary code in the context of the SYSTEM account. (CVE-2017-0104)<br/><br/> | 52495 |  | network | 10.0.0.5 | 192 | MS17-012: Security Update for Microsoft Windows | fail | none |  |  | Microsoft has released a set of patches for Windows Vista, 2008, 7, 2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. | 4 | 4 | open | 4 |




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



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetQuery | Unknown | The result of a vulnerability query | 


#### Command Example
```!edgescan-vulnerabilities-get-query id=52517 asset_id=165 severity=3 cvss_score=6.8 location=api.edgebank.com threat=3 asset_name="Edgebank API" risk=3 status=open```

#### Context Example
```json
{
    "Edgescan": {
        "VulnerabilitiesGetQuery": [
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
            }
        ]
    }
}
```

#### Human Readable Output

>### Vulnerabilities
>|id|asset_id|name|severity|cvss_score|
>|---|---|---|---|---|
>| 52517 | 165 | HSTS Missing From HTTPS Server | 3 | 6.8 |


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
```!edgescan-vulnerabilities-retest id=52496```


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
```!edgescan-vulnerabilities-risk-accept id=52496 value=true```


