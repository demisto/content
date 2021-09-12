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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | The format to export: json,csv or xlsx | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile | File | File with the host export information | 


#### Command Example
```!edgescan-host-get-export format=xlsx```

#### Human Readable Output

>### Hosts export
>**No entries.**

#### Context Example
```json
{
   "Info":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
   "Name":"hosts-export-20210709T101848Z.xlsx",
   "Extension":"xlsx",
   "EntryID":"2299@8ed7562a-849d-4bc2-8388-b7e5cf55b5da",
   "Type":"Microsoft OOXML",
   "Size":44329
}
```

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
                "email": "user2@example.com",
                "email_confirmed": true,
                "first_name": "John",
                "id": 586,
                "is_super": true,
                "last_login_time": "2021-06-01T15:26:51.525Z",
                "last_name": "Doe",
                "last_password_reset_time": "2021-03-10T14:47:28.853Z",
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": false,
                "mfa_method": "sms",
                "phone_number": "",
                "phone_number_confirmed": false,
                "updated_at": "2021-06-01T15:26:51.530Z",
                "username": "user2@example.com.8494"
            },
            {
                "account_locked": true,
                "created_at": "2021-06-01T14:46:49.429Z",
                "email": "user1@example.com",
                "email_confirmed": true,
                "first_name": "John",
                "id": 606,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Doe",
                "last_password_reset_time": "2021-06-01T14:47:09.192Z",
                "lock_reason": "Manual",
                "lock_time": "2021-07-08T04:38:56.846Z",
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "00480700772772",
                "phone_number_confirmed": true,
                "updated_at": "2021-07-08T04:38:56.850Z",
                "username": "user1@example.com.0938"
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
>| 586 | user2@example.com.8494 | user2@example.com |  | false |
>| 606 | user1@example.com.0938 | user1@example.com | 00480700772772 | true |
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
            "email": "user2@example.com",
            "email_confirmed": true,
            "first_name": "John",
            "id": 586,
            "is_super": true,
            "last_login_time": "2021-06-01T15:26:51.525Z",
            "last_name": "Doe",
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
            "username": "user2@example.com.8494"
        }
    }
}
```

#### Human Readable Output

>### User
>|id|username|email|phone_number|mfa_enabled|
>|---|---|---|---|---|
>| 586 | user2@example.com.8494 | user2@example.com |  | false |


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
```!edgescan-user-get-query account_locked=false email=user1@example.com email_confirmed=true first_name=John last_name=Doe mfa_enabled=true mfa_method=sms phone_number=00480700772772```

#### Context Example
```json
{
    "Edgescan": {
        "UserGetQuery": [
            {
                "account_locked": false,
                "created_at": "2021-06-01T14:46:49.429Z",
                "email": "user1@example.com",
                "email_confirmed": true,
                "first_name": "John",
                "id": 606,
                "is_super": false,
                "last_login_time": null,
                "last_name": "Doe",
                "last_password_reset_time": "2021-06-01T14:47:09.192Z",
                "lock_reason": null,
                "lock_time": null,
                "mfa_enabled": true,
                "mfa_method": "sms",
                "phone_number": "00480700772772",
                "phone_number_confirmed": true,
                "updated_at": "2021-07-08T04:42:49.462Z",
                "username": "user1@example.com.0938"
            }
        ]
    }
}
```

#### Human Readable Output

>### User query
>|id|username|email|phone_number|mfa_enabled|
>|---|---|---|---|---|
>| 606 | user1@example.com.0938 | user1@example.com | 00480700772772 | true |


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
            "email": "user1@example.com",
            "email_confirmed": true,
            "first_name": "John",
            "id": 606,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Doe",
            "last_password_reset_time": "2021-06-01T14:47:09.192Z",
            "lock_reason": "Manual",
            "lock_time": "2021-07-08T04:44:33.435Z",
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "00480700772772",
            "phone_number_confirmed": true,
            "updated_at": "2021-07-08T04:44:33.438Z",
            "username": "user1@example.com.0938"
        }
    }
}
```

#### Human Readable Output

>### User locked
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | 2021-06-01T14:46:49.429Z | user1@example.com | true | John | 606 | false |  | Doe | 2021-06-01T14:47:09.192Z | Manual | 2021-07-08T04:44:33.435Z | true | sms | 00480700772772 | true | 2021-07-08T04:44:33.438Z | user1@example.com.0938 |


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
            "email": "user1@example.com",
            "email_confirmed": true,
            "first_name": "John",
            "id": 606,
            "is_super": false,
            "last_login_time": null,
            "last_name": "Doe",
            "last_password_reset_time": "2021-06-01T14:47:09.192Z",
            "lock_reason": null,
            "lock_time": null,
            "mfa_enabled": true,
            "mfa_method": "sms",
            "phone_number": "00480700772772",
            "phone_number_confirmed": true,
            "updated_at": "2021-07-08T04:42:49.462Z",
            "username": "user1@example.com.0938"
        }
    }
}
```

#### Human Readable Output

>### User unlocked
>|account_locked|created_at|email|email_confirmed|first_name|id|is_super|last_login_time|last_name|last_password_reset_time|lock_reason|lock_time|mfa_enabled|mfa_method|phone_number|phone_number_confirmed|updated_at|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 2021-06-01T14:46:49.429Z | user1@example.com | true | John | 606 | false |  | Doe | 2021-06-01T14:47:09.192Z |  |  | true | sms | 00480700772772 | true | 2021-07-08T04:42:49.462Z | user1@example.com.0938 |


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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | The format to export: json,csv or xlsx | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile | File | The file with the result of the query | 


#### Command Example
```!edgescan-vulnerabilities-get-export format=xlsx```

#### Context Example
```json
{
   "Info":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
   "Name":"vulnerabilities-export-20210709T101848Z.xlsx",
   "Extension":"xlsx",
   "EntryID":"2299@8ed7562a-849d-4bc2-8388-b7e5cf55b5da",
   "Type":"Microsoft OOXML",
   "Size":44329
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

#### Base Command

`edgescan-vulnerabilities-add-annotation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the vulnerability to add the annotation to. | Required |
| text | The text of the annotation to add. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AnnotationAdd.id | Number | The ID of the added annotation |
| Edgescan.AnnotationAdd.category | String | The category of the added annotation |
| Edgescan.AnnotationAdd.text | String | The text of the added annotation |
| Edgescan.AnnotationAdd.user | String | The user that has added annotation |
| Edgescan.AnnotationAdd.user_id | Number | The user ID of the added annotation |
| Edgescan.AnnotationAdd.created_at | Date | The date when the annoation was added |

#### Command Example
```!edgescan-vulnerabilities-add-annotation id="52492" text="anotherTEST"```

#### Context Example
```json
{
    "Edgescan": {
        "AnnotationAdd": {
            "category": "default",
            "created_at": "2021-08-09T06:49:30.743Z",
            "id": 272,
            "text": "anotherTEST",
            "user": "user@example.com.8494",
            "user_id": 586
        }
    }
}
```

#### Human Readable Output

>### Annotation added:52492
>|category|created_at|id|text|user|user_id|
>|---|---|---|---|---|---|
>| default | 2021-08-09T06:49:30.743Z | 272 | anotherTEST | user@example.com.8494 | 586 |
