The XM Cyber integration creates unique incidents with valuable data collected daily, and enriches your existing incidents with attack simulation context. This enables you to prioritize your responses based on XM Cyber’s insights.
This integration was integrated and tested with version 1.43.0.355 of XMCyber

## Configure XM Cyber in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | True |
| URL |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of incidents per fetch |  | False |
| First fetch |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
|  |  | False |
|  |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xmcyber-affected-critical-assets-list
***
List critical assets at risk from an entity and the complexity of the attack


#### Base Command

`xmcyber-affected-critical-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeId | The relevant period of time. The options are timeAgo_days_7 (past 7 days) timeAgo_days_14, timeAgo_days_30, or monthly_YYYY_MM for a given year and month. | Optional | 
| entityId | Entity ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.criticalAssetsAtRiskList.name | String | Compromising Technique name | 
| XMCyber.Entity.criticalAssetsAtRiskList.average | Number | Average attack complexity | 
| XMCyber.Entity.criticalAssetsAtRiskList.minimum | Number | Minimum attack complexity | 

### xmcyber-affected-entities-list
***
List all entities at risk from an entity and the complexity of the attack

#### Command Example
```!xmcyber-affected-critical-assets-list entityId=872743867762485580```

#### Context Example
```json
{
    "XMCyber": {
        "criticalAssetsAtRiskList": [
            {
                "average": 2,
                "minimum": 2,
                "name": "SQLSERVERB"
            },
            {
                "average": 2,
                "minimum": 2,
                "name": "USERAA35"
            },
            {
                "average": 4,
                "minimum": 4,
                "name": "USERAA03"
            },
            {
                "average": 4,
                "minimum": 4,
                "name": "USERBB37"
            },
            {
                "average": 4,
                "minimum": 4,
                "name": "WSUSA"
            },
            {
                "average": 4.67,
                "minimum": 4,
                "name": "FileServerA"
            },
        ],
        "entityId": "872743867762485580"
    }
}
```

#### Human Readable Output

>found 6 affected critical assets from 872743867762485580. Top 5:
>
>
>| Asset Display Name | Average Complexity | Minimum Complexity
>| -- | -- | -- |
>| SQLSERVERB | 2 | 2  |
>| USERAA35 | 2 | 2  |
>| USERAA03 | 4 | 4  |
>| USERBB37 | 4 | 4  |
>| WSUSA | 4 | 4  |


#### Base Command

`xmcyber-affected-entities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeId | The relevant period of time. The options are timeAgo_days_7 (past 7 days) timeAgo_days_14, timeAgo_days_30, or monthly_YYYY_MM for a given year and month. | Optional | 
| entityId | Entity ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.entitiesAtRiskList.name | String | Compromising Techinique Name | 
| XMCyber.Entity.entitiesAtRiskList.technique | String | The attack technique which compromised the entity | 

#### Command Example
```!xmcyber-affected-entities-list entityId=872743867762485580```

#### Context Example
```json
{
    "XMCyber": {
        "entitiesAtRiskList": [
            {
                "name": "SQLSERVERB",
                "technique": "Microsoft SQL Credentials Usage"
            },
            {
                "name": "share",
                "technique": "Taint Shared Content"
            }
        ],
        "entityId": "872743867762485580"
    }
}
```

#### Human Readable Output

>found 2 affected entities from 872743867762485580. Top 5:
>
>
>| Display Name | Technique
>| -- | -- |
>| SQLSERVERB | Microsoft SQL Credentials Usage |
>| share | Taint Shared Content |

### xmcyber-version-supported
***
Check if current XM version supports Cortex Xsoar integration


#### Base Command

`xmcyber-version-supported`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Version.valid | Boolean | Flag that indicates if the version is valid | 

#### Command Example
```!xmcyber-version-supported```

#### Context Example
```json
{
    "XMCyber": {
        "IsVersion": {
            "valid": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|valid|
>|---|
>| true |

### xmcyber-version-get
***
Get current xm version


#### Base Command

`xmcyber-version-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Version.system | String | Get current system version | 

#### Command Example
```!xmcyber-version-get```

#### Context Example
```json
{
    "XMCyber": {
        "Version": {
            "db": "4.2.3",
            "north": "1.0.3369+6514",
            "south": "2.1.967.352",
            "system": "1.38.0.12861",
            "updater": "1.4.134.11886"
        }
    }
}
```

#### Human Readable Output

>### Results
>|db|north|south|system|updater|
>|---|---|---|---|---|
>| 4.2.3 | 1.0.3369+6514 | 2.1.967.352 | 1.38.0.12861 | 1.4.134.11886 |

### xmcyber-enrich-from-ip
***
Return data on Entity by IP from XM Cyber


#### Base Command

`xmcyber-enrich-from-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.name | String | Entity Name | 
| XMCyber.Entity.isAsset | Boolean | Entity is a critical asset | 
| XMCyber.Entity.affectedEntities | Number | Number of unique entities at risk from this entity | 
| XMCyber.Entity.averageComplexity | Number | Average complexity to compromise this entity | 
| XMCyber.Entity.criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| XMCyber.Entity.averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| XMCyber.Entity.compromisingTechniques.technique | String | Technique compromising this entity | 
| XMCyber.Entity.compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| XMCyber.Entity.type | String | Entity Type | 
| XMCyber.Entity.report | String | Link to the Entity Report | 
| IP.Address | String | IP address. | 
| Endpoint.Hostname | String | The hostname to matching the IP in XM Cyber | 
| Endpoint.IP | String | IP address | 
| Endpoint.OS | String | OS of the matched endpoint | 

### xmcyber-enrich-from-entityId
***
Return data on Entity by entityId from XM Cyber


#### Base Command

`xmcyber-enrich-from-entityId`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entityId | List of entityIds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.name | String | Entity Name | 
| XMCyber.Entity.isAsset | Boolean | Entity is a critical asset | 
| XMCyber.Entity.affectedEntities | Number | Number of unique entities at risk from this entity | 
| XMCyber.Entity.averageComplexity | Number | Average complexity to compromise this entity | 
| XMCyber.Entity.criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| XMCyber.Entity.averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| XMCyber.Entity.compromisingTechniques.technique | String | Technique compromising this entity | 
| XMCyber.Entity.compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| XMCyber.Entity.type | String | Entity Type | 
| XMCyber.Entity.report | String | Link to the Entity Report | 
| Host.Hostname | String | The name of the host. | 
| Host.ID | String | The unique ID within the tool retrieving the host. | 
| Host.IP | String | The IP address of the host. | 

### xmcyber-enrich-from-hostname
***
Return data on Entity by hostname from XM Cyber


#### Base Command

`xmcyber-enrich-from-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entityId | List of entityIds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.name | String | Entity Name | 
| XMCyber.Entity.isAsset | Boolean | Entity is a critical asset | 
| XMCyber.Entity.affectedEntities | Number | Number of unique entities at risk from this entity | 
| XMCyber.Entity.averageComplexity | Number | Average complexity to compromise this entity | 
| XMCyber.Entity.criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| XMCyber.Entity.averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| XMCyber.Entity.compromisingTechniques.technique | String | Technique compromising this entity | 
| XMCyber.Entity.compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| XMCyber.Entity.type | String | Entity Type | 
| XMCyber.Entity.report | String | Link to the Entity Report | 
| Host.Hostname | String | The name of the host. | 
| Host.ID | String | The unique ID within the tool retrieving the host. | 
| Host.IP | String | The IP address of the host. | 

### xmcyber-enrich-from-fields
***
Return data on an XM entity


#### Base Command

`xmcyber-enrich-from-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Comma-separated list of fields to search for the entity. | Required | 
| values | Comma-separated list of values (in the same order than the fields list) used to search for the entity. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.Entity.id | String | XMCyber Entity ID | 
| XMCyber.Entity.name | String | Entity Name | 
| XMCyber.Entity.isAsset | Boolean | Entity is a critical asset | 
| XMCyber.Entity.affectedEntities | Number | Number of unique entities at risk from this entity | 
| XMCyber.Entity.averageComplexity | Number | Average complexity to compromise this entity | 
| XMCyber.Entity.criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| XMCyber.Entity.averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| XMCyber.Entity.compromisingTechniques.technique | String | Technique compromising this entity | 
| XMCyber.Entity.compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| XMCyber.Entity.type | String | Entity Type | 
| XMCyber.Entity.report | String | Link to the Entity Report | 
| Host.Hostname | String | The name of the host. | 
| Host.ID | String | The unique ID within the tool retrieving the host. | 
| Host.IP | String | The IP address of the host. | 