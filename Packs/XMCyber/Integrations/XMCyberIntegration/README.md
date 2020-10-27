XMCyber continuously finds attack vectors to critical assets. This integration fetches events (incidents) on changes in the overall risk score, risk to assets, or impacting attack techniques. Additionally incidents are enriched with incoming attack vectors to the incident's endpoints, and critical assets at risk form the incident.
This integration was integrated and tested with version 1.38 of XMCyber
## Configure XMCyber on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XMCyber.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| url | URL | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xmcyber-affected-critical-assets-list
***
List critical assets at risk from an entity and the complexity of the attack


#### Base Command

`xmcyber-affected-critical-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeId | timeId for example timeAgo_days_7 | Optional | 
| entityId | Entity ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| entityId | String | XMCyber Entity ID | 
| XMCyber.criticalAssetsAtRiskList.name | String | Compromising Techinique Name | 
| XMCyber.criticalAssetsAtRiskList.average | Number | Average attack complexity | 
| XMCyber.criticalAssetsAtRiskList.minimum | Number | Minimum attack complexity | 


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
            {
                "average": 6,
                "minimum": 6,
                "name": "LNK-Win10"
            },
            {
                "average": 6,
                "minimum": 6,
                "name": "USERAA04"
            },
            {
                "average": 6,
                "minimum": 6,
                "name": "USERAA99"
            },
            {
                "average": 6,
                "minimum": 6,
                "name": "USERBB05"
            },
            {
                "average": 6,
                "minimum": 6,
                "name": "USERBB07"
            },
            {
                "average": 8,
                "minimum": 8,
                "name": "TerminalServerA"
            },
            {
                "average": 8,
                "minimum": 8,
                "name": "USERAA05"
            },
            {
                "average": 10,
                "minimum": 10,
                "name": "DCA22008R2"
            },
            {
                "average": 10,
                "minimum": 10,
                "name": "artiom"
            },
            {
                "average": 10,
                "minimum": 10,
                "name": "maayan-test-user"
            },
            {
                "average": 11,
                "minimum": 8,
                "name": "artiom AKIA**SLZV"
            },
            {
                "average": 11,
                "minimum": 8,
                "name": "maayan-test-user AKIA**WGSM"
            },
            {
                "average": 11.33,
                "minimum": 6,
                "name": "DCA1NEW"
            },
            {
                "average": 12,
                "minimum": 12,
                "name": "AmazonSSMManagedInstanceCore"
            },
            {
                "average": 12,
                "minimum": 12,
                "name": "LinuxAgent01"
            },
            {
                "average": 12,
                "minimum": 12,
                "name": "LinuxAgent02"
            },
            {
                "average": 14,
                "minimum": 14,
                "name": "IISSERVERB"
            },
            {
                "average": 14,
                "minimum": 10,
                "name": "ssh-from-model (i-0178d087ca0b118f7)"
            },
            {
                "average": 15,
                "minimum": 12,
                "name": "model-bucket-comp-by-user"
            },
            {
                "average": 15,
                "minimum": 12,
                "name": "s3-comp-by-read-data"
            },
            {
                "average": 16,
                "minimum": 12,
                "name": "ec2_struts_2 (i-00aa84a2ffd5bce67)"
            },
            {
                "average": 18,
                "minimum": 14,
                "name": "access-to-model-bucket"
            },
            {
                "average": 20,
                "minimum": 16,
                "name": "model-bucket-from-struts"
            },
            {
                "average": 22,
                "minimum": 22,
                "name": "USERBB03"
            },
            {
                "average": 24,
                "minimum": 24,
                "name": "USERBB01"
            },
            {
                "average": 24,
                "minimum": 24,
                "name": "USERBB32"
            },
            {
                "average": 28,
                "minimum": 28,
                "name": "USERBB31"
            },
            {
                "average": 28,
                "minimum": 28,
                "name": "USERBB36"
            },
            {
                "average": 30,
                "minimum": 30,
                "name": "USERBB27"
            },
            {
                "average": 30,
                "minimum": 30,
                "name": "USERBB50"
            }
        ],
        "entityId": "872743867762485580"
    }
}
```

#### Human Readable Output

>found 36 affected critical assets from 872743867762485580. Top 5:
>
>
>| Asset Display Name | Average Complexity | Minimum Complexity
>| -- | -- | -- |
>| SQLSERVERB | 2 | 2  |
>| USERAA35 | 2 | 2  |
>| USERAA03 | 4 | 4  |
>| USERBB37 | 4 | 4  |
>| WSUSA | 4 | 4  |


### xmcyber-affected-entities-list
***
List all entities at risk from an entity and the complexity of the attack


#### Base Command

`xmcyber-affected-entities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeId | timeId for example timeAgo_days_7 | Optional | 
| entityId | Entity ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| entityId | String | XMCyber Entity ID | 
| XMCyber.entitiesAtRiskList.name | String | Compromising Techinique Name | 
| XMCyber.entitiesAtRiskList.technique | String | The attack technique which compromised the entity | 


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
Check if current XM version supports Demisto integration


#### Base Command

`xmcyber-version-supported`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XMCyber.IsVersion.valid | Boolean | Flag that indicates if the version is valid | 


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


### ip
***
Return data on Entity by IP from XM Cyber


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| entityId | String | XMCyber Entity ID | 
| name | String | Entity Name | 
| isAsset | Boolean | Is Entity a Critical Asset | 
| affectedEntities | Number | Number of unique entities at risk from this entity | 
| averageComplexity | Number | Average complexity to compromise this entity | 
| criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| compromisingTechniques.name | String | Technique compromising this entity | 
| compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| entityType | String | Entity Type | 
| entityReport | String | Link to the Entity Report | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.ASN | String | The autonomous system name for the IP address. | 


#### Command Example
```!ip ip=192.168.170.60```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "192.168.170.60",
        "Score": 3,
        "Type": "ip",
        "Vendor": "XMCyber"
    },
    "IP": {
        "Address": "192.168.170.60",
        "Malicious": {
            "Description": "XM Cyber affected assets low",
            "Vendor": "XMCyber"
        }
    },
    "XMCyber": {
        "affectedEntities": 2,
        "averageComplexity": 8.67,
        "averageComplexityLevel": "low",
        "compromisingTechniques": [
            {
                "count": 78,
                "name": "Script Infector for Shared Files"
            },
            {
                "count": 24,
                "name": "Group Policy Modification"
            }
        ],
        "criticalAssetsAtRisk": 36,
        "criticalAssetsAtRiskLevel": "low",
        "displayName": "USERBB02",
        "entityId": "872743867762485580",
        "entityReport": "https://xmcyber.example.com/#/scenarioHub/entityReport/872743867762485580?timeId=timeAgo_days_7",
        "entityType": "Sensor",
        "isAsset": true
    }
}
```

#### Human Readable Output

>**Resolved the following entities for IP 192.168.170.60**
>
>| Property | Value |
>| -- | -- |
>| Entity Id | 872743867762485580 |
>| Display Name | USERBB02 |
>| Entity Type  | Sensor  |
>| Entity Report | [USERBB02](https://xmcyber.example.com/#/scenarioHub/entityReport/872743867762485580?timeId=timeAgo_days_7) |

### xmcyber-entity-get
***
Return data on Entity by IP or Hostname from XM Cyber


#### Base Command

`xmcyber-entity-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs | Optional | 
| hostname | List of hostnames | Optional | 
| entityId | List of XMCyber Entity IDs | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| entityId | String | XMCyber Entity ID | 
| name | String | Entity Name | 
| isAsset | Boolean | Is Entity a Critical Asset | 
| affectedEntities | Number | Number of unique entities at risk from this entity | 
| averageComplexity | Number | Average complexity to compromise this entity | 
| criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| compromisingTechniques.name | String | Technique compromising this entity | 
| compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| entityType | String | Entity Type | 
| entityReport | String | Link to the Entity Report | 


#### Command Example
```!xmcyber-entity-get ip=172.0.0.1 hostname=pc-5123 entityId=872743867762485580```

#### Context Example
```json
{
    "XMCyber": null
}
```

#### Human Readable Output

>**Matched the following entities**
>
>| Property | Value |
>| -- | -- |
>| Entity Id | 872743867762485580 |
>| Display Name | USERBB02 |
>| Entity Type  | Sensor  |
>| Entity Report | [USERBB02](https://xmcyber.example.com/#/scenarioHub/entityReport/872743867762485580?timeId=timeAgo_days_7) |

### hostname
***
Return data on Entity by hostname from XM Cyber


#### Base Command

`hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | List of hostnames. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| entityId | String | XMCyber Entity ID | 
| name | String | Entity Name | 
| isAsset | Boolean | Is Entity a Critical Asset | 
| affectedEntities | Number | Number of unique entities at risk from this entity | 
| averageComplexity | Number | Average complexity to compromise this entity | 
| criticalAssetsAtRisk | Number | Number of unique critical assets at risk from this entity | 
| averageComplexityLevel | String | Level of the average complexity to compromise this entity | 
| compromisingTechniques.name | String | Technique compromising this entity | 
| compromisingTechniques.count | Number | Number of vectors with this technique compromising this entity | 
| entityType | String | Entity Type | 
| entityReport | String | Link to the Entity Report | 
| Host.Domain | String | The domain of the host. | 
| Host.Hostname | String | The name of the host. | 
| Host.BIOVersion | String | The BIOS version of the host. | 
| Host.ID | String | The unique ID within the tool retrieving the host. | 
| Host.DHCPServer | String | The DHCP server. | 
| Host.IP | String | The IP address of the host. | 
| Host.MACAddress | String | The MAC address of the host. | 
| Host.Memory | String | Memory on the host. | 
| Host.Model | String | The model of the host. | 
| Host.OS | String | Host OS. | 
| Host.OSVersion | String | The OS version of the host. | 
| Host.Processor | String | The processor of the host. | 
| Host.Processors | Number | The number of processors that the host is using. | 


#### Command Example
```!hostname hostname=USERBB02```

#### Context Example
```json
{
    "Endpoint": {
        "Domain": "model3b.domainb.demo",
        "Hostname": "USERBB02",
        "ID": "872743867762485580",
        "IPAddress": [
            "192.168.170.60"
        ],
        "OS": "Windows",
        "OSVersion": "Windows 7 SP 1.0"
    },
    "XMCyber": {
        "affectedEntities": 2,
        "averageComplexity": 8.67,
        "averageComplexityLevel": "low",
        "compromisingTechniques": [
            {
                "count": 78,
                "name": "Script Infector for Shared Files"
            },
            {
                "count": 24,
                "name": "Group Policy Modification"
            }
        ],
        "criticalAssetsAtRisk": 36,
        "criticalAssetsAtRiskLevel": "low",
        "displayName": "USERBB02",
        "entityId": "872743867762485580",
        "entityReport": "https://xmcyber.example.com/#/scenarioHub/entityReport/872743867762485580?timeId=timeAgo_days_7",
        "entityType": "Sensor",
        "isAsset": true
    }
}
```

#### Human Readable Output

>**Matched the following entities for hostname USERBB02**
>
>| Property | Value |
>| -- | -- |
>| Entity Id | 872743867762485580 |
>| Display Name | USERBB02 |
>| Entity Type  | Sensor  |
>| Entity Report | [USERBB02](https://xmcyber.example.com/#/scenarioHub/entityReport/872743867762485580?timeId=timeAgo_days_7) |
