### EclecticIQ Platform v2
Threat Intelligence Platform that connects and interprets intelligence data from open sources, commercial suppliers and industry partnerships.
This integration was integrated and tested with version of EclecticIQ Platform v2

## Configure EclecticIQ Platform v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EclecticIQ Platform v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://ic-playground.eclecticiq.com/api/v1) | True |
    | API Key | True |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lookup_observables
***
Lookup observables from EclecticIQ Intelligence Center Platform


#### Base Command

`lookup_observables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of the value to lookup observables from . Possible values are: ipv4, ipv6, domain, uri, email, hash-md5, hash-sha256, hash-sha1, hash-sha512. | Required | 
| value | Value to search the related observables from EclecticIQ Intelligence Center Platform. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EclecticIQ.Observables.type | string | EclecticIQ  Observables type | 
| EclecticIQ.Entity.confidence | string | EclecticIQ Entity confidence | 
| EclecticIQ.Entity.observables | string | EclecticIQ Entity related observables | 
| EclecticIQ.Entity.threat_start_time | date | EclecticIQ Threat start time | 
| EclecticIQ.Entity.title | string | EclecticIQ Entity Title | 

#### Command Example
```!lookup_observables type="ipv4" value="001.001.001.001"```
#### Context Example
```json
{
    "EclecticIQ":{
       "DBotScore":{
          "Created":"2022-12-20T12:47:24.531410+00:00",
          "ID":"9382489",
          "LastUpdated":"2022-12-20T12:47:24.398456+00:00",
          "Type":"ipv4",
          "indicator":"ipv4",
          "score":3
       },
       "Entity":{
          "confidence":"unknown",
          "threat_start_time":"2022-12-20T12:47:24.474221+00:00",
          "title":"sighting",
          "observables":{
             "classification":"high",
             "type":"ipv4",
             "value":"000.001.001.001",
             "Malicious":{
                "Description":"EclectiqIQ maliciousness confidence level: high",
                "Vendor":"EclectiqIQ"
             },
             "data":[
                {
                   "created_at":"2022-08-24T10:02:04.609448+00:00",
                   "entities":[
                      "https://ic-playground.eclecticiq.com/api/v1/entities/183fa404-ba48-471b-980d-02600fe89a2b"
                   ],
                   "id":7938475,
                   "last_updated_at":"2022-11-23T06:25:55.945630+00:00",
                   "meta":{
                      "maliciousness":"medium"
                   },
                   "sources":[
                      "https://ic-playground.eclecticiq.com/api/v1/sources/9a479225-37d1-4dae-9554-172eeccea193"
    ],
                   "type":"ipv4",
                   "value":"000.001.001.001"
                }
             ]
          }
       }
    }
 }
```
##### Human Readable Output
#### EclecticIQ observable reputation - 001.001.001.001 
|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`low`	|creationofsighting|	{'type': 'ipv4', 'value': '001.001.001.001, 'classification': 'low'}|   |   |	2022-08-25T04:50:56+00:00|sighting|

### create_sighting
***
create sighting in the EclecticIQ Intelligence Center Platform 

#### Base Command

`create_sighting`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value |  value for the sighting. | Required | 
| description | description about the sighting. | Required | 
| title |  Title for the sighting. | Required | 
| tags |  Tag for the sighting. | Required | 
| type | type for the sighting. Possible values are: ipv4, ipv6, domain, uri, email, hash-md5, hash-sha256, hash-sha1, hash-sha512. | Required | 
| confidence_level | severity level of the sighting. Possible values are: low, medium, high, unknown. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sighting.Data.Type | string | Sighting Type | 
| Sighting.Data.tags | string | Sighting Tags | 
| Sighting.Data.title | string | Sighting Title | 
| Sighting.Data.description | string | Sighting Description | 
| Sighting.Data.value | string | Sighting Value | 

#### Command Example
```!create_sighting  type="ipv4" value="001.001.001.001" description="sighting creation" title="sighting" tags="Alert" confidence_level="high"```

#### Context Example
```json
{
   "sighting":{
      "Data":{
         "Type":"ipv4",
         "confidence_level":"high",
         "description":"Sighting",
         "tags":"Alert",
         "title":"EIQ",
         "value":"001.001.001.001"
      }
   }
}
```
##### Human Readable Output
#### !sighting created for- 001.001.001.001
|confidence	|description|
| :--------     | :-------     |
|`Type`	|ipv4  |
|`confidence_level`| low|
|`description`| sighting creation|
|`tags`|	Alert|
|`title`|	sighting|
|`value`|	001.001.001.001|

### create_observable
***
create observable in the EclecticIQ Intelligence Center Platform 

#### Base Command

`create_observable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of the observable. Possible values are: ipv4, ipv6, domain, uri, email, hash-md5, hash-sha1, hash-sha256, hash-sha512. | Required | 
| value | value of the type of observable. | Required | 
| maliciousness | severity level of the type. Possible values are: unknown, safe, low, medium, high. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Observables.Data.type | string | Observable Type | 
| Observables.Data.value | string | Observable Value | 
| Observables.Data.maliciousness | string | Observable maliciousness | 

#### Command Example
```!create_observable  type="ipv4" value="001.001.001.001" maliciousness="high"```
#### Context Example
```json
{
   "Observables":{
      "Data":{
         "maliciousness":"high",
         "type":"ipv4",
         "value":"000.001.001.001"
      }
   }
}
```
##### Human Readable Output
#### Observables created successfully…!!
|confidence	|description|
| :--------     | :-------     |
|`maliciousness`	|low|
|`type`|	ipv4|
|`value`|	001.001.001.001|
