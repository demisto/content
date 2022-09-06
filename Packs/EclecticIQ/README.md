### Introduction
#### EclecticIQ Platform
* EclecticIQ platform is a Threat Intelligence Platform (TIP) that sits at the center of an organization’s Cyber Threat Intelligence practice, collecting intelligence from open sources, commercial suppliers, and industry partnerships into a single workspace.
* Using EclecticIQ Platform, intelligence analysts can deliver actionable intelligence and support detection, prevention, and incident response through existing security infrastructure. This approach improves security operations and leadership through a comprehensive yet cost-effective system.
* EclecticIQ Platform is uniquely designed to improve an organization’s security posture and intelligence analysts' efficiency, speed, accuracy, and capacity, allowing organizations to continue operations unimpeded by cyber threats.

#### EclecticIQ Cortex App
  * Get the lookup observables from the EIQ Platform
  * Create observables for the EIQ data
  * Create sighting for the EIQ data 
#### Configure EclecticIQ Platform on Cortex XSOAR
  1. Navigate to Settings > Integrations.
  2. Search for Integration- EclecticIQ. 
  3. Click Add instance to create and configure a new integration instance.
     * Name : EclecticIQ_instance_1
     * Server URL : https://ic-playground.eclecticiq.com/api/v1 
     * API Key 
     * Use System Proxy
     * Log level
  4. Click Test to validate the token and connection.
  5. Save the integration instance.
#### Commands
 * Execute these commands from the Cortex XSOAR CLI or in a Playbook.
 * After successfully execute a command, a DBot message appears in the War Room with the command details.
1. create sighting in the EclecticIQ Intelligence Center Platform : create_sighting
2. create observable in the EclecticIQ Intelligence Center Platform : create_observable
3. Lookup observables from EclecticIQ Intelligence Center Platform : lookup_observables
#### 1. create sighting in the EclecticIQ Intelligence Center Platform
create sighting in the EclecticIQ Intelligence Center Platform
##### Base command
create_sighting
#### Inputs
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Type of the sighting from (ipv4,ipv6,domain,uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512) |
| `value`         | `string`       | Required   | Value of the sighting  |
|`title`|        `string`  |Required  | Title of the sighting |
|`description`| `string`|Required|Description of the sighting|
|`Confidence`|`string`|Required| Confidence of the sighting from (low,high,medium,unknown)|
|`Tags`|`string`|Required| tags attached with the sighting|
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `Sighting.Data.Type`       | `string`     |Sighting Type|
| `Sighting.Data.tags`       | `string`     | Sighting Tags|
| `Sighting.Data.title`       | `string`     | Sighting Title|
| `Sighting.Data.description`       | `string`     | Sighting Description|
| `Sighting.Data.value`       | `string`     | Sighting Value|
 #### Command example
```http
  ip ipv4=172.168.156.115
```
##### Human Readable Output
#### !sighting created for- 172.168.156.115
|confidence	|description|
| :--------     | :-------     |
|`Type`	|ipv4  |
|`confidence_level`| low|
|`description`|	creation of sighting|
|`tags`|	XSOARsighting|
|`title`|	sighting|
|`value`|	172.168.156.115|
#### 2. create observable in the EclecticIQ Intelligence Center Platform
create observable in the EclecticIQ Intelligence Center Platform
##### Base command
create_observable
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Type of the observable from (ipv4,ipv6,domain,uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512) |
| `value`         | `string`       | Required   | Value of the type of observable |
|`maliciousness`|        `string`  |Required  | Maliciousness of the observable from (unknown, safe, low, medium, high)|
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `Observables.Data.type`       | `string`     |Observable Type|
| `Observables.Data.value`       | `string`     | Observable Value|
| `Observables.Data.maliciousness`       | `string`     | Observable maliciousness|
 ### Command example
```http
  ip ipv4=169.198.116.115
```
##### Human Readable Output
#### Observables created successfully…!!
|confidence	|description|
| :--------     | :-------     |
|`maliciousness`	|low|
|`type`|	ipv4|
|`value`|	169.198.116.115|
#### 3. Lookup observables from EclecticIQ Intelligence Center Platform
Lookup observables from EclecticIQ Intelligence Center Platform
##### Base command
lookup_observable
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |IPv4 to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 ### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Observables.type`       | `string`     | EclecticIQ  Entity Type|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|
|`EclecticIQ.DBotScore.Created`|`date`|Observable creation date|
|`EclecticIQ.DBotScore.ID`|`number`|Observable ID|
|`EclecticIQ.DBotScore.LastUpdated`|`date`|Observable last updated date|
|`EclecticIQ.DBotScore.Type`|`string`|Indicator type|
|`EclecticIQ.DBotScore.indicator`|`string`|The indicator that was tested|
|`EclecticIQ.DBotScore.Score`|`number`|The actual score|
|`EclecticIQ.IP.Malicious.Description`|`string`|For malicious IPs, the reason that the vendor made the decision|
|`EclecticIQ.IP.Malicious.Vendor`|`string`|Vendor used to calculate the score|

### Command example
```http
  ip ipv4=172.168.156.115
```
##### Human Readable Output
#### EclecticIQ observable reputation - 172.168.156.115 
|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`low`	|creation of sighting|	{'type': 'ipv4', 'value': '172.168.156.115, 'classification': 'low'}|   |   |	2022-08-25T04:50:56+00:00|sighting|



