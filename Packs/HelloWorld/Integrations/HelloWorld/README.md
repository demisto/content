This is the Hello World integration for getting started.

## Configure HelloWorld on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HelloWorld.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Server URL (e.g., https://api.xsoar-example.com) |  | True |
    | Fetch alerts |  | False |
    | Alert type |  | False |
    | Maximum number of alerts per fetch |  | False |
    | API Key |  | True |
    | Score threshold for IP reputation command | Set this to determine the HelloWorld score that will determine if an IP is malicious \(0-100\) | False |
    | Severity of alerts to fetch |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Hello command - prints hello to anyone.

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. | 

#### Command example
```!helloworld-say-hello name="Hello Dbot"```
#### Context Example
```json
{
    "hello": "Hello Hello Dbot"
}
```

#### Human Readable Output

>## Hello Hello Dbot

### helloworld-alert-list

***
Lists the example alerts as it would be fetched from the API.

#### Base Command

`helloworld-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Filter by alert item ID. If not provided, all IDs will be retrieved. | Optional | 
| limit | How many alerts to fetch. Default is 10. | Optional | 
| severity | The severity  by which to filter the alerts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.alert.id | Number | The ID of the alert. | 
| HelloWorld.alert.name | String | The name of the alert. | 
| HelloWorld.alert.severity | String | The severity of the alert. | 
| HelloWorld.alert.date | Date | The date of the alert occurrence. | 
| HelloWorld.alert.status | String | The status of the alert. | 

#### Command example
```!helloworld-alert-list limit="3" severity="low"```
#### Context Example
```json
{
    "HelloWorld": {
        "Alert": [
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 1,
                "name": "XSOAR Test Alert #1",
                "severity": "low",
                "status": "Testing"
            },
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 2,
                "name": "XSOAR Test Alert #2",
                "severity": "low",
                "status": "Testing"
            },
            {
                "date": "2023-09-14T11:30:39.882955",
                "id": 3,
                "name": "XSOAR Test Alert #3",
                "severity": "low",
                "status": "Testing"
            }
        ]
    }
}
```

#### Human Readable Output

>### Items List (Sample Data)
>|date|id|name|severity|status|
>|---|---|---|---|---|
>| 2023-09-14T11:30:39.882955 | 1 | XSOAR Test Alert #1 | low | Testing |
>| 2023-09-14T11:30:39.882955 | 2 | XSOAR Test Alert #2 | low | Testing |
>| 2023-09-14T11:30:39.882955 | 3 | XSOAR Test Alert #3 | low | Testing |


#### Command example
```!helloworld-alert-list alert_id=2```
#### Context Example
```json
{
    "HelloWorld": {
        "Alert": {
            "date": "2023-09-14T11:30:39.882955",
            "id": 2,
            "name": "XSOAR Test Alert #2",
            "severity": "low",
            "status": "Testing"
        }
    }
}
```

#### Human Readable Output

>### Items List (Sample Data)
>|date|id|name|severity|status|
>|---|---|---|---|---|
>| 2023-09-14T11:30:39.882955 | 2 | XSOAR Test Alert #2 | low | Testing |


### helloworld-alert-note-create

***
Example of creating a new item in the API.

#### Base Command

`helloworld-alert-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert's ID to add the note to. | Required | 
| note_text | The comment to add to the note. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.alert.id | Number | The ID of the alert. | 
| HelloWorld.alert.name | String | The name of the alert. | 
| HelloWorld.alert.severity | String | The severity of the alert. | 
| HelloWorld.alert.date | Date | The date of the alert occurrence. | 
| HelloWorld.alert.status | String | The status of the alert. | 

#### Command example
```!helloworld-alert-note-create alert_id=2 note_text=test```
#### Context Example
```json
{
    "HelloWorld": {
        "Note": {
            "msg": "Note was created for alert #2 successfully with comment='test'",
            "status": "success"
        }
    }
}
```

#### Human Readable Output

>Note was created successfully.

### ip

***
Return IP information and reputation.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 
| threshold | If the IP has a reputation above the threshold, then the IP is defined as malicious. If threshold is not set, then the threshold from the instance configuration is used. Default is 65. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| HelloWorld.IP.asn | String | The autonomous system name for the IP address. | 
| HelloWorld.IP.asn_cidr | String | The ASN CIDR. | 
| HelloWorld.IP.asn_country_code | String | The ASN country code. | 
| HelloWorld.IP.asn_date | Date | The date on which the ASN was assigned. | 
| HelloWorld.IP.asn_description | String | The ASN description. | 
| HelloWorld.IP.asn_registry | String | The registry the ASN belongs to. | 
| HelloWorld.IP.entities | String | Entities associated to the IP. | 
| HelloWorld.IP.ip | String | The actual IP address. | 
| HelloWorld.IP.network.cidr | String | Network CIDR for the IP address. | 
| HelloWorld.IP.network.country | Unknown | The country of the IP address. | 
| HelloWorld.IP.network.end_address | String | The last IP address of the CIDR. | 
| HelloWorld.IP.network.events.action | String | The action that happened on the event. | 
| HelloWorld.IP.network.events.actor | Unknown | The actor that performed the action on the event. | 
| HelloWorld.IP.network.events.timestamp | String | The timestamp when the event occurred. | 
| HelloWorld.IP.network.handle | String | The handle of the network. | 
| HelloWorld.IP.network.ip_version | String | The IP address version. | 
| HelloWorld.IP.network.links | String | Links associated to the IP address. | 
| HelloWorld.IP.network.name | String | The name of the network. | 
| HelloWorld.IP.network.notices.description | String | The description of the notice. | 
| HelloWorld.IP.network.notices.links | Unknown | Links associated with the notice. | 
| HelloWorld.IP.network.notices.title | String | Title of the notice. | 
| HelloWorld.IP.network.parent_handle | String | Handle of the parent network. | 
| HelloWorld.IP.network.raw | Unknown | Additional raw data for the network. | 
| HelloWorld.IP.network.remarks | Unknown | Additional remarks for the network. | 
| HelloWorld.IP.network.start_address | String | The first IP address of the CIDR. | 
| HelloWorld.IP.network.status | String | Status of the network. | 
| HelloWorld.IP.network.type | String | The type of the network. | 
| HelloWorld.IP.query | String | IP address that was queried. | 
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. | 
| HelloWorld.IP.score | Number | Reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). | 
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 

#### Command example
```!ip ip="8.8.8.8"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "C - Fairly reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "HelloWorld Dev"
    },
    "HelloWorld": {
        "IP": {
            "id": "x.x.x.x",
            "ip": "8.8.8.8",
            "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/x.x.x.x"
            },
            "type": "ip_address"
        }
    },
    "IP": {
        "Address": "8.8.8.8",
        "Malicious": {
            "Description": "Hello World returned reputation -4",
            "Vendor": "HelloWorld Dev"
        },
        "Relationships": [
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "h",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "t",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "t",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "p",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "s",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ":",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "w",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "w",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "w",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ".",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "v",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "i",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "r",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "u",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "s",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "t",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "o",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "t",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "a",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "l",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ".",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "c",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "o",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "m",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "a",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "p",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "i",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "v",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "3",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "i",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "p",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "_",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "a",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "d",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "d",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "r",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "e",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "s",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "s",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "e",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "s",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "x",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ".",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "x",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ".",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "x",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": ".",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "8.8.8.8",
                "EntityAType": "IP",
                "EntityB": "x",
                "EntityBType": "URL",
                "Relationship": "related-to"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP (Sample Data)
>|id|ip|links|type|
>|---|---|---|---|
>| x.x.x.x | 8.8.8.8 | self: https:<span>//</span>www.virustotal.com/api/v3/ip_addresses/x.x.x.x | ip_address |
>### Attributes
>|as_owner|asn|continent|country|jarm|last_analysis_stats|last_modification_date|network|regional_internet_registry|reputation|tags|total_votes|whois_date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| EMERALD-ONION |  | NA | US | :jarm: | ***harmless***: 72<br/>***malicious***: 5<br/>***suspicious***: 2<br/>***timeout***: 0<br/>***undetected***: 8 |  | :cidr: | ARIN |  | ***values***:  | ***harmless***: 0<br/>***malicious***: 1 |  |

