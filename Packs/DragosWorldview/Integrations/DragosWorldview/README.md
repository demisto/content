Custom integration designed to pull in reports from the Dragos Worldview API as incidents 
This integration was integrated and tested with version 1.0 of Dragos Worldview 

## Configure Dragos Worldview  in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://portal.dragos.com) | The Dragos server URL | True |
| API Token | The API token  | True |
| API Key | The key for the API Token | True |
| First fetch time | The first time to run a fetch request | False |
| Trust any certificate (not secure) | If true trust any certicicate | False |
| Use system proxy settings | If true use system proxy settings | False |
| Incidents Fetch Interval | How often to fetch incidents | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators | False |
| Fetch incidents | If true fetch incidents in a feed | False |
| Incident type | The incident type | False |
| Fetch Limit | The fetch limit | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dragos-get-indicators
***
Get Indicators from the Dragos WorldView API


#### Base Command

`dragos-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclude_suspect_domain | Exclude indicators that are only associated with Suspect Domain Reports (API default false). | Optional | FContext
| page | Page number to start at (API default 1). | Optional |
| page_size | Page size (API default 500) (must be less than 1001). | Optional | 
| serial | Report serial number to get indicators from, if no serial number provided command will retrieve all indicators from the last 48 hours. | Optional | 
| tags | List of tags to search for indicators. | Optional | 
| type | Search for indicators of a specific type. | Optional |
| updated_after | UTC timestamp in YYYY-mm-dd (optionally with HH:mm:ss) to filter to recent indicators (default is within the last 48 hours). | Optional |
| value | Search for indicators that match a specific value. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Dragos.Indicators.activity_groups | Unknown | A list of activity groups. |
| Dragos.Indicators.attack_techniques | Unknown | A list of attack techniques. |
| Dragos.Indicators.category | String | The Dragos Indicator's category. |
| Dragos.Indicators.comment | String | The Dragos Indicator's comment. |
| Dragos.Indicators.confidence | String | The Dragos Indicator's confidence. |
| Dragos.Indicators.first_seen | String | The first time the Indicator was seen in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). |
| Dragos.Indicators.ics_attack_techniques | Unknown | A list of ics attack techniques. |
| Dragos.Indicators.indicator_id | Number | The Dragos Indicator's id. |
| Dragos.Indicators.indicator_type | String | The Dragos Indicator's type. |
| Dragos.Indicators.kill_chain | String | The Dragos Indicator's kill chain. |
| Dragos.Indicators.kill_chains | Unknown | A list of kill chains. |
| Dragos.Indicators.last_seen | String | The last time the Indicator was seen in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). |
| Dragos.Indicators.pre_attack_techniques | Unknown | A list of pre-attack techniques. |
| Dragos.Indicators.products | Unknown | A list of dictionaries, usually containing the serial numbers of related Dragos reports. |
| Dragos.Indicators.products.serial | Unknown | The serial numbers of related Dragos reports. |
| Dragos.Indicators.severity | String | The Dragos Indicator's severity. |
| Dragos.Indicators.status | String | The Dragos Indicator's status. |
| Dragos.Indicators.threat_groups | Unknown | A list of threat groups. |
| Dragos.Indicators.updated_at | String | The last time the Indicator was updated in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). |
| Dragos.Indicators.uuid | String | The Dragos Indicator's uuid. |
| Dragos.Indicators.value | String | The Dragos Indicator's value. |


#### Command Example
```!dragos-get-indicators exclude_suspect_domain=false page=1 page_size=500 serial=DOM-2023-37 tags=test type=domain updated_after=2023-12-31 value=example.com```

#### Human Readable Output

## Dragos Indicators
| activity_groups | attack_techniques | category | comment | confidence | first_seen | ics_attack_techniques | id | indicator_type | kill_chain | kill_chains | last_seen | pre_attack_techniques | products | severity | status | threat_groups | updated_at | uuid | value |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  | moderate |  2018-04-06T00:00:00.000Z |  | 0000 | domain | | | 2023-09-12T19:37:31.000Z |  | {'serial': 'DOM-2023-37'} |  | released |  |  2024-09-12T21:31:51.000Z |  | example.com | 


### dragos-get-full-report
***
Get the report file from the given serial number


#### Base Command

`dragos-get-full-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number for the report to retrieve. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!dragos-get-full-report serial=DOM-2023-37```

#### Human Readable Output



### dragos-get-ioc-csv
***
Get csv file with indicators from a given report


#### Base Command

`dragos-get-ioc-csv`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the report from which to get the file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!dragos-get-ioc-csv serial=DOM-2023-37```

#### Human Readable Output



### dragos-get-stix2
***
Get the stix2 json bundle of indicators from a given report


#### Base Command

`dragos-get-stix2`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the report from which to retrieve the file. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!dragos-get-stix2 serial=DOM-2023-37```

#### Human Readable Output