Custom integration designed to pull in reports from the Dragos Worldview API as incidents 
This integration was integrated and tested with version 1.0 of Dragos Worldview 

## Configure Dragos Worldview  on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Dragos Worldview .
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://portal.dragos.com) |  | True |
    | API Token |  | True |
    | API Key |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Fetch Limit |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dragos-get-indicators
***
Get Indicators from the Dragos WorldView API


#### Base Command

`dragos-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclude_suspect_domain | Exclude indicators that are only associated with Suspect Domain Reports (API default false). | Optional | 
| page | Page number to start at (API default 1). | Optional |
| page_size | Page size (API default 500) (must be less than 1001). | Optional | 
| serial | Report serial number to get indicators from, if no serial number provided command will retrieve all indicators from the last 48 hours. | Optional | 
| tags | List of tags to search for indicators. | Optional | 
| type | Search for indicators of a specific type. | Optional |
| updated_after | UTC timestamp in YYYY-mm-dd (optionally with HH:mm:ss) to filter to recent indicators (default is within the last 48 hours). | Optional |
| value | Search for indicators that match a specific value. | Optional |

#### Context Output

| **Context Path** | **Description** | **Type** |
| --- | --- | --- |
| Dragos.Indicators.activity_groups | A list of activity groups. | Unknown | 
| Dragos.Indicators.attack_techniques | A list of attack techniques. | Unknown |
| Dragos.Indicators.category | The Dragos Indicator's category. | String | 
| Dragos.Indicators.comment | The Dragos Indicator's comment. | String | 
| Dragos.Indicators.confidence | The Dragos Indicator's confidence. | String | 
| Dragos.Indicators.first_seen | The first time the Indicator was seen in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). | String |
| Dragos.Indicators.ics_attack_techniques | A list of ics attack techniques. | Unknown |
| Dragos.Indicators.indicator_id | The Dragos Indicator's id. | Number |
| Dragos.Indicators.indicator_type | The Dragos Indicator's type. | String |
| Dragos.Indicators.kill_chain | The Dragos Indicator's kill chain. | String |
| Dragos.Indicators.kill_chains | A list of kill chains. | Unknown |
| Dragos.Indicators.last_seen | The last time the Indicator was seen in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). | String |
| Dragos.Indicators.pre_attack_techniques | A list of pre-attack techniques. | Unknown |
| Dragos.Indicators.products | A list of dictionaries, usually containing the serial numbers of related Dragos reports. | Unknown |
| Dragos.Indicators.products.serial | The serial numbers of related Dragos reports. | Unknown |
| Dragos.Indicators.severity | The Dragos Indicator's severity. | String |
| Dragos.Indicators.status | The Dragos Indicator's status. | String |
| Dragos.Indicators.threat_groups | A list of threat groups. | Unknown | 
| Dragos.Indicators.updated_at | The last time the Indicator was updated in Dragos (yyyy-mm-ddThh:mm:ss.sssZ). | String |
| Dragos.Indicators.uuid | The Dragos Indicator's uuid. | String |
| Dragos.Indicators.value | The Dragos Indicator's value. | String |


#### Command Example
``` ```

#### Human Readable Output



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
``` ```

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
``` ```

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
``` ```

#### Human Readable Output

