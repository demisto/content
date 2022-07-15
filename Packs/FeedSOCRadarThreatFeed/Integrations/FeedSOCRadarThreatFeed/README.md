Retrieve indicators provided by collections via SOCRadar Threat Intelligence Feeds.
This integration was integrated and tested with v21.11 of SOCRadar.

## Configure SOCRadar Threat Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SOCRadarThreatFeed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection to SOCRadar ThreatFusion API. | True |
    | insecure | Trust any certificate (not secure). | False |
    | proxy | Whether to use XSOAR’s system proxy settings to connect to the API. | False |
    | Feed Name | The feed name(s) to fetch. | True |
    | Fetch indicators | Whether to fetch indicators. | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Tags | Supports CSV values. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Feed Fetch Interval | The feed fetch interval. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate API key and connection to SOCRadar Threat Feeds/IOC API.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### How to obtain SOCRadar Threat Feeds/IOC API key?

Every company has a unique API key in SOCRadar platform. This API key can be used to benefit from
various API endpoints that SOCRadar provides. 

For the information about the SOCRadar API keys and how to obtain them, please see [SOCRadar API](https://platform.socradar.com/docs/api/intro/) documentation.

### socradar-get-indicators
***
Retrieves SOCRadar Recommended Threat Intelligences Collections.


#### Base Command

`socradar-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collections_to_fetch | Names of the collections that intended to be retrieved indicators from. | Required | 
| limit | The maximum number of indicators to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFeed.Indicators[0].Indicator | String | The value of the indicator. | 
| SOCRadarThreatFeed.Indicators[0].Indicator Type | String | The type of the indicator. | 
| SOCRadarThreatFeed.Indicators[0].Feed Maintainer Name | String | Name of the maintainer that the indicator found from. | 
| SOCRadarThreatFeed.Indicators[0].First Seen Date | Date | The date that the indicator was in SOCRadar collections for the first time. | 
| SOCRadarThreatFeed.Indicators[0].Last Seen Date | Date | The latest date that the indicator was seen in SOCRadar collections. | 
| SOCRadarThreatFeed.Indicators[0].Seen Count | Number | The feed description. | 
| SOCRadarThreatFeed.Indicators[0].rawJSON | JSON | Raw JSON object that contains the value and type of the indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.ASN | Number | ASN field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.AsnCode | Number | ASN code field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.AsnName | String | ASN name field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.Cidr | String | CIDR field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.CityName | String | City name field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.CountryCode | String | Country code field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.CountryName | String | Country name field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.Latitude | Number | Latitude field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.Longitude | Number | Longitude field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.RegionName | String | Region name field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.Timezone | String | Timezone field Geographical location information of the IP type indicator. | 
| SOCRadarThreatFeed.Indicators[0].Geo Location.ZipCode | String | Zip code field Geographical location information of the IP type indicator. | 

#### Command Example
```!socradar-get-indicators collections_to_fetch="SOCRadar-APT-Recommended-Block-Domain" limit=2```

#### Context Example

```json
{
    "SOCRadarThreatFeed": {
        "Indicators": [
            {
              "Feed Maintainer Name": "SOCRadar-APT Feed",
              "First Seen Date": "2021-07-15 07:04:29",
              "Indicator": "dump-indicator.domain", 
              "Indicator Type": "Domain", 
              "Last Seen Date": "2021-07-16 07:04:49",
              "Seen Count": 2,
              "rawJSON": {
                   "value": "dump-indicator.domain",
                   "type": "Domain"  
              }   
            },
            {
              "Feed Maintainer Name": "SOCRadar-APT Feed",
              "First Seen Date": "2021-07-15 07:04:29",
              "Indicator": "yet-another-dump-indicator.domain", 
              "Indicator Type": "Domain", 
              "Last Seen Date": "2021-07-16 07:04:49",
              "Seen Count": 2,
              "rawJSON": {
                   "value": "yet-another-dump-indicator.domain",
                   "type": "Domain"  
              }   
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators from SOCRadar ThreatFeed Collections (SOCRadar-APT-Recommended-Block-Domain):
>|Feed Maintainer Name|First Seen Date|Indicator|Indicator Type|Last Seen Date|Seen Count
>|---|---|---|---|---|---|
>| SOCRadar-APT Feed | 2021-07-15 07:04:29 | dump-indicator.domain | Domain | 2021-07-16 07:04:49 | 2
>| SOCRadar-APT Feed | 2021-07-15 07:04:29 | yet-another-dump-indicator.domain | Domain | 2021-07-16 07:04:49 | 2


### socradar-reset-fetch-indicators
***
Resets the indicator fetch history.

#### Base Command

`socradar-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!socradar-reset-fetch-indicators```

#### Human Readable Output

>Fetch history has been successfully deleted!

