## Overview
ReversingLabs Ransomware and Related Tools Feed includes fresh indicators from not only ransomware but the tools used 
to gain access and deploy ransomware enabling defenders the opportunity to discover adversaries initial network access 
and lateral movement before their data is encrypted. Our threat intelligence researchers analyze ransomware attack 
trends and the security landscape to ensure that only the most up to date and relevant malware families are dissected 
to create technical indicators.

The user can set the initial fetch time to go historically up to 4 hours back. Each following fetch calculates the 
historical time dynamically by itself so no indicators are missed.

## Configuring
Upon installing the ReversingLabs Ransomware and Related Tools Feed integration, do the following:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ReversingLabs Ransomware and Related Tools Feed.
3. Click __Add instance__ to create and configure a new integration instance.
4. After creating an instance of the integration, click on the cog icon and configure the following parameters:  

    | Parameter | Description                                                                                                                                                                                            |
    |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
    | Name | A name for the integration instance.                                                                                                                                                                   |
    | Fetch indicators | If checked, the instance fetches indicators.                                                                                                                                                           |
    | ReversingLabs TitaniumCloud URL | The host address of ReversingLabs TitaniumCloud. Default is "https://data.reversinglabs.com"                                                                                                           |
    | Credentials | Username for the ReversingLabs TitaniumCloud.                                                                                                                                                          |
    | Password | Password for the ReversingLabs TitaniumCloud.                                                                                                                                                          
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. Default is "Bad".                                                                                                       |
    | Source Reliability | Defines the reliability of the source providing the intelligence data. Default is "A - Completely reliable"                                                                                            |
    | Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance.                                                                                                                 |
    | Indicator Expiration Interval | How often to expire the indicators from this integration instance expressed in minutes.                                                                                                                |
    | Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance expressed in hours and minutes. Default and recommended is 1 hour.                                                           | 
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |
    | First fetch time | Defines how many hours back in time should the indicators be fetched from during the first run. Value should be between 1 and 4. Recommended value is 2.                                               |
    | Indicator types | Which types of indicators should be fetched from the feed. Possible values are 'ipv4', 'domain', 'hash', 'uri'.                                                                                        |
    | Tags | Tags added by the user that will be appended to the indicator tags. Tags need to be separated by a comma with no spaces.                                                                               |
    | Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.                                                                                                             |
    | Trust any certificate (not secure) | If checked, the server certificate integrity will be ignored.                                                                                                                                          |
    
5. When the parameters are configured, click "Test".
6. If the test succeeds, click "Done" to finish configuring the instance.

## Commands
The commands in this feed integration can be executed manually from the Cortex XSOAR CLI, or as a part of an automation or a playbook.

### Get indicators from the feed
```reversinglabs-get-indicators```

#### Available arguments

| Argument Name | Description                                                                                                                                    | Required |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| limit | The maximum number of indicators to return. Default is 50.                                                                                     | Optional | 
| indicator_types | Which indicator types should be fetched from the feed. Possible values are 'ipv4', 'domain', 'hash', 'uri'. The default is "ipv4,domain,hash". | Optional |
| hours_back | Defines how many hours hours back in time should the indicators be fetched from. Value should be between 1 and 4. Recommended value is 1.      | Optional |

#### Context and readable output

Depending on the indicator type and each specific indicator, context and readable output can have varying data fields. Full available list of output fields is the following:

| Field | Type |
| --- | --- |
| Indicator Value | String |
| Indicator Type | String |
| Days Valid | Integer |
| Confidence | Integer |
| Rating | Decimal |
| Indicator Tags | Object |
| Last Update | Timestamp |
| Deleted | Boolean |
| Hash | Object |

Indicator Tags object

| Field             | Type            |
|-------------------|-----------------|
| port              | String          |
| malwareType       | String          |
| lifecycleStage    | String          |
| malwareFamilyName | String          |
| source            | String          |
| mitre             | List            |
| Protocol          | List of strings |
| asn               | String          |
| fileInfo          | List of strings |

Hash object

| Field | Type |
| --- | --- |
| sha1 | String |
| md5 | String |
| sha256 | String |


#### Context prefix
```ReversingLabs.indicators```

#### Command example
```!reversinglabs-get-indicators limit="40" indicator_types="ipv4,hash" hours_back="2"```