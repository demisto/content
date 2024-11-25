## Configure AutoFocus Tags Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Account's private token. | False |
| AutoFocus Endpoint URL | The AutoFocus endpoint URL. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Feed Fetch Interval | The feed fetch interval. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Create Relationships | Create relationships between indicators as part of Enrichment. | False |    
| Trust any certificate (not secure) | Whether to trust any certificate (not secure). | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### autofocus-tags-feed-get-indicators
***
Gets indicators from the feed.


#### Base Command

`autofocus-tags-feed-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Should be 50 or less. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!autofocus-tags-feed-get-indicators limit=10```

#### Human Readable Output
Value |	Type	| Fields
|---|---|---|
DarkHotel|	Threat Actor|	publications: {'link': 'https://securelist.com/the-darkhotel-apt/66779/', 'title': 'The DarkHotel APT', 'source': 'Kaspersky', 'timestamp': '2018-08-20T15:25:31'},aliases: ParasiticBeast, description: The DarkHotel attackers were most infamously behind a series of attacks between 2008 and 2014 against organizations located primarily in  Japan, Taiwan, China, Russia and South Korea. This campaign infiltrated multiple hotel networks and used them as a jumping-off point to infect hotel guests., lastseenbysource: 2021-05-03T01:55:18Z, updateddate: 2019-08-28T08:56:30Z ,reportedby: Unit 42

#### Notes
Be aware, due to API limitations, `fetch-indicators` fetches only a limited number of indicators for each interval.
Fetching all the indicators can take up to 13 hours. 