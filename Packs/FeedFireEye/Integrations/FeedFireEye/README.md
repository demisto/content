
Use the FireEye feed integration to fetch indicators from the FireEye Intelligence Feed feed.

## Configure FireEye Feed in Cortex
---


| Parameter | Description |
| --- | --- |
| Name | A meaningful name for the integration instance. |
| Fetch indicators | If checked, fetches indicators. |
| Indicator Reputation | The reputation applied to indicators from this integration instance. Default is "Bad". |
| Source Reliability | The reliability of the source providing the intelligence data. Default is "A - Completely reliable" |
| Traffic Light Protocol color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp. |
| Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance. |
| Indicator Expiration Interval | How often to expire the indicators from this integration instance (in minutes). This only applies if the *feedExpirationPolicy* is set to **interval**.|
| Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance (in minutes). Default is 60. | 
| Public Key + Password | The credentials used to access the feed's data. | 
| Collection(s) to fetch from feed | Select which collections to fetch from the feed. Default is "Indicators, Reports" |
| First Fetch Time | First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year). |
| Malicious Threshold | The minimum score returned from the feed to determine whether the indicator is malicious. Default is 70. | 
| Reputation Interval | If this amount of days passed since the indicator was created, then its reputation can be at most **Suspicious**. Default is 30. | 
| Bypass exclusion list | Whether the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |



## Commands
---
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed
---
Gets the feed indicators and reports.

##### Base Command

`fireeye-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 


##### Context Output

There is no context output for this command.

#### Command Example
```!fireeye-get-indicators limit=10```


### fireeye-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.

#### Base Command

`fireeye-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!fireeye-reset-fetch-indicators```

#### Human Readable Output
Fetch was reset successfully. Your next indicator fetch will collect indicators from the configured "First Fetch Time"
