Use the Cofense Feed Integration to fetch indicators from the feed.
This integration was integrated and tested with version 1 of Cofense Feed

## Configure Cofense Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username |  | False |
| Password |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| The threat type for which to fetch indicators | To fetch malware and phishing indicators select "all". | False |
| First fetch time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes) | This value also will be used as an expiration time - all indicators before the given time will not be fetched. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cofense-get-indicators
***
Gets indicators from the feed.


#### Base Command

`cofense-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of context indicators to return. The default value is 10. Default is 10. | Optional | 
| from_time | The time period (previous) for which to fetch indicators. For example, a value of 3 days will return indicators from the previous three days. Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cofense-get-indicators limit=2```

#### Human Readable Output
Results from Cofense Feed:

| **threat_id** | **type** | **value** | **impact** | **confidence** | **roleDescription** |
| --- | --- | --- | --- | --- | --- |
| [218956](https://www.threathq.com/p42/search/default?m=218956) | URL | https://r-gk8.online/main/main.php | Major | 100 |	Credential Phishing|
| [218956](https://www.threathq.com/p42/search/default?m=218956) | URL | https://notification.ba.com/LinkTracking?id=17174577&url=https://r-⁠gk8.online?e=| Major | 100 | Credential Phishing |