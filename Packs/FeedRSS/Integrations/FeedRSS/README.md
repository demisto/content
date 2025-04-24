RSS Feed can ingest new items as report indicators.
This integration was integrated and tested with version 2.0 of RSS.

## Configure RSS Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Feed URL | The RSS URL should be a URL with 'feed' as the suffix or prefix. | True |
| Article content max size in KB | Default is 45KB. If you increase the limit substantialy, it may slow performance. You need to specify only a number, e.g., 50. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Feed Expiration Method |  | False |
| feedExpirationInterval |  | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rss-get-indicators
***
Gets the reports from the RSS feed.


#### Base Command

`rss-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!rss-get-indicators ```

#### Human Readable Output

RSS Feed:


| **Title** | **Link** | **Type** |
| --- | --- | --- |
| Title of an article | https://article-example.com | Report | 