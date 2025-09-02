Use the Anomali ThreatStream Feed Integration to fetch indicators from the Anomali ThreatStream.

## Configure Anomali ThreatStream Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Enable this checkbox to automatically pull indicators from the Anomali ThreatStream at regular intervals. |  |
| Fetch by | Fetch by the modification or creation time of the indicators. | True |
| Server URL (e.g., https://www.test.com) | Confirm that the pre-filled URL matches the correct API endpoint for your Anomali ThreatStream instance. | True |
| Username |  | True |
| API Key |  | True |
| Feed Fetch Interval |  | False |
| Confidence Threshold | Will only return indicators above the confidence threshold. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Indicator's TLP will override the default value. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. If not selected, Indicators' verdicts are determined by their Dbot score from the API. The default is Unknown. | False |
| Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance. | False |
| Create relationships |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatstream-feed-get-indicators

***
Gets indicators from the feed. This command is mainly used for testing and debugging purposes.

#### Base Command

`threatstream-feed-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indicator type to analyze. If not selected, indicators from all types are retrieved. Possible values are: domain, ip, md5, url, email. | Optional |
| limit | Maximum number of objects to return. Default is 10. | Optional |
| sort_by | Sort the records in descending order according to the Created or Modified Time. Possible values are: Created Time, Modified Time. Default is Modified Time. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!threatstream-feed-get-indicators indicator_type="domain" limit="5" sort_by="Created Time"```

#### Human Readable Output

>### Indicators from Anomali ThreatStream Feed
>
>|Source|ThreatStreamID|Domain|Modified|Confidence|Creation|Tags|TrafficLightProtocol|
>|---|---|---|---|---|---|---|---|
>| Demisto | 440576095 | my.domainnn_test.com | 2023-12-24T00:00:05.890Z | 50 | 2023-06-20T08:07:33.841Z | ***values***: tag3452, tag23452 |  |
>| Demisto | 440126275 | my.domain_987.com | 2023-12-24T00:00:05.877Z | 50 | 2023-06-19T12:14:52.216Z | ***values***: tag3452, tag23452 |  |
>| Demisto | 439658732 | my.domain1357.com | 2023-09-16T10:10:05.788Z | 50 | 2023-06-18T10:02:07.876Z |  |  |
>| dummydomain.com | 284008208 | test_domain_121.com | 2025-04-05T01:48:33.997Z | 0 | 2021-11-16T09:40:10.407Z | ***values***: tag4567 | amber |
>| Analyst | 231953546 | abc_test_domain1.com | 2023-07-17T09:55:54.228Z | 60 | 2021-04-06T09:36:09.122Z | ***values***: tag1356 |  |
