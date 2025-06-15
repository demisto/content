Use the Anomali ThreatStream Feed integration to fetch indicators from the feed.

## Configure Anomali ThreatStream Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Select this check box to fetch indicators. | False |
| Fetch by | Fetch by the modification or creation date of the indicators. | True |
| Server URL (e.g., https://www.test.com) | URL of Anomali ThreatStream API | True |
| Username | Username of the Domain User. | True |
| API Key | The API Key to use for connection. | True |
| Feed Fetch Interval | The feed fetch interval. | False |
| Confidence Threshold | Will only return indicators above the confidence threshold. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Traffic Light Protocol Color | Indicator's TLP will override default value. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Indicator Expiration Method | The feed's expiration method. | False |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Trust any certificate (not secure) | Trust server certificate.  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatstream-feed-get-indicators

***
Gets indicators from the feed.
This command is mainly used for testing and debugging purposes.

#### Base Command

`threatstream-feed-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indictor type to analyze. Possible values are: domain, ip, md5, url, email. | Optional | 
| limit | Maximum number of objects to return (default is 10). | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!threatstream-feed-get-indicators indicator_type=domain limit=5```
#### Human Readable Output

>### Indicators from Anomali ThreatStream Feed:
>|Source|ThreatStreamID|domain|Modified|Confidence|Creation|Tags|TrafficLightProtocol|
>|---|---|---|---|---|---|---|---|
>| nickelfreesolutions.com | 284008208 | dunnydomain.com | 2025-04-05T01:48:33.997Z | 0 | 2021-11-16T09:40:10.407Z | **-**	***id***: pit<br/>	***name***: domain-test-h-without-approval-cloud-unresolved | amber |
>| Demisto | 440576095 | my.domainnn.com | 2023-12-24T00:00:05.890Z | 50 | 2023-06-20T08:07:33.841Z | **-**	***name***: tag3452<br/>	***org_id***: 88<br/>	***id***: yxy<br/>	***tlp***: amber<br/>	***_valid***: true<br/>**-**	***name***: tag23452<br/>	***org_id***: 88<br/>	***id***: q6q<br/>	***tlp***: amber<br/>	***_valid***: true |  |
>| Demisto | 440126275 | my.domain8961.com | 2023-12-24T00:00:05.877Z | 50 | 2023-06-19T12:14:52.216Z | **-**	***name***: tag3452<br/>	***org_id***: 88<br/>	***id***: yro<br/>	***tlp***: red<br/>	***_valid***: true<br/>**-**	***name***: tag23452<br/>	***org_id***: 88<br/>	***id***: bdw<br/>	***tlp***: red<br/>	***_valid***: true |  |
>| Demisto | 439658732 | my.domain1357.com | 2023-09-16T10:10:05.788Z | 50 | 2023-06-18T10:02:07.876Z |  |  |
>| Analyst | 231953546 | abctest1.com | 2023-07-17T09:55:54.228Z | 60 | 2021-04-06T09:36:09.122Z | **-**	***id***: 5nt<br/>	***name***: Reconnaissance |  |

