SecneurX provides real-time threat intelligence that protects companies against the latest cyber threats, including APTs, phishing, malware, ransomware, data exfiltration, and brand infringement. Security teams rely on our dependable and rich data to expand their threat landscape visibility, resulting in improved detection rates and response times.
This integration was integrated and tested with version 1.0.0 of SecneurX Threat Feeds

## Configure SecneurX Threat Feeds in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Feed URL | Input the url of SecneurX Threat Intelligence Feeds. | True |
| API Key | Input the API key for fetching feed from the source. | True |
| Fetch indicators | Select this option if you want this integration instance to fetch indicators from the SecneurX Threat Intelligence feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Tags | Supports CSV values. | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Feed Fetch Interval | How often do fetch indicators from this integration instance. You can specify the interval in days, hours, or minutes. | True |
| Feed Expiration Policy |  | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| First fetch | First fetch query e.g., 12 hours, 7 days. SecurityScorecard provides a maximum of 7 days back. To ensure no alerts are missed, it's recommended to use a value less than 2 days. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### snxfeeds-get-indicators
***
Retrieves a limited number of the indicators.


#### Base Command

`snxfeeds-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default is 10. | Optional |


#### Context Output

There is no context output for this command.

#### Human Readable Output
Type |	Value  | Fields
|---|---|---|
Domain | mak.logupdates.xyz | firstseenbysource: 2022-06-13T10:37:23Z, indicatoridentification: indicator--c0f9425f-a3e9-4fcf-85c5-58e809f4e763, verdict: Malicious, tags: apt ,  Donot APT, modified: 2022-06-13T10:37:23Z, reportedby: SecneurX Threat Feeds |

#### Notes
Be aware, due to API limitations, `fetch-indicators` fetches only a limited number of indicators for each interval.
Fetching all the indicators can take up to 24 hours.