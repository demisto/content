This feed of IPs are associated with infrastructure actively utilized or abused by cyber criminals, including VPN/Proxy services and malicious hosts. With this integration, users can fetch a daily list of newly compiled indicators from QSentry’s proprietary collections to quickly surface suspicious activity.
This integration was integrated and tested with the latest version of QSentry Feeds

## Configure QintelQSentryFeed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QintelQSentryFeed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | QSentry API URL (optional) |  | False |
    | Qintel Token |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch indicators |  | False |
    | Feed Types | Select which feed types to ingest | False |
    | Override Indicator Reputation | Indicators from this integration instance will be marked with this reputation regardless of feed classification. Criminal indicators will be scored one level higher. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qintel-qsentry-get-indicators
***
Gets indicators from the QSentry Feed.


#### Base Command

`qintel-qsentry-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!qintel-qsentry-get-indicators```

#### Human Readable Output

>### Indicators from QSentry Feed:
>|Indicator|Service Name|Service Type|Criminal|Cdn|Comment|
>|---|---|---|---|---|---|
>| 101.100.146.147 | tor_exitnodes | tor | 0 | 0 | This IP address has been associated with the TOR network. |
>| 101.99.90.171 | tor_exitnodes | tor |  | 0 | This IP address has been associated with the TOR network. |
>| 102.130.113.37 | tor_exitnodes | tor | 0 | 0 | This IP address has been associated with the TOR network. |
>| 102.130.113.9 | tor_exitnodes | tor | 0 | 0 | This IP address has been associated with the TOR network. |
>| 103.228.53.155 | tor_exitnodes | tor | 0 | 0 | This IP address has been associated with the TOR network. |
>| 192.168.1.0/29 |  |  |  |  | This IP address belongs to a network block that has been abused by nation state actors. |
>| 192.168.2.0/24 |  |  |  |  | This IP address belongs to an identified bullet proof hoster. |

