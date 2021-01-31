Use the Google Cloud Platform whitelist integration to get indicators from the feed.

## Configure GCP Whitelist Feed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GCP Whitelist Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gcp-whitelist-get-indicators
***
Gets indicators from the feed.


##### Base Command

`gcp-whitelist-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!gcp-whitelist-get-indicators limit=2```

##### Context Example
```
{}
```

##### Human Readable Output
### Indicators from GCP Whitelist Feed:
|value|type|
|---|---|
| 52.86.122.241/18 | CIDR |
| 52.15.91.198/18 | CIDR |

