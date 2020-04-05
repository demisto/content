Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
## Configure AutoFocus Feed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AutoFocus Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| indicator_feeds | Indicator Feed | True |
| api_key | The AutoFocus API key | True |
| custom_feed_urls | The URL for the custom feed to fetch | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### autofocus-get-indicators
***
Gets the indicators from AutoFocus.


##### Base Command

`autofocus-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Required | 
| offset | The index of the first indicator to fetch. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!autofocus-get-indicators limit=4```


##### Human Readable Output
### Indicators from AutoFocus:
|Value|Type|
|---|---|
| demisto.com | Domain |
| {file hash} | File |
| 8.8.8.8 | IP |
| demsito.com/some/aditional/path | URL |

To bring the next batch of indicators run:
!autofocus-get-indicators limit=4 offset=4
