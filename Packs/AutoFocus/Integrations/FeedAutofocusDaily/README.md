Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
For more information click [here](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).

## Configure AutoFocus Feed on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AutoFocus Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| api_key | The AutoFocus API key. | True |
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use the system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.


## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from AutoFocus.

Note: This command does not create indicators within Cortex XSOAR.

##### Base Command

`autofocus-daily-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Optional | 
| offset | The index of the first indicator to fetch. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!autofocus-daily-get-indicators limit=4```


##### Human Readable Output
### Indicators from AutoFocus:
|Value|Type|
|---|---|
| demisto\<Span\>.com | Domain |
| {file hash} | File |
| 8.8.8.8 | IP |
| demsito\<Span\>.com/some/aditional/path | URL |

To bring the next batch of indicators run:
`!autofocus-daily-get-indicators limit=4 offset=4`
