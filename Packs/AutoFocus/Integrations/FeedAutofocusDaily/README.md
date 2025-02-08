Deprecated. use the AutoFocus Feed integration instead.
Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
For more information click [here](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).
TIM customers that upgraded to version 6.2 or above, can have the API Key pre-configured in their main account so no additional input is needed. To use this feature, upgrade your license so it includes the license key.

## Configure AutoFocus Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| api_key | API Key. | False |
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |
| override_default_credentials | Override default credentials | False | 
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use the system proxy settings. | False |



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| demsito\<Span\>.com | Domain |
| {file hash} | File |
| 8.8.8.8 | IP |
| demsito\<Span\>.com/some/aditional/path | URL |

To bring the next batch of indicators run:
`!autofocus-daily-get-indicators limit=4 offset=4`