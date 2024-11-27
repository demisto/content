Use the AlienVault OTX integration to fetch indicators using a TAXII client.

This integration can only fetch indicators from **active** collections. Active collections are those which contain at least one indicator.

## Configure AlienVault OTX TAXII Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |
| api_key | The AlienVault OTX API key. | True |
| all_collections | Whether to get all active collections - if selected the integration will run on all **active** collections regardless of the collections supplied in the collections parameter. Inactive collections will not return indicators. | False |
| collections | The collections to fetch from. | False |
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use the system proxy settings. | False |


If you do not know which collections are available - do not set the `Collections` and `All Collections` parameters. The resulting error message will list all the accessible collections.

**Note**: not all listed collections are **active**.




## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators
***
Gets the indicators from AlienVault OTX.


##### Base Command

`alienvaultotx-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!alienvaultotx-get-indicators limit=3```


##### Human Readable Output
### Indicators from AlienVault OTX TAXII:
|value|type|
|---|---|
| 1.2.3.4 | IP |
| https:/\<span\>/demisto.com | URL |
| demisto\<span\>.com | Domain |

## Video Demo
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedAlienVault/AlienVault_OTX_Feed_Demo.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedAlienVault/AlienVault_OTX_Feed_Demo.mp4
</video>