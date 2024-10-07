Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
For more information click [here](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).
This Feed supports the AutoFocus Custom Feed and the AutoFocus Samples Feed.
TIM customers that upgraded to version 6.2 or above, can have the API Key pre-configured in their main account so no additional input is needed. To use this feature, upgrade your license so it includes the license key.

**Note:** The `Daily Threat Feed` option is deprecated. No available replacement.

## Configure AutoFocus Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| indicator_feeds | The indicator feed. Choose the requested indicator feeds. The Custom Feeds and Samples Feed. | True |
| api_key | API Key. | False |
| custom_feed_urls | The URL for the custom feed to fetch. This applies only in cases where a Custom Feed is requested. | False |
| scope_type | The scope of the samples to be fetched. | False |
| sample_query | The query that will be used to fetch the samples. | False |
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


#### Custom Feed info:
To connect a custom AutoFocus feed you need to provide the Custom Feed URL.

The Custom Feed URL should be in this form:
https://autofocus.paloaltonetworks.com/IOCFeed/{Output_Feed_ID}/{Output_Feed_Name}


#### Samples Feed info:
To connect a samples AutoFocus feed you need to provide the scope of the samples and the query for the samples.
1. The scope can be either:
    1. public - Samples available for all organizations.
    2. private - Your own samples.
    3. global - Both public and private samples.
2. The samples query - is the query to be used to fetch the samples from AutoFocus.
You can go to AutoFocus UI -> Search -> Sample -> Advanced -> Create your desired query -> API -> copy the query.
`For example:
{
  "operator": "all",
  "children": [
    {
      "field": "sample.create_date",
      "operator": "is after",
      "value": [
        "30 days ago",
        "30 days ago"
      ]
    }
  ]
}`

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from AutoFocus.

Note: This command does not create indicators within Cortex XSOAR.

##### Base Command

`autofocus-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Optional | 
| offset | The index of the first indicator to fetch. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!autofocus-get-indicators limit=4```


##### Human Readable Output
### Indicators from AutoFocus:
|Value|Type|
|---|---|
| XSOAR\<Span\>.com | Domain |
| {file hash} | File |
| 8.8.8.8 | IP |
| demsito\<Span\>.com/some/aditional/path | URL |

To bring the next batch of indicators run:
`!autofocus-get-indicators limit=4 offset=4`


## Demo Video
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/7fd9e45c4d809dc1a41521c66828733dafe82148/Assets/FeedAutofocus/AutoFocus_Feed_demo.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/raw/7fd9e45c4d809dc1a41521c66828733dafe82148/Assets/FeedAutofocus/AutoFocus_Feed_demo.mp4 
</video>

**Note:** The video instructs users to click the **_API** link to get the JSON query of the *Autofocus Samples Search*. An easier option to get the JSON query is available via the **Export Search** button.