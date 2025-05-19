Use the AutoFocus Feeds integration to fetch indicators from AutoFocus.
For more information click [here](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).
This Feed supports the AutoFocus Custom Feed and the AutoFocus Samples Feed.
TIM customers that upgraded to version 6.2 or above, can have the API Key pre-configured in their main account so no additional input is needed. To use this feature, upgrade your license so it includes the license key.

**Note:** The `Daily Threat Feed` option is deprecated. No available replacement.

## Configure AutoFocus Feed in Cortex



| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Feed |  | True |
| API Key |  | False |
| The URL for the custom feed to fetch | Only necessary in case a Custom Feed is fetched. Can also support a CSV of Custom feed URLs. | False |
| Samples Feed Scope Type | Only necessary in case a Samples Feed is fetched. | False |
| Samples Feed Query | Relevant only for sample feeds. JSON styled AutoFocus query, an example can be found in the description \(?\) section. mandatory for Samples Feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. | False |



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