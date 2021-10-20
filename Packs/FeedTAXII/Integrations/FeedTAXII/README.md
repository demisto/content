Ingests indicator feeds from TAXII 1.x servers.
This integration was integrated and tested with version xx of TAXIIFeed

## Configure TAXII Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TAXII Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Discovery Service | TAXII discovery service endpoint. For example, http://hailataxii.com/taxii-discovery-service | True |
    | Collection | Collection name to fetch indicators from. | False |
    | Subscription ID | Subscription ID for the TAXII consumer. | False |
    | Name (To use the API key click the "?" icon) |  | False |
    | Password |  | False |
    | Certificate File as Text | Add a certificate file as text to connect to the TAXII server | False |
    | Key File as Text | Add a key file as text to connect to the TAXII server | False |
    | Request Timeout | Time \(in seconds\) before HTTP requests timeout. | False |
    | Poll Service | Used by a TAXII Client to request information from a TAXII Server. | False |
    | First Fetch Time | The time interval for the first fetch \(retroactive\). &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt; of type minute/hour/day. For example, 1 minute, 12 hours, 7 days. | False |
    | Tags | Supports CSV values. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-indicators
***
Gets indicators from the the feed.


#### Base Command

`get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 50. | Optional | 
| initial_interval | The time interval for the first fetch (retroactive). &lt;number&gt; &lt;time unit&gt; of type minute/hour/day. For example, 1 minute, 12 hours, 7 days. Default is 1 day. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXII.Indicator.Value | String | The indicator value. | 
| TAXII.Indicator.Type | String | The indicator type. | 
| TAXII.Indicator.title | String | The indicator title. | 
| TAXII.Indicator.description | String | The indicator description. | 
| TAXII.Indicator.stixindicatordescription | String | The indicator description. | 
| TAXII.Indicator.stixindicatorname | String | The indicator title. | 
| TAXII.Indicator.stixttptitle | String | The ttp title. | 
| TAXII.Indicator.stixmalwaretypes | String | The stix malware type. | 
| TAXII.Indicator.confidence | String | The indicator confidence. | 
| TAXII.Indicator.fields | Unknown | The indicator value. | 
| TAXII.Indicator.Rawjson | Unknown | The indicator rawJSON value. | 


#### Command Example
```!get-indicators limit=4 initial_interval="1 day"```


##### Context Example
```
{
    "TAXII.Indicator": [
       {
           "value": "http://example.com/?n",
           "type": "URL",
           "title": "URL: http://example.com/?n...",
           "description": "URL: http://example.com/?n| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
           "stixindicatorname": "phishTank.com id:7324360 with malicious URL:http://example...",
           "stixindicatordescription": "This URL:[http://example.com/?n] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324360",
           "confidence": "High",
           "fields": {
               "title": "URL: http://example.com/?n...",
               "description": "URL: http://example.com/?n| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "stixindicatorname": "phishTank.com id:7324360 with malicious URL:http://example...",
               "stixindicatordescription": "This URL:[http://example.com/?n] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324360",
               "confidence": "High"
           },
           "relationships": [
               {
                   "name": "related-to",
                   "reverseName": "related-to",
                   "type": "IndicatorToIndicator",
                   "entityA": "http://example.com/?n",
                   "entityAFamily": "Indicator",
                   "entityAType": "URL",
                   "entityB": "URL embedded in Email",
                   "entityBFamily": "Indicator",
                   "entityBType": "Attack Pattern",
                   "fields": {}
               }
           ],
           "rawJSON": {
               "indicator": "http://example.com/?n",
               "type": "URL",
               "indicator_ref": "opensource:Observable-335290e0-3496-4644-bdaa-25b323814b46",
               "stix_title": "URL: http://example.com/?n...",
               "stix_description": "URL: http://example.com/?n| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "TLP": "WHITE",
               "stix_indicator_name": "phishTank.com id:7324360 with malicious URL:http://example...",
               "stix_indicator_description": "This URL:[http://example.com/?n] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324360",
               "confidence": "High",
               "ttp_ref": [
                   "opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"
               ],
               "relationships": [
                   {
                       "stix_ttp_title": "Email Emmbedded URL",
                       "ttp_description": "Target Users via Email by adding a malicious URL",
                       "type": "Attack Pattern",
                       "indicator": "URL embedded in Email",
                       "value": "URL embedded in Email"
                   }
               ],
               "value": "http://example.com/?n"
           }
       },
       {
           "value": "https://pancakeswap.finance.exchange-goswap.com/",
           "type": "URL",
           "title": "URL: https://pancakeswap.finance.exchange-goswap.com/...",
           "description": "URL: https://pancakeswap.finance.exchange-goswap.com/| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
           "stixindicatorname": "phishTank.com id:7324397 with malicious URL:http://example...",
           "stixindicatordescription": "This URL:[https://pancakeswap.finance.exchange-goswap.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324397",
           "confidence": "High",
           "fields": {
               "title": "URL: https://pancakeswap.finance.exchange-goswap.com/...",
               "description": "URL: https://pancakeswap.finance.exchange-goswap.com/| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "stixindicatorname": "phishTank.com id:7324397 with malicious URL:http://example...",
               "stixindicatordescription": "This URL:[https://pancakeswap.finance.exchange-goswap.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324397",
               "confidence": "High"
           },
           "relationships": [
               {
                   "name": "related-to",
                   "reverseName": "related-to",
                   "type": "IndicatorToIndicator",
                   "entityA": "https://pancakeswap.finance.exchange-goswap.com/",
                   "entityAFamily": "Indicator",
                   "entityAType": "URL",
                   "entityB": "URL embedded in Email",
                   "entityBFamily": "Indicator",
                   "entityBType": "Attack Pattern",
                   "fields": {}
               }
           ],
           "rawJSON": {
               "indicator": "https://pancakeswap.finance.exchange-goswap.com/",
               "type": "URL",
               "indicator_ref": "opensource:Observable-5af3d9a1-b0ac-4846-95b0-efd498c14594",
               "stix_title": "URL: https://pancakeswap.finance.exchange-goswap.com/...",
               "stix_description": "URL: https://pancakeswap.finance.exchange-goswap.com/| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "TLP": "WHITE",
               "stix_indicator_name": "phishTank.com id:7324397 with malicious URL:http://example...",
               "stix_indicator_description": "This URL:[https://pancakeswap.finance.exchange-goswap.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324397",
               "confidence": "High",
               "ttp_ref": [
                   "opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"
               ],
               "relationships": [
                   {
                       "stix_ttp_title": "Email Emmbedded URL",
                       "ttp_description": "Target Users via Email by adding a malicious URL",
                       "type": "Attack Pattern",
                       "indicator": "URL embedded in Email",
                       "value": "URL embedded in Email"
                   }
               ],
               "value": "https://pancakeswap.finance.exchange-goswap.com/"
           }
       },
       {
           "value": "http://example.com/",
           "type": "URL",
           "title": "URL: http://example.com/...",
           "description": "URL: http://example.com/| isOnline:yes| dateVerified:2021-10-19T10:07:34+00:00",
           "stixindicatorname": "phishTank.com id:7324767 with malicious URL:http://example...",
           "stixindicatordescription": "This URL:[http://example.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T10:07:34+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324767",
           "confidence": "High",
           "fields": {
               "title": "URL: http://example.com/...",
               "description": "URL: http://example.com/| isOnline:yes| dateVerified:2021-10-19T10:07:34+00:00",
               "stixindicatorname": "phishTank.com id:7324767 with malicious URL:http://example...",
               "stixindicatordescription": "This URL:[http://example.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T10:07:34+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324767",
               "confidence": "High"
           },
           "relationships": [
               {
                   "name": "related-to",
                   "reverseName": "related-to",
                   "type": "IndicatorToIndicator",
                   "entityA": "http://example.com/",
                   "entityAFamily": "Indicator",
                   "entityAType": "URL",
                   "entityB": "URL embedded in Email",
                   "entityBFamily": "Indicator",
                   "entityBType": "Attack Pattern",
                   "fields": {}
               }
           ],
           "rawJSON": {
               "indicator": "http://example.com/",
               "type": "URL",
               "indicator_ref": "opensource:Observable-cfe14953-f986-450b-93f1-0041a597b8d2",
               "stix_title": "URL: http://example.com/...",
               "stix_description": "URL: http://example.com/| isOnline:yes| dateVerified:2021-10-19T10:07:34+00:00",
               "TLP": "WHITE",
               "stix_indicator_name": "phishTank.com id:7324767 with malicious URL:http://example...",
               "stix_indicator_description": "This URL:[http://example.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T10:07:34+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324767",
               "confidence": "High",
               "ttp_ref": [
                   "opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"
               ],
               "relationships": [
                   {
                       "stix_ttp_title": "Email Emmbedded URL",
                       "ttp_description": "Target Users via Email by adding a malicious URL",
                       "type": "Attack Pattern",
                       "indicator": "URL embedded in Email",
                       "value": "URL embedded in Email"
                   }
               ],
               "value": "http://example.com/"
           }
       },
       {
           "value": "http://example.org/mellenium/index.php",
           "type": "URL",
           "title": "URL: http://example.org/mellenium/index.php...",
           "description": "URL: http://example.org/mellenium/index.php| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
           "stixindicatorname": "phishTank.com id:7324342 with malicious URL:http://example.org/melle...",
           "stixindicatordescription": "This URL:[http://example.org/mellenium/index.php] was identified by phishtank.com as part of a phishing email which appears to be targeting Bank Millennium This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324342",
           "confidence": "High",
           "fields": {
               "title": "URL: http://example.org/mellenium/index.php...",
               "description": "URL: http://example.org/mellenium/index.php| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "stixindicatorname": "phishTank.com id:7324342 with malicious URL:http://example.org/melle...",
               "stixindicatordescription": "This URL:[http://example.org/mellenium/index.php] was identified by phishtank.com as part of a phishing email which appears to be targeting Bank Millennium This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324342",
               "confidence": "High"
           },
           "relationships": [
               {
                   "name": "related-to",
                   "reverseName": "related-to",
                   "type": "IndicatorToIndicator",
                   "entityA": "http://example.org/mellenium/index.php",
                   "entityAFamily": "Indicator",
                   "entityAType": "URL",
                   "entityB": "URL embedded in Email",
                   "entityBFamily": "Indicator",
                   "entityBType": "Attack Pattern",
                   "fields": {}
               }
           ],
           "rawJSON": {
               "indicator": "http://example.org/mellenium/index.php",
               "type": "URL",
               "indicator_ref": "opensource:Observable-810ca3be-d3b7-460f-ae17-a73bcd899633",
               "stix_title": "URL: http://example.org/mellenium/index.php...",
               "stix_description": "URL: http://example.org/mellenium/index.php| isOnline:yes| dateVerified:2021-10-19T04:13:43+00:00",
               "TLP": "WHITE",
               "stix_indicator_name": "phishTank.com id:7324342 with malicious URL:http://example.org/melle...",
               "stix_indicator_description": "This URL:[http://example.org/mellenium/index.php] was identified by phishtank.com as part of a phishing email which appears to be targeting Bank Millennium This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324342",
               "confidence": "High",
               "ttp_ref": [
                   "opensource:ttp-86c046db-2a49-4a90-8abc-3e274b11027d",
                   "opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"
               ],
               "relationships": [
                   {
                       "stix_ttp_title": "Email Emmbedded URL",
                       "ttp_description": "Target Users via Email by adding a malicious URL",
                       "type": "Attack Pattern",
                       "indicator": "URL embedded in Email",
                       "value": "URL embedded in Email"
                   }
               ],
               "value": "http://example.org/mellenium/index.php"
           }
       }
    ]
}
```

#### Human Readable Output
### Indicators
|Value|Type|Rawjson|
|---|---|---|
| http://example.com/?n | URL | indicator: http://example.com/?n<br>type: URL<br>indicator_ref: opensource:Observable-335290e0-3496-4644-bdaa-25b323814b46<br>stix_title: URL: http://example.com/?n...<br>stix_description: URL: http://example.com/?n\| isOnline:yes\| dateVerified:2021-10-19T04:13:43+00:00<br>TLP: WHITE<br>stix_indicator_name: phishTank.com id:7324360 with malicious URL:http://example...<br>stix_indicator_description: This URL:[http://example/?n] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324360<br>confidence: High<br>ttp_ref: opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29<br>relationships: {'stix_ttp_title': 'Email Emmbedded URL', 'ttp_description': 'Target Users via Email by adding a malicious URL', 'type': 'Attack Pattern', 'indicator': 'URL embedded in Email', 'value': 'URL embedded in Email'}<br>value: http://example.com/?n |
| https://pancakeswap.finance.exchange-goswap.com/ | URL | indicator: https://pancakeswap.finance.exchange-goswap.com/<br>type: URL<br>indicator_ref: opensource:Observable-5af3d9a1-b0ac-4846-95b0-efd498c14594<br>stix_title: URL: https://pancakeswap.finance.exchange-goswap.com/...<br>stix_description: URL: https://pancakeswap.finance.exchange-goswap.com/\| isOnline:yes\| dateVerified:2021-10-19T04:13:43+00:00<br>TLP: WHITE<br>stix_indicator_name: phishTank.com id:7324397 with malicious URL:http://example...<br>stix_indicator_description: This URL:[https://pancakeswap.finance.exchange-goswap.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324397<br>confidence: High<br>ttp_ref: opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29<br>relationships: {'stix_ttp_title': 'Email Emmbedded URL', 'ttp_description': 'Target Users via Email by adding a malicious URL', 'type': 'Attack Pattern', 'indicator': 'URL embedded in Email', 'value': 'URL embedded in Email'}<br>value: https://pancakeswap.finance.exchange-goswap.com/ |
| http://example.com/ | URL | indicator: http://example.com/<br>type: URL<br>indicator_ref: opensource:Observable-cfe14953-f986-450b-93f1-0041a597b8d2<br>stix_title: URL: http://example.com/...<br>stix_description: URL: http://example.com/\| isOnline:yes\| dateVerified:2021-10-19T10:07:34+00:00<br>TLP: WHITE<br>stix_indicator_name: phishTank.com id:7324767 with malicious URL:http://example...<br>stix_indicator_description: This URL:[http://example.com/] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-10-19T10:07:34+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324767<br>confidence: High<br>ttp_ref: opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29<br>relationships: {'stix_ttp_title': 'Email Emmbedded URL', 'ttp_description': 'Target Users via Email by adding a malicious URL', 'type': 'Attack Pattern', 'indicator': 'URL embedded in Email', 'value': 'URL embedded in Email'}<br>value: http://example.com/ |
| http://example.org/mellenium/index.php | URL | indicator: http://example.org/mellenium/index.php<br>type: URL<br>indicator_ref: opensource:Observable-810ca3be-d3b7-460f-ae17-a73bcd899633<br>stix_title: URL: http://example.org/mellenium/index.php...<br>stix_description: URL: http://example.org/mellenium/index.php\| isOnline:yes\| dateVerified:2021-10-19T04:13:43+00:00<br>TLP: WHITE<br>stix_indicator_name: phishTank.com id:7324342 with malicious URL:http://example.org/melle...<br>stix_indicator_description: This URL:[http://example.org/mellenium/index.php] was identified by phishtank.com as part of a phishing email which appears to be targeting Bank Millennium This URL appears to still be online as of 2021-10-19T04:13:43+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7324342<br>confidence: High<br>ttp_ref: opensource:ttp-86c046db-2a49-4a90-8abc-3e274b11027d,<br>opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29<br>relationships: {'stix_ttp_title': 'Email Emmbedded URL', 'ttp_description': 'Target Users via Email by adding a malicious URL', 'type': 'Attack Pattern', 'indicator': 'URL embedded in Email', 'value': 'URL embedded in Email'}<br>value: http://example.org/mellenium/index.php |
