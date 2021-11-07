The TAXII Feed integration ingests indicator feeds from TAXII 1.x servers.

## Configure TAXIIFeed on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for TAXIIFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Discovery Service__: TAXII discovery service endpoint. For example: `http://hailataxii.com/taxii-discovery-service`
    * __Collection__: Collection name to fetch indicators from.
    * __Subscription ID__: Subscription ID for the TAXII consumer.
    * __Username__: Username/Password (if required)
    * __Request Timeout__: Time (in seconds) before HTTP requests timeout.
    * __Poll Service__: Used by a TAXII Client to request information from a TAXII Server.
    * __API Key__: API key used for authentication with the TAXII server.
    * __API Header Name__: API key header to be used to provide API key to the TAXII server. For example, "Authorization".
    * __First Fetch Time__: The time interval for the first fetch (retroactive). [number] [time unit] of type minute/hour/day. For example, 1 minute, 12 hours, 7 days.
4. Click __Test__ to validate the URLs, token, and connection.

## Step by step configuration
As an example, we'll use the public TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_. These are the feed instance configuration parameters for our example.

**Indicator Reputation** - Because this is just an example, we can leave the default value. Ordinarily you would set the reputation based on the specific feed's information about what type of indicators they are returning, i.e., whether they are good or bad.

**Source Reliability** - Because this is just an example, we can leave the default value. Ordinarily you would set the reliability according to your level of trust in this feed.

**Indicator Expiration Method** - For this example, we can leave the default value here. Ordinarily you would set the value according to the type of feed you were fetching from. As an example, let's that you are a customer of a Cloud Services provider and you want to add the URLs from which that provider serves up many of the services you use to your network firewall exclusion list. Assuming that that same Cloud Services provider maintains an up-to-date feed of the URLs from which they currently provide service, you would probably want to configure a feed integration instance with this parameter set to `Expire indicators when they disappear from feed` so that you don't continue to mark a given URL with a `Good` reputation after it is no longer being used by your Cloud Services provider.

**Feed Fetch Interval** - For this example, we can leave the default value here.

**Discovery Service** - Enter `http://hailataxii.com/taxii-discovery-service`.

**Collection** - Enter `guest.Abuse_ch`.

**Subscription ID** - No need to enter a value here for this example since the TAXII server we are addressing does not require it so we'll leave it blank.

**Username** - Enter `guest`.

**Password** - Enter `guest`.

**Request Timeout** - Let's increase the number to `80` seconds since the request may take a while to complete.

**Poll Service** - We don't have to enter a value here for this example because the poll service will be determined dynamically in the integration code if it is not explicitly provided.

**API Key** - We don't have to enter a value here for this example because the TAXII server we are addressing doesn't require an API key.

**API Header Name** - We don't have to enter a value here for this example because the TAXII server we are addressing doesn't require an API header name.

**First Fetch Time** - Since this example feed isn't very high volume, let's enter `500 days`  to make sure we fetch a sufficient number of indicators.

Click the `Test` button and ensure that a green `Success` message is returned.

Now we have successfully configured an instance for the TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map indicator data returned by the feed to actual indicator fields in Cortex XSOAR.
We can use `Set up a new classification rule` using actual data from the feed.

### Get indicators
---
Gets indicators from the the feed.
##### Base Command

`get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 
| initial_interval | The time interval for the first fetch (retroactive). `<number> <time unit>` of type minute/hour/day. For example, 1 minute, 12 hours, 7 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXII.Indicator.Value | String | The indicator value. | 
| TAXII.Indicator.Type | String | The indicator type. | 
| TAXII.Indicator.title | String | The indicator title. | 
| TAXII.Indicator.description | String | The observable description. | 
| TAXII.Indicator.stixindicatordescription | String | The indicator description. | 
| TAXII.Indicator.stixindicatorname | String | The indicator title. | 
| TAXII.Indicator.stixttptitle | String | The ttp title. | 
| TAXII.Indicator.stixmalwaretypes | String | The stix malware type. | 
| TAXII.Indicator.confidence | String | The indicator confidence. | 
| TAXII.Indicator.score | String | The indicator DBot score. | 
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
