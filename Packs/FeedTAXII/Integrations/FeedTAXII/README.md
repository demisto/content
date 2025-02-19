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
    * __Discovery Service__: TAXII discovery service endpoint. For example: `http://example.com/taxii-discovery-service`
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

**Discovery Service** - Enter `http://example.com/taxii-discovery-service`.

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
| TAXII.Indicator.Title | String | The observable title. | 
| TAXII.Indicator.Description | String | The observable description. | 
| TAXII.Indicator.Stixindicatordescription | String | The indicator description. | 
| TAXII.Indicator.Stixindicatorname | String | The indicator title. | 
| TAXII.Indicator.Stixttptitle | String | The ttp title. | 
| TAXII.Indicator.Stixmalwaretypes | String | The stix malware type. | 
| TAXII.Indicator.Confidence | String | The indicator confidence. | 
| TAXII.Indicator.Score | String | The indicator DBot score. | 
| TAXII.Indicator.Relationships | String | The indicator relationships. | 
| TAXII.Indicator.Fields | Unknown | The indicator fields. | 
| TAXII.Indicator.Rawjson | Unknown | The indicator rawJSON value. | 


#### Command Example
```!get-indicators limit=1 initial_interval="1 day"```

#### Context Example
```json
{
    "TAXII": {
        "Indicator": [
            {
                "Confidence": "High",
                "Description": "URL: https://example.com| isOnline:yes| dateVerified:2021-11-06T21:53:09+00:00",
                "Fields": {},
                "Rawjson": {
                    "TLP": "WHITE",
                    "confidence": "High",
                    "indicator": "https://example.com",
                    "indicator_ref": "opensource:Observable-9fe6464a-4a53-4269-90c6-d81013b2073e",
                    "relationships": [
                        {
                            "indicator": "URL embedded in Email",
                            "stix_ttp_title": "Email Emmbedded URL",
                            "ttp_description": "Target Users via Email by adding a malicious URL",
                            "type": "Attack Pattern",
                            "value": "URL embedded in Email"
                        }
                    ],
                    "share_level": "white",
                    "stix_description": "URL: https://example.com| isOnline:yes| dateVerified:2021-11-06T21:53:09+00:00",
                    "stix_indicator_description": "This URL:[https://example.com] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-11-06T21:53:09+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7341640",
                    "stix_indicator_name": "phishTank.com id:7341640 with malicious URL:https://example.com...",
                    "stix_title": "URL: https://example.com...",
                    "ttp_ref": [
                        "opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"
                    ],
                    "type": "URL",
                    "value": "https://example.com"
                },
                "Relationships": [
                    {
                        "entityA": "https://example.com",
                        "entityAFamily": "Indicator",
                        "entityAType": "URL",
                        "entityB": "URL embedded in Email",
                        "entityBFamily": "Indicator",
                        "entityBType": "Attack Pattern",
                        "fields": {},
                        "name": "related-to",
                        "reverseName": "related-to",
                        "type": "IndicatorToIndicator"
                    }
                ],
                "Stixindicatordescription": "This URL:[https://example.com] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-11-06T21:53:09+00:00. More detailed infomation can be found at http://www.phishtank.com/phish_detail.php?phish_id=7341640",
                "Stixindicatorname": "phishTank.com id:7341640 with malicious URL:https://example.com...",
                "Title": "URL: https://example.com...",
                "Type": "URL",
                "Value": "https://example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators
>|Value|Type|Rawjson|
>|---|---|---|
>| https://example.com | URL | indicator: https://example.com<br/>type: URL<br/>indicator_ref: opensource:Observable-9fe6464a-4a53-4269-90c6-d81013b2073e<br/>stix_title: URL: https://example.com...<br/>stix_description: URL: https://example.com\| isOnline:yes\| dateVerified:2021-11-06T21:53:09+00:00<br/>share_level: white<br/>TLP: WHITE<br/>stix_indicator_name: phishTank.com id:7341640 with malicious URL:https://example.com...<br/>stix_indicator_description: This URL:[https://example.com] was identified by phishtank.com as part of a phishing email. This URL appears to still be online as of 2021-11-06T21:53:09+00:00. More detailed infomation can be found at http:<span>//</span>www.phishtank.com/phish_detail.php?phish_id=7341640<br/>confidence: High<br/>ttp_ref: opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29<br/>relationships: {'stix_ttp_title': 'Email Emmbedded URL', 'ttp_description': 'Target Users via Email by adding a malicious URL', 'type': 'Attack Pattern', 'indicator': 'URL embedded in Email', 'value': 'URL embedded in Email'}<br/>value: https://example.com |

