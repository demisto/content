The TAXII Feed integration ingests indicator feeds from TAXII 1.x servers.

## Configure TAXIIFeed on Demisto

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for TAXIIFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.
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


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXII.Indicator.Value | String | The indicator value. | 
| TAXII.Indicator.Type | String | The indicator type. | 
| TAXII.Indicator.Rawjson | Unknown | The indicator rawJSON value. | 


##### Command Example
```!get-indicators limit=5 initial_interval="10 days"```

##### Context Example
```
{
    "TAXII.Indicator": [
        {
            "Type": "URL", 
            "Value": "http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/", 
            "Rawjson": {
                "indicator": "http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/", 
                "stix_title": "URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/...", 
                "share_level": "white", 
                "value": "http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/", 
                "stix_description": "URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/| isOnline:yes| dateVerified:2020-01-06T07:55:08+00:00", 
                "type": "URL"
            }
        }, 
        {
            "Type": "URL", 
            "Value": "https://software8n-chase.com/home/", 
            "Rawjson": {
                "indicator": "https://software8n-chase.com/home/", 
                "stix_title": "URL: https://software8n-chase.com/home/...", 
                "share_level": "white", 
                "value": "https://software8n-chase.com/home/", 
                "stix_description": "URL: https://software8n-chase.com/home/| isOnline:yes| dateVerified:2020-01-06T07:54:30+00:00", 
                "type": "URL"
            }
        }, 
        {
            "Type": "URL", 
            "Value": "https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php", 
            "Rawjson": {
                "indicator": "https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php", 
                "stix_title": "URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/inde...", 
                "share_level": "white", 
                "value": "https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php", 
                "stix_description": "URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php| isOnline:yes| dateVerified:2020-01-06T13:25:07+00:00", 
                "type": "URL"
            }
        }, 
        {
            "Type": "URL", 
            "Value": "http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66", 
            "Rawjson": {
                "indicator": "http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66", 
                "stix_title": "URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/accou...", 
                "share_level": "white", 
                "value": "http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66", 
                "stix_description": "URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66| isOnline:yes| dateVerified:2020-01-06T07:37:02+00:00", 
                "type": "URL"
            }
        }, 
        {
            "Type": "URL", 
            "Value": "https://icloud.com.uk-maps.info/?ld=iXS64Gold", 
            "Rawjson": {
                "indicator": "https://icloud.com.uk-maps.info/?ld=iXS64Gold", 
                "stix_title": "URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold...", 
                "share_level": "white", 
                "value": "https://icloud.com.uk-maps.info/?ld=iXS64Gold", 
                "stix_description": "URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold| isOnline:yes| dateVerified:2020-01-06T09:38:56+00:00", 
                "type": "URL"
            }
        }
    ]
}
```

##### Human Readable Output
### Indicators
|Value|Type|Rawjson|
|---|---|---|
| http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/ | URL | indicator: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/<br/>type: URL<br/>stix_title: URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/...<br/>stix_description: URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/\| isOnline:yes\| dateVerified:2020-01-06T07:55:08+00:00<br/>share_level: white<br/>value: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/ |
| https://software8n-chase.com/home/ | URL | indicator: https://software8n-chase.com/home/<br/>type: URL<br/>stix_title: URL: https://software8n-chase.com/home/...<br/>stix_description: URL: https://software8n-chase.com/home/\| isOnline:yes\| dateVerified:2020-01-06T07:54:30+00:00<br/>share_level: white<br/>value: https://software8n-chase.com/home/ |
| https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php | URL | indicator: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php<br/>type: URL<br/>stix_title: URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/inde...<br/>stix_description: URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php\| isOnline:yes\| dateVerified:2020-01-06T13:25:07+00:00<br/>share_level: white<br/>value: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php |
| http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66 | URL | indicator: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66<br/>type: URL<br/>stix_title: URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/accou...<br/>stix_description: URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66\| isOnline:yes\| dateVerified:2020-01-06T07:37:02+00:00<br/>share_level: white<br/>value: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66 |
| https://icloud.com.uk-maps.info/?ld=iXS64Gold | URL | indicator: https://icloud.com.uk-maps.info/?ld=iXS64Gold<br/>type: URL<br/>stix_title: URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold...<br/>stix_description: URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold\| isOnline:yes\| dateVerified:2020-01-06T09:38:56+00:00<br/>share_level: white<br/>value: https://icloud.com.uk-maps.info/?ld=iXS64Gold |
