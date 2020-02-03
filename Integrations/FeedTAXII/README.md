## Overview
---

Ingests indicator feeds from TAXII 1.x servers.

## Configure TAXIIFeed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for TAXIIFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Discovery Service__: TAXII discovery service endpoint. For example, http://hailataxii.com/taxii-discovery-service
    * __Collection__: Collection name to fetch indicators from.
    * __Subscription ID__: Subscription ID for the TAXII consumer.
    * __Username__: Username/Password (if required)
    * __Request Timeout__: Time (in seconds) before HTTP requests timeout.
    * __Poll Service__: Used by a TAXII Client to request information from a TAXII Server.
    * __API Key__: API key used for authentication with the TAXII server.
    * __API Header Name__: API key header to be used to provide API key to the TAXII server. For example, "Authorization".
    * __First Fetch Time__: The time interval for the first fetch (retroactive). <number> <time unit> of type minute/hour/day. For example, 1 minute, 12 hours, 7 days.
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. get-indicators
### 1. get-indicators
---
Gets indicators from the the feed.
##### Base Command

`get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. | Optional | 
| initial_interval | The time interval for the first fetch (retroactive). <number> <time unit> of type minute/hour/day. For example, 1 minute, 12 hours, 7 days. | Optional | 


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
| http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/ | URL | indicator: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/<br>type: URL<br>stix_title: URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/...<br>stix_description: URL: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/\| isOnline:yes\| dateVerified:2020-01-06T07:55:08+00:00<br>share_level: white<br>value: http://www.lifetmeda.ru/rewq/3e7479b6d30a8b744b96db72795b6aba/ |
| https://software8n-chase.com/home/ | URL | indicator: https://software8n-chase.com/home/<br>type: URL<br>stix_title: URL: https://software8n-chase.com/home/...<br>stix_description: URL: https://software8n-chase.com/home/\| isOnline:yes\| dateVerified:2020-01-06T07:54:30+00:00<br>share_level: white<br>value: https://software8n-chase.com/home/ |
| https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php | URL | indicator: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php<br>type: URL<br>stix_title: URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/inde...<br>stix_description: URL: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php\| isOnline:yes\| dateVerified:2020-01-06T13:25:07+00:00<br>share_level: white<br>value: https://hmrc.5-notifications.com/338c933a18e9b57f72e608e67c5e4afd/index.php |
| http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66 | URL | indicator: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66<br>type: URL<br>stix_title: URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/accou...<br>stix_description: URL: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66\| isOnline:yes\| dateVerified:2020-01-06T07:37:02+00:00<br>share_level: white<br>value: http://medimobility.es/wordpress/wp-admin/includes/onlinebanking/account/validation/chase.com/home/myaccount/billing.php?dispatched=66 |
| https://icloud.com.uk-maps.info/?ld=iXS64Gold | URL | indicator: https://icloud.com.uk-maps.info/?ld=iXS64Gold<br>type: URL<br>stix_title: URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold...<br>stix_description: URL: https://icloud.com.uk-maps.info/?ld=iXS64Gold\| isOnline:yes\| dateVerified:2020-01-06T09:38:56+00:00<br>share_level: white<br>value: https://icloud.com.uk-maps.info/?ld=iXS64Gold |
