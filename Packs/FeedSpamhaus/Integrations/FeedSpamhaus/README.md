## Overview
---

Use the Spamhaus feed integration to fetch indicators from the feed.


## Configure SpamhausFeed on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SpamhausFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Services__: Services of Spamhaus to fetch indicators from.
     * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.  
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp
    * __Skip Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system. 
    * __Indicator reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Request Timeout__: Timeout of the polling request in seconds.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.


### spamhaus-get-indicators
***
Gets the feed indicators.


#### Base Command

`spamhaus-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional | 
| indicator_type | The indicator type. | Optional | 


#### Context Output

There is no context output for this command.