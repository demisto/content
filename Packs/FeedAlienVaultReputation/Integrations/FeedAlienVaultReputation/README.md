## Overview
---

Use the AlienVault Reputation feed integration to fetch indicators from the feed.


## Configure AlienVault Reputation Feed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for AlienVault Reputation Feed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Indicator Reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Source Reliability__: Reliability of the feed.
    * __Indicator Expiration Method__: The method by which to expire indicators from this feed for this integration instance.
    * __Fetch Interval__: Interval of the fetches.
    * __Bypass Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system. 
4. Click __Test__ to validate the URLs, token, and connection.
