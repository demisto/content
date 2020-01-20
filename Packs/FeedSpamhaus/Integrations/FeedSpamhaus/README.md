## Overview
---

Use the Spamhaus feed integration to fetch indicators from the feed.


## Configure SpamhausFeed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SpamhausFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Sub-Feeds__
    * __Fetch indicators__
    * __Fetch Interval__
    * __Indicator Type__
    * __Reliability__ 
    * __Skip Exclusion List__
    * __Indicator reputation__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Request Timeout__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. get-indicators
### 1. get-indicators
---
Gets the feed indicators.

##### Base Command

`get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. | Optional | 
| indicator_type | The indicator type. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpamhausFeed.Indicator.Value | String | The indicator value. | 
| SpamhausFeed.Indicator.Type | String | The indicator type. | 
| SpamhausFeed.Indicator.RawJSON | Unknown | The indicator rawJSON value. | 


##### Command Example
```!get-indicators limit=20```

##### Human Readable Output
| **Value** | **Type** | **Rawjson** |
| --- | --- | --- |
| 5.79.79.209 | IP | ```indicator: 5.79.79.209 None: IP used by banjori C&C, 2020-01-16 09:03, http://osint.bambenekconsulting.com/manual/banjori.txt value: 5.79.79.209 type: IP``` | 
