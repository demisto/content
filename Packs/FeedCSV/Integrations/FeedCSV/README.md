## Overview
---

Fetch indicators from a CSV feed.
 

## Configure CSV Feed on Demisto
---


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CSVFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __URL__
    * __Fetch indicators__
    * __Fetch Interval__
    * __Indicator Type__ 
    * __Username__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Request Timeout__
    * __Ignore Regex__
    * __Field Names__
    * __Delimiter__
    * __Doublequote__
    * __Escape character__
    * __Quote Character__
    * __Skip Initial Space__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. get-indicators
### 1. get-indicators
---
Gets indicators from the feed.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return to the output. | Optional | 
| indicator_type | The indicator type. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSV.Indicator.Value | String | The indicator value. | 
| CSV.Indicator.Type | String | The indicator type. | 
| CSV.Indicator.Rawjson | Unknown | The indicator rawJSON value. | 


##### Command Example
``` ```
