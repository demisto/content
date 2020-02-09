## Overview
---

Use the Office365 feed integration to get indicators from the feed.
This integration was integrated and tested with version xx of Office365 Feed


## Configure Office365 Feed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Office365 Feed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__
    * __Regions__
    * __Services__
    * __Indicator Reputation__
    * __Source Reliability__
    * __feedExpirationPolicy__
    * __feedExpirationInterval__
    * __Feed Fetch Interval__
    * __Bypass exclusion list__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. office365-get-indicators
### 1. office365-get-indicators
---
Gets indicators from the feed.

##### Base Command

`office365-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 
| indicator_type | The indicator type. Can be "IPs", "URLs", or "Both". The default value is "IPs". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example

!office365-get-indicators limit="5"

##### Human Readable Output

### Indicators from Office 365 Feed:
|value|type|
|---|---|
| 13.107.6.152/31 | CIDR |
| 23.103.160.0/20 | CIDR |
| 131.253.33.215/32 | CIDR |
| 132.245.0.0/16 | CIDR |
| 150.171.32.0/22 | CIDR |
| 204.79.197.215/32 | CIDR |
| 2603:1006::/40 | IPv6CIDR |
| 2603:1016::/36 | IPv6CIDR |

