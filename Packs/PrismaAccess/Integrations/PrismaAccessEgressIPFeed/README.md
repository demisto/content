## Overview
---

Dynamically retrieve and whitelist IPs Prisma Access uses to egress traffic to the internet and SaaS apps.

This integration can be used as a TIM feed to fetch indicators, or if a playbook starts from a non-indicator trigger it can use the command to get the IPs.


## Use Cases
---

## Configure Prisma Access Egress IP feed on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Prisma Access Egress IP feed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch indicators__
    * __URL__
    * __Prisma Access API Key__
    * __Service Type__
    * __Address Type__
    * __Location__
    * __Indicator Reputation__
    * __Source Reliability__
    * __feedExpirationPolicy__
    * __feedExpirationInterval__
    * __Feed Fetch Interval__
    * __Bypass exclusion list__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. prisma-access-get-indicators
### 1. prisma-access-get-indicators
---
Gets indicators from the feed.

##### Base Command

`prisma-access-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.Egress.IP.Address | string | Prisma Access Egress IP address | 
| PrismaAccess.Egress.IP.Zone | string | Prisma Access Egress IP zone | 

