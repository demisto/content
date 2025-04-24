Use the AlienVault Reputation feed integration to fetch indicators from the feed.

## Configure AlienVault Reputation Feed in Cortex
---


   | Parameter | Description | Example |
   | --- | --- | ---| 
   | Name | A meaningful name for the integration instance. | alienvault_domain |
   | Fetch indicators | Select this check box to fetch indicators. | N/A |
   | Indicator Reputation | The reputation applied to indicators from this integration instance. The default value is Bad. | N/A |
   | Source Reliability | Reliability of the source providing the intelligence data. The default value is C - Fairly reliable | N/A |
   | Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | N/A |
   | feedExpirationPolicy | The method by which to expire indicators from this feed for this integration instance. | N/A |
   | feedExpirationInterval | How often to expire the indicators from this integration instance (in minutes). Only applies if the feedExpirationPolicy is "interval". The default value is 20160 (two weeks). | N/A |
   | Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance (in minutes). The default value is 60. | N/A | 
   | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | N/A |


## Commands
---
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed: alienvault-get-indicators
---
Gets the feed indicators.

##### Base Command

`alienvault-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. | Optional | 
| indicator_type | The indicator type. | Optional | 


##### Context Output

There is no context output for this command.