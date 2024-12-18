GreyNoise is a cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic. With this integration, users can contextualize existing alerts, filter false-positives, identify compromised devices, and track emerging threats. This Integration provides a feed of IPv4 Internet Scanners from GreyNoise.
This integration was integrated and tested with version 2.0.1 of GreyNoise SDK.

## Configure GreyNoise Indicator Feed in Cortex


| **Parameter** | **Description**                                                                                                                                                                                        | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| Fetch indicators |                                                                                                                                                                                                        | False |
| Username |                                                                                                                                                                                                        | False |
| Password |                                                                                                                                                                                                        | False |
| Indicator Reputation | Leave this selection blank.  Not used for this integration.                                                                                                                                            | False |
| Source Reliability | Reliability of the source providing the intelligence data                                                                                                                                              | True |
| GreyNoise Feed Type | Select which GreyNoise Feed to ingest                                                                                                                                                                  | True |
| Tags | Supports CSV values.                                                                                                                                                                                   | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed                                                                                                            | False |
| feedExpirationPolicy |                                                                                                                                                                                                        | False |
| feedExpirationInterval |                                                                                                                                                                                                        | False |
| Feed Fetch Interval |                                                                                                                                                                                                        | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |                                                                                                                                                                                                        | False |
| Trust any certificate (not secure) |                                                                                                                                                                                                        | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### greynoise-get-indicators

***
Gets the feed indicators.

#### Base Command

`greynoise-get-indicators`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreyNoiseFeed.Indicators.Value | String | The value of the indicator. | 
| GreyNoiseFeed.Indicators.Type | String | The type of the indicator. | 
| GreyNoiseFeed.Indicators.Tags | String | The GreyNoise tags associated with the indicator. | 