Ingests indicators from Recorded Future feeds into Demisto.
This integration was integrated and tested with Recorded Future Feed
## Configure Recorded Future Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Recorded Future Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Indicator Type | Type of the indicator in the feed. | True |
    | API token |  | True |
    | Services |  | True |
    | Risk Rule | Limit the indicators list to a specific risk rule. To see available<br/>risk rules run the rf-feed-get-risk-rules command. This parameter will only be<br/>used for the 'connectApi' service. | False |
    | Fusion File Path | Load a custom risklist from a specified Recorded Future file path.<br/>If no file path is specified, the default risklist file is used. This parameter<br/>will only be used for the 'fusion' service. | False |
    | Tags | Supports CSV values. | False |
    | Request Timeout | Time in seconds before HTTP requests timeout. | True |
    | Malicious Threshold | The minimum score from the feed in order to to determine whether the indicator is malicious. Default is "65". For more information about Recorded Future scoring go to integration details. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Notes
The feed size can be change according to the chosen indicator type:
- IP - As of September 24, 2020, this risk list includes over 5.9k records.
- Domain - Due to additional sources of malicious domains added recently, the number of high risk domains collected and analyzed in Recorded Future has dramatically increased.  As a result, now cap this risklist at 100,000 domains.
- Hash - In the second half of 2018, improvements and enhancements to our hash collection and analysis processes led to a dramatic increase in risky hashes that meet the above criteria.  As a result, now cap this risklist at 100,000 hashes.
- URL - This risk list includes 100,000 records.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rf-feed-get-indicators
***
Gets indicators from the feed.


#### Base Command

`rf-feed-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. Default is 10. | Required | 
| indicator_type | The indicator type. Can be "ip", "domain", "hash", or "url". Possible values are: ip, domain, hash, url. | Optional | 


#### Context Output

There is no context output for this command.


### rf-feed-get-risk-rules
***
Get a list of the risk rules available for an indicator,
To limit the 'connectApi' service indicators list.


#### Base Command

`rf-feed-get-risk-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The indicator type. Possible values are: ip, domain, hash, url. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFutureFeed.RiskRule.Name | String | The risk rule name. | 
| RecordedFutureFeed.RiskRule.Description | String | The risk rule description. | 
| RecordedFutureFeed.RiskRule.Criticality | String | The risk rule criticality. | 



