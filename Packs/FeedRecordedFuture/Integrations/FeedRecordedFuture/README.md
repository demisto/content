Ingests indicators from Recorded Future feeds into Cortex XSOAR.
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
    | Risk Rule | A comma-separated list of risk rules which limits the indicators list to a specific risk rule. For example: 'dhsAis,phishingUrl'. If more than one risk rule is set, the indicators fetching and the 'rf-feed-get-indicators' command will be executed for each risk rule. To see available risk rules run the rf-feed-get-risk-rules command. This parameter will only be used for the 'connectApi' service. Using the 'large' risk rule is not recommended. | False |
    | Fusion File Path | Load a custom risklist from a specified Recorded Future file path.<br/>If no file path is specified, the default risklist file is used. This parameter<br/>will only be used for the 'fusion' service. | False |
    | Tags | Supports CSV values. | False |
    | Request Timeout | Time in seconds before HTTP requests timeout. | True |
    | Malicious Threshold | The minimum score from the feed in order to to determine whether the indicator is malicious. Default is "65". For more information about Recorded Future scoring go to integration details. | False |
    | IOC Risk Score Threshold | If selected, will be used to filter out the ingested indicators, and only indicators with equivalent and higher risk score will be ingested into XSOAR. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Notes
1. It is highly recommended to not create multiple instances of the same indicator type, even when fetching both from fusion and connectApi. Creating multiple instances with same indicator type will lead to duplicate indicators being fetched which can cause performance issues for the server.
2. Recommended interval for fetching indicators according to Recorded Future documentation:

    | **Indicator Type** | **Recommended Fetch Interval**
    | --- | --- |
    | IP | 1 Hour. |
    | Domain | 2 Hours. |
    | Hash | 1 Day. |
    | URL | 2 Hours. |
    | Vulnerability | 2 Hours. |
3. Per instance configuration, it is recommended to use either `connectApi` or `fusion` as a service for chosen indicator type, and not both, as most of the data between both services is duplicated.
4. The feed size can be change according to the chosen indicator type:
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
| indicator_type | The indicator type. Can be "ip", "domain", "hash", "vulnerability" or "url". Possible values are: ip, domain, hash, url, vulnerability. | Optional | 


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
| indicator_type | The indicator type. Possible values are: ip, domain, hash, url, vulnerability. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFutureFeed.RiskRule.Name | String | The risk rule name. | 
| RecordedFutureFeed.RiskRule.Description | String | The risk rule description. | 
| RecordedFutureFeed.RiskRule.Criticality | String | The risk rule criticality. | 
