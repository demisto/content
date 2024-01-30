GreyNoise is all about Internet Scanners.
## Configure GreyNoise Indicator Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GreyNoise Indicator Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Username |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Indicator Expiration Method |  | False |
    | Feed Expiration Interval |  | False |
    | Feed Fetch Interval |  | False |
    | Indicator Type | Type of the indicator in the feed. | True |
    | Search by Threat Type | "Search indicators by threat type \(e.g. malware, bulletproof_hosting, proxy_service\).<br/>If empty, all threat types will be considered." | False |
    | Malware Family | "Search indicators by malware family \(e.g. gozi_isfb, smokeloader, trickbot\).<br/>If empty, all malware families will be considered." | False |
    | Search by confidence | Search indicators by confidence. See detailed description of the confidence levels below. | False |
    | Free text indicator search (all fields included) |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | How far back in time to go when performing the first fetch. | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Create relationships | Create relationships between indicators as part of Enrichment. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### greynoise-get-indicators
***
Gets the feed indicators.


#### Base Command

`greynoise-get-indicators`
#### Input

| **Argument Name** | **Description**                                                                                        | **Required** |
|-------------------|--------------------------------------------------------------------------------------------------------|--------------|
| limit             | The maximum number of results to return. Default is 50. Will limit the result for each indicator type. | Optional     | 


#### Context Output

There is no context output for this command.

#### Command Example
```!greynoise-get-indicators limit=5```

#### Human Readable Output

>### Indicators
>| value               | type |
>|---------------------|------|
>| https://example.com | URL  |


