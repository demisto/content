GreyNoise is all about Internet Scanners.
## Configure GreyNoise Indicator Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GreyNoise Indicator Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                                    | **Description**                                                                                                                                                                                        | **Required** |
    |----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
    | Fetch indicators                                                                 |                                                                                                                                                                                                        | False |
    | Password                                                                         | GreyNoise API Key                                                                                                                                                                                      | False |
    | Indicator Reputation                                                             | Indicators from this integration instance will be marked with this reputation                                                                                                                          | False |
    | Source Reliability                                                               | Reliability of the source providing the intelligence data                                                                                                                                              | True |
    | Traffic Light Protocol Color                                                     | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed                                                                                                            | False |
    | Indicator Expiration Method                                                      |                                                                                                                                                                                                        | False |
    | Feed Expiration Interval                                                         |                                                                                                                                                                                                        | False |
    | Feed Fetch Interval                                                              |                                                                                                                                                                                                        | False |
    | Tags                                                                             | Supports CSV values.                                                                                                                                                                                   | False |
    | Bypass exclusion list                                                            | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Use system proxy settings                                                        |                                                                                                                                                                                                        | False |
    | Trust any certificate (not secure)                                               |                                                                                                                                                                                                        | False |

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

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| NONE              |                 |              | 


#### Context Output

There is no context output for this command.

#### Command Example
```!greynoise-get-indicators```

#### Human Readable Output

>### Indicators
>| value   | type | rawJSON | fields |
>|---------|------|---------|--------|
>| 1.3.4.5 | IP   | {data}  | fields |


