Ingest indicator feeds from OpenCTI. Compatible with OpenCTI 4.X API version.
This integration was integrated and tested with version v4.0.7 of OpenCTI Feed 4.X
## Configure OpenCTI Feed 4.X on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI Feed 4.X.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | API Key |  | True |
    | Indicators Type to fetch | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File", "Host", "IP", "IPv6", "Registry Key", and "URL". The rest will not cause automatic indicator creation in XSOAR. The default is "ALL". | True |
    | Max. indicators per fetch |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. If no option was chosen, the default Indicator Reputation will be taken from the Indicator data. | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. If no option was chosen the default TLP color will be taken from the Indicator data. | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Score start value | Score range start to filter by. Possible range is 1-100.  | False |
    | Score start value | Score range end to filter by. Possible range is 1-100.  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opencti-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`opencti-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-reset-fetch-indicators```

#### Human Readable Output

>Fetch history deleted successfully

### opencti-get-indicators
***
Gets indicators from the feed.


#### Base Command

`opencti-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return per fetch. The default value is "50". Maximum value is "500". | Optional | 
| indicator_types | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File", "Host", "IP", "IPv6", "Registry Key", and "URL". The rest will not cause automatic indicator creation in XSOAR. The default is "ALL". Possible values are: ALL, Account, Domain, Email, File, Host, IP, IPv6, Registry Key, URL. Default is ALL. | Optional | 
| last_run_id | The last ID from the previous call from which to begin pagination for this call. You can find this value at OpenCTI.IndicatorsList.LastRunID context path. | Optional | 
| score_start | Score range start to filter by. Possible range is 1-100. . | Optional | 
| score_end | Score range end to filter by. Possible range is 1-100. . | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-get-indicators limit=2 indicator_types="IP"```

#### Human Readable Output

>### Indicators
>|type|value|id|
>|---|---|---|
>| IP | 1.2.3.4 | 700c8187-2dce-4aeb-bf3a-0864cb7b02c7 |
>| IP | 1.1.1.1 | 33bd535b-fa1c-41e2-a6f9-80d82dd29a9b |

