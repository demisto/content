Azure.CloudIPs Feed Integration.
## Configure AzureFeed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureFeed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | feed | Fetch indicators | False |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | tlp_color | Traffic Light Protocol Color | False |
    | feedExpirationPolicy |  | False |
    | feedExpirationInterval |  | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | regions | Regions | True |
    | services | Services | True |
    | feedTags | Tags | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | polling_timeout | Request Timeout | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-get-indicators
***
Gets indicators from the feed.


#### Base Command

`azure-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-get-indicators```

#### Human Readable Output
### Indicators from Azure Feed:
|value|type|
|---|---|
| 20.37.158.0/23 | CIDR |
| 20.37.194.0/24 | CIDR |
| 20.39.13.0/26 | CIDR |


