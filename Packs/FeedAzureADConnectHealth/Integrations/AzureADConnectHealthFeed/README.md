Use the Microsoft Azure AD Connect Health Feed integration to get indicators from the feed.
This integration was integrated and tested with version 1 of Azure AD Connect Health Feed
## Configure Azure AD Connect Health Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure AD Connect Health Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| url | The Microsoft Azure endpoint URL | True |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-ad-health-get-indicators
***
Gets indicators from the feed.


#### Base Command

`azure-ad-health-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-health-get-indicators```

#### Context Example
```
{}
```

#### Human Readable Output

>### Indicators from Microsoft Azure Feed:
>|value|type|
>|---|---|
>| https://login.microsoftonline.com | URL |
>| https://secure.aadcdn.microsoftonline-p.com | URL |
>| https://login.windows.net | URL |
