Use the Microsoft Azure AD Connect Health Feed integration to get indicators from the feed.
This integration was integrated and tested with version 1 of Azure AD Connect Health Feed
## Configure Azure AD Connect Health Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False || feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| url | The Microsoft Azure endpoint URL | True |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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