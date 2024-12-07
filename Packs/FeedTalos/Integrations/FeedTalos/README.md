Use the Talos Feed integration to get indicators from the feed.

## Configure Talos Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | Expiration Method | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| url | Talos Endpoint URL | True |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| feed | Fetch indicators | False |
| feed | Fetch indicators | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### talos-get-indicators
***
Gets indicators from the feed.


#### Base Command

`talos-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!talos-get-indicators```

#### Human Readable Output

| value	           | type |
| ---------------- | ---  |
| 60.249.23.235	   |  IP  |