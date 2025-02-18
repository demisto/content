Use this feed to retrieve the discovered IPs/Domains/Certificates from Expanse Expander asset database.

This integration was developed and tested with version 2 of Expander Asset API.

Expanse is a Palo Alto Networks company.

Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure Expanse Expander Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Your server URL | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| feed | Fetch indicators | False |
| max_fetch | The maximum number of indicators to fetch. | False |
| min_last_observed | Retrieve indicators observed in the last specified number of days | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedReliability | Source Reliability | True |
| feedReputation | Indicator Reputation | False |
| feedTags | Tags | False |
| tlp_color | Traffic Light Protocol Color | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### feedexpanse-get-indicators
***
Retrieve discovered IPs/IP Ranges/Domains/Certificates


#### Base Command

`feedexpanse-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_indicators | The maximum number of results to return per type | Optional | 
| ip | Retrieve discovered IPs | Optional | 
| domain | Retrieve discovered Domains | Optional | 
| certificate | Retrieve discovered certificates | Optional | 
| iprange | Retrieve IP Ranges | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!feedexpanse-get-indicators max_indicators=1 certificate=yes ip=yes domain=yes```

#### Human Readable Output

>### Expanse Indicators (capped at 1)
>|value|type|
>|---|---|
>| 198.51.100.220 | IP |
>| e0ce1c7a7e02d3a9f361a760e9f2ab22fe3d7e9a9ee9188386b1abff44be6b5f | Certificate |
>| test.example.com | Domain |
>| 198.51.100..0/24 | CIDR |
