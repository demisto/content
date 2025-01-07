Majestic Million

## Troubleshooting

Ingesting a million indicators may cause performance issues.
The default value is 100k. If you encounter performance issues, consider decreasing the limit.

## Configure Majestic Million in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| limit | Number of top domains to fetch from the feed. | False |
| tlp_color | Traffic Light Protocol Color | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedTags | Tags | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| use_https | Use HTTPS connection | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### majesticmillion-get-indicators
***
Gets the feed indicators.


#### Base Command

`majesticmillion-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!majesticmillion-get-indicators limit=4```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Indicators
>|value|type|fields|
>|---|---|---|
>| facebook.com | Domain | domainname: facebook.com<br/>domainreferringsubnets: 500065<br/>domainreferringips: 2959982<br/>idndomain: facebook.com<br/>tags:  |
>| google.com | Domain | domainname: google.com<br/>domainreferringsubnets: 496082<br/>domainreferringips: 2743820<br/>idndomain: google.com<br/>tags:  |
>| youtube.com | Domain | domainname: youtube.com<br/>domainreferringsubnets: 451680<br/>domainreferringips: 2401931<br/>idndomain: youtube.com<br/>tags:  |
>| twitter.com | Domain | domainname: twitter.com<br/>domainreferringsubnets: 443003<br/>domainreferringips: 2369579<br/>idndomain: twitter.com<br/>tags:  |