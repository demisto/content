A PassiveTotal with Security Intelligence Services Feed provides you with newly observed Domain, Malware, Phishing, Content, and Scam Blacklist with Hourly ingestion available.
This integration was integrated and tested with version 1.0 of Security Intelligence Services Feed.

The XSOAR instance with **ElasticSearch** is required as this integration would ingest large amount of indicators from SIS to XSOAR.

For that same reason, in case this integration fails to fetch indicators with timeout error, the `feedIntegrationScript.timeout` configuration should be configured with value 45 or more.
## Configure Security Intelligence Services Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| accessKey | S3 Access Key | True |
| secretKey | S3 Secret Key | True |
| feedType | Feed Type | True |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedTags | Tags | False |
| MaxIndicators | Max Indicators Per Interval | True |
| firstFetchInterval | First Fetch Time Range \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | True |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sis-get-indicators
***
Gets indicators from Security Intelligence Services feed. Note- Indicators will fetch from the latest found object.


#### Base Command

`sis-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return from S3. Note- The maximum limit supported is 1000. | Optional | 
| feed_type | Indicators will be fetched based on feed_type. | Optional | 
| search | Indicators that match the given search pattern will be fetched. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sis-get-indicators limit=2 type=Domain```

#### Human Readable Output

>### Total indicators fetched: 2
>### Indicators from Security Intelligence Services feed
>|Value|Type|
>|---|---|
>| 0363059571.online | Domain |
>| 0363059571.xyz | Domain |
