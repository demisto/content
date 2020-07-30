A PassiveTotal with Security Intelligence Services Feed provides you with newly observed Domain, Host, Malware, Phishing, and Scam Blacklist with options for Daily and Hourly ingestion available.
This integration was integrated and tested with version xx of Security Intelligence Services Feed
## Configure SecurityIntelligenceServicesFeed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SecurityIntelligenceServicesFeed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| accessKey | S3 Access Key | True |
| secretKey | S3 Secret Key | True |
| feedType | Feed Type | True |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| firstFetchInterval | First Fetch Time Range | True |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings |  |

4. Click **Test** to validate the S3 Access Key, S3 Secret Key, Feed Types, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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

