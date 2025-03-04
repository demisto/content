Use this feed integration to fetch Google Threat Intelligence Threat Lists matches. It processes the latest finished job retrieving its matches based on the limit parameter (40 by default) in every fetch until there are no more matches for that job.

## Configure Google Threat Intelligence Threat Lists on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Threat Intelligence Threat Lists.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| credentials | API Key. | True |
| feed_type | Feed type. | True |
| limit | The maximum number of results to return. Default is 10. | False | 
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedMinimumGTIScore | The minimum GTI score to import as part of the feed. | True |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gti-threatlists-get-indicators
***
Gets the matches from Google Threat Intelligence Threat Lists.

#### Base Command

`gti-threatlists-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed_type | Feed type. | Required | 
| package | Package in '%Y%m%d%H' format. If not given, the latest package is taken. | Optional | 
| limit | The maximum number of results to return. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gti-threatlists-get-indicators```
```!gti-threatlists-get-indicators feed=malware package=2025021910 limit=10```

#### Human Readable Output

### Indicators from Google Threat Intelligence Threat Lists:
| Id | Detections | Gti Threat Score | Gti Severity | Gti Verdict | Malware Families | Threat Actors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| f221425286c9073cbb2168f73120b6... | 59/69 | 80 | SEVERITY_LOW | VERDICT_MALICIOUS | beacon | SWEED |
