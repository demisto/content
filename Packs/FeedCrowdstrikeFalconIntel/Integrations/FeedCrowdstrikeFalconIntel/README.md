The CrowdStrike intelligence team tracks the activities of threat actor groups and advanced persistent threats (APTs) to understand as much as possible about their known aliases, targets, methods, and more.
## Configure Crowdstrike Falcon Intel Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| client_id | The Crowdstrike API client ID | True |
| feedReputation | Indicator reputation | False |
| feedReliability | Source reliability | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedIncremental | Incremental feed | False |
| feedFetchInterval | Feed fetch interval | False |
| limit | Number of top indicators to fetch from the feed | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| feedTags | Tags | False |
| client_secret | Crowdstrike API client secret | True |
| target_industries | Filter by threat actor's target industries. | False |
| target_countries | Filter by threat actor's target countries. | False |
| custom_filter | A custom filter by which to filter the indicators. If you pass the custom_filter argument it will override the custom\_filter parameter from the integration instance configuration.| False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### crowdstrike-falcon-intel-get-indicators
***
Gets indicators from Crowdstrike Falcon Intel Feed.


#### Base Command

`crowdstrike-falcon-intel-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Optional | 
| offset | The index of the first indicator to fetch. | Optional | 
| target_industries | A comma-separated list of the threat actor's target industries by which to filter the indicators. | Optional | 
| target_countries | A comma-separated list of the threat actor's target countries by which to filter the indicators. | Optional | 
| custom_filter | A custom filter by which to filter the indicators. If you pass the custom_filter argument it will override the custom_filter parameter from the integration instance configuration. For more information about custom filters and their structure, see the Crowdstrike Falcon documentation (https://falcon.crowdstrike.com/login/?next=%2Fsupport%2Fdocumentation%2F45%2Ffalcon-query-language-fql%3F). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output

