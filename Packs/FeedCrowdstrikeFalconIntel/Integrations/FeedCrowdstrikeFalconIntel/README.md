CrowdStrike intelligence team are tracking the activities of threat actor groups and  advanced persistent threats (APTs) to understand as much as possible about their known aliases, targets, methods, and more.
## Configure Crowdstrike Falcon Intel Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Crowdstrike Falcon Intel Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | Fetch indicators | False |
| client_id | The Crowdstrike api client\_id | True |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedIncremental | Incremental Feed | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| feedTags | Tags | False |
| client_secret | The Crowdstrike api client\_secret | True |
| target_industries | Filter by actor's target industries. | False |
| target_countries | Filter by actor's target countries. | False |
| custom_filter | Filter by custom filter, If the user uses custom\_filter other filters will not work | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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
| target_industries | Filter by actor's target industries, List divided by commas. | Optional | 
| target_countries | Filter by actor's target countries, List divided by commas. | Optional | 
| custom_filter | Filter by custom filter, If the user uses custom_filter other filters will not work | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


