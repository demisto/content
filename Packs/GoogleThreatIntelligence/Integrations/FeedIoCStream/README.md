Use the Google Threat Intelligence IoC Stream Feed integration to fetch indicators from IoC Stream rules or rulesets.

## Configure Google Threat Intelligence IoC Stream Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Threat Intelligence IoC Stream Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| credentials | API Key. | True |
| filter | Exact name of the rule or ruleset you want to filter on. Leave empty to receive all. | False |
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedMinimumGTIScore | The minimum GTI score to import as part of the feed. | True |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |

4. Click **Test** to validate the Google Threat Intelligence API Key, and connection.

#### IoC Stream Feed info:
By default the IoC Stream Feed retrieve all indicators on [IoC Stream](https://www.virustotal.com/gui/ioc-notifications). You have the option to get files, domains, IP addresses or URLs only from LiveHunt, RetroHunt, Collections, Threat Actors, etc., using the filter parameter.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from Google Threat Intelligence IoC Stream.

##### Base Command

`gti-iocstream-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10 and max 40. | Optional |
| filter | Filter your IoC Stream (e.g., "source_type:hunting_ruleset" for LiveHunt, "source_type:retrohunt_job" for RetroHunt). Leave empty to receive all. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!gti-iocstream-get-indicators limit=1 filter=source_type:hunting_ruleset```


##### Human Readable Output
### Indicators from Google Threat Intelligence IoC Stream:
| Id | Detections | Origin | Sources | Gti Threat Score | Gti Severity | Gti Verdict | Malware Families | Threat Actors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| f221425286c9073cbb2168f73120b6... | 59/69 | hunting | \[hunting_ruleset\] YARA ruleset | 80 | SEVERITY_LOW | VERDICT_MALICIOUS | beacon | SWEED |
