Use the VirusTotal Livehunt Feed integration to fetch indicators from Livehunt rules or rulesets.

## Configure VirusTotal Livehunt Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| feed | The fetch indicators. | False |
| api_key | API Key. | True |
| filter | Exact name of the rule or ruleset you want to filter on. Leave empty to receive all. | False |
| feedReputation | The indicator reputation. | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |


#### Livehunt Feed info:
By default the Livehunt feed retrieve indicators based on all active rulesets in [livehunt](https://www.virustotal.com/gui/hunting/notifications), you have the option to get indicators only from one rule or ruleset using the filter parameter.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from VirusTotal Livehunt.

##### Base Command

`vt-livehunt-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10 and max 40. | Optional |
| filter | Exact name of the rule or ruleset you want to filter on. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!vt-livehunt-get-indicators limit=1 filter=WannaCry_Ransomware```


##### Human Readable Output
### Indicators from VirusTotal Livehunt:
| Sha256 | Detections |Filetype | Rulesetname | Rulename |
|---|---|---|---|---|
f221425286c9073cbb2168f73120b6...|59/69|Win32 EXE|Wannacry Ransomware|WannaCry_Ransomware_Gen|


## Demo Video
<iframe width="560" height="315" src="https://www.youtube.com/watch?v=Qv89-iS9HVY" frameborder="0"
allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture"
allowfullscreen="true"></iframe>