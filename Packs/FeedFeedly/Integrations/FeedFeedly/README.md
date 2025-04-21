Ingest articles with indicators, entities and relationships from Feedly into XSOAR

## Configure Feedly in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| API key |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
|  |  | False |
|  |  | False |
| Stream ID | The stream id you want to fetch articles from. You can find it in Feedly by going to the stream, clicking on \`...\` &gt; \`Sharing\`, then \`Copy ID\` in the \`Feedly API Stream ID\` section. | True |
| Days to fetch for first run | Number of days to fetch articles from when running the integration for the first time | True |
| Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### feedly-get-indicators

***
Gets indicators from the feed.

#### Base Command

`feedly-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!feedly-get-indicators limit=100```
#### Human Readable Output

>### Indicators from Feedly Feed:
>|Value|
>|---|
>| A new sophisticated SkidMap variant targets unsecured Redis servers |
>| DarkWatchman RAT detection with Wazuh |
>| Microsoft Fixes 87 Flaws and 2 Actively Exploited 0Day Bugs |
>| Colorado Department of Higher Education Experiences Ransomware Atta... |
>| Skidmap |
>| DarkWatchman |
>| WScript.exe |
>| ROMCOM RAT |
>| SkidMap |
>| pupy |
>| pupy |
>| pupy |
>| reptile |
>| Melofee |
>| BPFDoor |
>| Syslogk |
>| Match Legitimate Name or Location |
>| Masquerade File Type |
>| Command and Scripting Interpreter |
>| Ingress Tool Transfer |
>| SSH |
>| SSH Authorized Keys |
>| Resource Hijacking |
>| Rootkit |
>| Windows Command Shell |
>| Modify Registry |
>| Fileless Storage |
>| Disable or Modify Tools |
>| Keylogging |
>| DLL Side-Loading |
>| Clipboard Data |
>| Command and Scripting Interpreter |
>| JavaScript |
>| Visual Basic |
>| Regsvr32 |
>| Hidden Window |
>| PowerShell |
>| Exploitation for Client Execution |
>| Mark-of-the-Web Bypass |
>| Endpoint Denial of Service |
>| Resource Hijacking |
>| Ingress Tool Transfer |
>| Match Legitimate Name or Location |
>| Masquerade File Type |
>| Command and Scripting Interpreter |
>| Malware |
>| Rootkit |
>| Port Knocking |
>| Fallback Channels |
>| SSH Authorized Keys |
>| RomCom |
>| Earth Berberoka |
>| Red Menshen |
