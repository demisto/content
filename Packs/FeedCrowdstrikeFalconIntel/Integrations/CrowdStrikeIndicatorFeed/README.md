CrowdStrike Falcon Intel Indicator Feed
## Configure CrowdStrike Indicator Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike Indicator Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Crowdstrike API client ID |  | True |
    | Crowdstrike API client secret |  | True |
    | Include deleted indicators |  | False |
    | Type | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File md5", "File sha256", "IP", "Registry Key", and "URL". The default is "ALL". | False |
    | Max. indicators per fetch |  | False |
    | Malicious confidence | Malicious confidence level of the indicator. | False |
    | Filter | Advanced: FQL query. For more information visit CrowdStrike documentation. | False |
    | Generic phrase match | Generic phrase match search across all indicators fields. | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### crowdstrike-indicators-list
***
Gets indicators from Crowdstrike Falcon Intel Feed.


#### Base Command

`crowdstrike-indicators-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional | 
| offset | The index of the first indicator to fetch. | Optional | 
| include_deleted | Include deleted indicators. Possible values are: true, false. | Optional | 
| type | Indicator type. Possible values are: ALL, Account, Domain, Email, File MD5, File SHA-256, IP, Registry Key, URL. Default is ALL. | Optional | 
| malicious_confidence | Malicious confidence level of the indicator. Possible values are: high, medium, low, unverified. | Optional | 
| filter | FQL query, indicators filter. | Optional | 
| generic_phrase_match | Generic phrase match search across all indicators fields. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrikeFalconIntel.Indicators.id | String | Indicator ID. | 
| CrowdStrikeFalconIntel.Indicators.value | String | Indicator value. | 
| CrowdStrikeFalconIntel.Indicators.type | String | Indicator type. | 
| CrowdStrikeFalconIntel.Indicators.deleted | Boolean | If the indicator deleted, deleted set true. | 
| CrowdStrikeFalconIntel.Indicators.published_date | Date | Indicator published date. | 
| CrowdStrikeFalconIntel.Indicators.last_updated | Date | Indicator last updated date. | 
| CrowdStrikeFalconIntel.Indicators.reports | Unknown | Indicator reports. | 
| CrowdStrikeFalconIntel.Indicators.actors | Unknown | Actors related to indicator. | 
| CrowdStrikeFalconIntel.Indicators.malware_families | Unknown | Indicator malware families. | 
| CrowdStrikeFalconIntel.Indicators.kill_chains | Unknown | Indicator kill chains. | 
| CrowdStrikeFalconIntel.Indicators.malicious_confidence | String | Indicator malicious confidence. | 
| CrowdStrikeFalconIntel.Indicators.labels | Unknown | Indicator labels. | 
| CrowdStrikeFalconIntel.Indicators.targets | Unknown | Targets of indicator. | 
| CrowdStrikeFalconIntel.Indicators.threat_types | Unknown | Indicator threat types. | 
| CrowdStrikeFalconIntel.Indicators.vulnerabilities | Unknown | Indicator vulnerabilities. | 
| CrowdStrikeFalconIntel.Indicators.rawJSON | Unknown | Raw response. | 


#### Command Example
```!crowdstrike-indicators-list type=IP include_deleted=true malicious_confidence=high limit=3```

#### Context Example
```json
{
    "CrowdStrikeFalconIntel": {
        "Indicators": [
            {
                "actors": [],
                "deleted": false,
                "domain_types": [],
                "id": "ip_address_1.1.1.1",
                "ip_address_types": [],
                "kill_chains": [
                    "C2"
                ],
                "labels": [
                    "MaliciousConfidence/High",
                    "KillChain/C2",
                    "Malware/njRAT",
                    "ThreatType/Commodity"
                ],
                "last_updated": "1970-01-19T14:43:36.000Z",
                "malicious_confidence": "high",
                "malware_families": [
                    "njRAT"
                ],
                "published_date": "1970-01-18T06:26:28.000Z",
                "reports": [],
                "targets": [],
                "threat_types": [
                    "Commodity"
                ],
                "type": "IP",
                "value": "1.1.1.1",
                "vulnerabilities": []
            },
            {
                "actors": [
                    "PIRATEPANDA"
                ],
                "deleted": false,
                "domain_types": [],
                "id": "ip_address_2.2.2.2",
                "ip_address_types": [],
                "kill_chains": [
                    "C2"
                ],
                "labels": [
                    "MaliciousConfidence/High",
                    "KillChain/C2",
                    "ThreatType/Targeted",
                    "Actor/PIRATEPANDA",
                    "CSD/CSA-201604",
                    "Malware/PoisonIvy"
                ],
                "last_updated": "1970-01-19T14:44:04.000Z",
                "malicious_confidence": "high",
                "malware_families": [
                    "PoisonIvy"
                ],
                "published_date": "1970-01-19T14:39:42.000Z",
                "reports": [
                    "CSA-201604"
                ],
                "targets": [],
                "threat_types": [
                    "Targeted"
                ],
                "type": "IP",
                "value": "2.2.2.2",
                "vulnerabilities": []
            },
            {
                "actors": [],
                "deleted": false,
                "domain_types": [],
                "id": "ip_address_1.2.3.4",
                "ip_address_types": [],
                "kill_chains": [
                    "C2"
                ],
                "labels": [
                    "KillChain/C2",
                    "Malware/njRAT",
                    "ThreatType/Commodity",
                    "MaliciousConfidence/High"
                ],
                "last_updated": "1970-01-19T14:44:33.000Z",
                "malicious_confidence": "high",
                "malware_families": [
                    "njRAT"
                ],
                "published_date": "1970-01-18T04:57:02.000Z",
                "reports": [],
                "targets": [],
                "threat_types": [
                    "Commodity"
                ],
                "type": "IP",
                "value": "1.2.3.4",
                "vulnerabilities": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators from CrowdStrike Falcon Intel
>|Type|Value|Id|
>|---|---|---|
>| IP | 1.1.1.1 | ip_address_1.1.1.1 |
>| IP | 2.2.2.2 | ip_address_2.2.2.2 |
>| IP | 1.2.3.4 | ip_address_1.2.3.4 |


### crowdstrike-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`crowdstrike-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!crowdstrike-reset-fetch-indicators```

#### Human Readable Output

>Fetch history deleted successfully
