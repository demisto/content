CrowdStrike Falcon Intel Indicator Feed

## Configure CrowdStrike Indicator Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| CrowdStrike Base URL |  | True |
| CrowdStrike API Client ID | For non 6.1 - enter your CrowdStrike API Client Secret in the password field. | True |
| Type | The indicator types to fetch. Out-of-the-box indicator types supported in XSOAR are: "Account", "Domain", "Email", "File MD5", "File SHA256", "IP", "Registry Key", and "URL". The default is "ALL". | False |
| First fetch time | The time range to consider for the initial data fetch. Leave empty to fetch from the first available indicator. | False |
| Max. indicators per fetch | Maximum number of indicators per fetch. Value should be between 1 - 10000. A large value may result in a timeout. | False |
| Malicious confidence | Malicious confidence level to filter by. | False |
| Include deleted indicators |  | False |
| Filter | Advanced: FQL query. For more information visit the CrowdStrike documentation. For example: published_date:>"now-3d" can be used to only pull indicators published in the last 3 days. | False |
| Generic phrase match | Generic phrase match search across all indicator fields. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Indicator Expiration Method | The feed's expiration method. | False |
| Feed Fetch Interval | The interval after which the feed expires. | False |
| Tags | Supports CSV values. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    

**Note**: To change the fetch start time , use the `crowdstrike-reset-fetch-indicators` command after setting the desired time in `First Fetch Time` parameter.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### crowdstrike-indicators-list
***
Gets indicators from the CrowdStrike Falcon Intel Feed.

#### Base Command

`crowdstrike-indicators-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional | 
| offset | The index of the first indicator to fetch. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrikeFalconIntel.Indicators.id | String | Indicator ID. | 
| CrowdStrikeFalconIntel.Indicators.value | String | Indicator value. | 
| CrowdStrikeFalconIntel.Indicators.type | String | Indicator type. | 
| CrowdStrikeFalconIntel.Indicators.fields.reports | Unknown | Indicator reports. | 
| CrowdStrikeFalconIntel.Indicators.fields.actors | Unknown | Actors related to the indicator. | 
| CrowdStrikeFalconIntel.Indicators.fields.malwarefamily | Unknown | Indicator malware families. | 
| CrowdStrikeFalconIntel.Indicators.fields.stixkillchainphases | Unknown | Indicator kill chains. | 
| CrowdStrikeFalconIntel.Indicators.fields.maliciousconfidence | String | Indicator malicious confidence. | 
| CrowdStrikeFalconIntel.Indicators.fields.tags | Unknown | Indicator labels. | 
| CrowdStrikeFalconIntel.Indicators.fields.targets | Unknown | Targets of the indicator. | 
| CrowdStrikeFalconIntel.Indicators.fields.threattypes | Unknown | Indicator threat types. | 
| CrowdStrikeFalconIntel.Indicators.fields.vulnerabilities | Unknown | Indicator vulnerabilities. | 
| CrowdStrikeFalconIntel.Indicators.fields.ipaddress | Unknown | Indicator related IP address. | 
| CrowdStrikeFalconIntel.Indicators.fields.domainname | Unknown | Indicator related domains. | 
| CrowdStrikeFalconIntel.Indicators.fields.updateddate | Date | Indicator update date. | 
| CrowdStrikeFalconIntel.Indicators.fields.creationdate | Unknown | Indicator creation date. | 
| CrowdStrikeFalconIntel.Indicators.rawJSON | Unknown | Raw response. | 

#### Command Example
```!crowdstrike-indicators-list limit=3```

#### Context Example
```json
{
  "CrowdStrikeFalconIntel": {
    "Indicators": [
      {
        "fields": {
          "actor": [],
          "creationdate": 1600080520,
          "domainname": [],
          "ipaddress": [],
          "confidence": "low",
          "malwarefamily": [
            "Remcos"
          ],
          "reports": [],
          "stixkillchainphases": [
            "C2"
          ],
          "threattypes": [
            {
              "threatcategory": "Criminal"
            }
          ],
          "tags": [
            "MaliciousConfidence/Low",
            "KillChain/C2",
            "ThreatType/Commodity",
            "ThreatType/Criminal",
            "ThreatType/CredentialHarvesting",
            "Malware/Remcos"
          ],
          "targets": [],
          "trafficlightprotocol": "AMBER",
          "updateddate": 1608207378,
          "vulnerabilities": []
        },
        "id": "ip_address_1.1.1.1",
        "rawJSON": {
          "_marker": "1608207378159fc77935511a2f0c9541511bd936f8",
          "actors": [],
          "deleted": false,
          "domain_types": [],
          "id": "ip_address_1.1.1.1",
          "indicator": "1.1.1.1",
          "ip_address_types": [],
          "kill_chains": [
            "C2"
          ],
          "labels": [
            {
              "created_on": 1600080520,
              "last_valid_on": 1608207377,
              "name": "MaliciousConfidence/Low"
            },
            {
              "created_on": 1600080520,
              "last_valid_on": 1608207377,
              "name": "KillChain/C2"
            }
          ],
          "last_updated": 1608207378,
          "malicious_confidence": "low",
          "malware_families": [
            "Remcos"
          ],
          "published_date": 1600080520,
          "relations": [
            {
              "created_date": 1608207377,
              "id": "hash_sha256_9bb12d611cb19e84f2f22791cb86a43841e95020b1e113469e5cad95b97a8d42",
              "indicator": "9bb12d611cb19e84f2f22791cb86a43841e95020b1e113469e5cad95b97a8d42",
              "last_valid_date": 1608207377,
              "type": "hash_sha256"
            },
            {
              "created_date": 1608207377,
              "id": "hash_sha256_58a3e65de35d8da1f7955680e07a82ede43a1e677e0abc200923b484a7615494",
              "indicator": "58a3e65de35d8da1f7955680e07a82ede43a1e677e0abc200923b484a7615494",
              "last_valid_date": 1608207377,
              "type": "hash_sha256"
            }
          ],
          "reports": [],
          "targets": [],
          "threat_types": [
            "Criminal"
          ],
          "type": "ip_address",
          "vulnerabilities": []
        },
        "type": "IP",
        "value": "1.1.1.1"
      },
      {
        "fields": {
          "actor": [],
          "creationdate": 1608208087,
          "domainname": [],
          "ipaddress": [],
          "confidence": "low",
          "malwarefamily": [
            "Remcos"
          ],
          "reports": [],
          "stixkillchainphases": [
            "C2"
          ],
          "tags": [
            "MaliciousConfidence/Low",
            "KillChain/C2",
            "Malware/Remcos",
            "ThreatType/Commodity",
            "ThreatType/Criminal",
            "ThreatType/CredentialHarvesting"
          ],
          "threattypes": [
            {
              "threatcategory": "Criminal"
            }
          ],
          "targets": [],
          "trafficlightprotocol": "AMBER",
          "updateddate": 1608208109,
          "vulnerabilities": []
        },
        "id": "ip_address_2.2.2.2",
        "rawJSON": {
          "_marker": "16082081092644654ac0f7738b7086d25532d38ec1",
          "actors": [],
          "deleted": false,
          "domain_types": [],
          "id": "ip_address_2.2.2.2",
          "indicator": "2.2.2.2",
          "ip_address_types": [],
          "kill_chains": [
            "C2"
          ],
          "labels": [
            {
              "created_on": 1608208087,
              "last_valid_on": 1608208108,
              "name": "MaliciousConfidence/Low"
            },
            {
              "created_on": 1608208087,
              "last_valid_on": 1608208108,
              "name": "KillChain/C2"
            }
          ],
          "last_updated": 1608208109,
          "malicious_confidence": "low",
          "malware_families": [
            "Remcos"
          ],
          "published_date": 1608208087,
          "relations": [
            {
              "created_date": 1608208090,
              "id": "hash_sha256_b90713f3b31f29ceb64355b3c016aa0a74e1ce90dca5570db04aff27e12b343c",
              "indicator": "b90713f3b31f29ceb64355b3c016aa0a74e1ce90dca5570db04aff27e12b343c",
              "last_valid_date": 1608208090,
              "type": "hash_sha256"
            },
            {
              "created_date": 1483468884,
              "id": "domain_holmann02.ddns.net",
              "indicator": "holmann02.ddns.net",
              "last_valid_date": 1483468884,
              "type": "domain"
            }
          ],
          "reports": [],
          "targets": [],
          "threat_types": [
            "Criminal"
          ],
          "type": "ip_address",
          "vulnerabilities": []
        },
        "type": "IP",
        "value": "1.2.3.4"
      },
      {
        "fields": {
          "actor": [
            "MUMMYSPIDER"
          ],
          "creationdate": 1592473928,
          "domainname": [],
          "ipaddress": [],
          "confidence": "low",
          "malwarefamily": [],
          "reports": [],
          "stixkillchainphases": [
            "C2"
          ],
          "threattypes": [],
          "tags": [
            "KillChain/C2",
            "MaliciousConfidence/Low",
            "Actor/MUMMYSPIDER"
          ],
          "targets": [],
          "trafficlightprotocol": "AMBER",
          "updateddate": 1608208626,
          "vulnerabilities": []
        },
        "id": "ip_address_1.2.3.4",
        "rawJSON": {
          "_marker": "1608208626d02e40678e554f71fd6c3c33cc71c5c0",
          "actors": [
            "MUMMYSPIDER"
          ],
          "deleted": false,
          "domain_types": [],
          "id": "ip_address_1.2.3.4",
          "indicator": "1.2.3.4",
          "ip_address_types": [],
          "kill_chains": [
            "C2"
          ],
          "labels": [
            {
              "created_on": 1592473928,
              "last_valid_on": 1592473930,
              "name": "KillChain/C2"
            },
            {
              "created_on": 1592473928,
              "last_valid_on": 1592473930,
              "name": "MaliciousConfidence/Low"
            },
            {
              "created_on": 1592473930,
              "last_valid_on": 1592473930,
              "name": "Actor/MUMMYSPIDER"
            }
          ],
          "last_updated": 1608208626,
          "malicious_confidence": "low",
          "malware_families": [],
          "published_date": 1592473928,
          "relations": [
            {
              "created_date": 1597858281,
              "id": "url_http://1.1.1.1:80",
              "indicator": "http://1.1.1.1:80",
              "last_valid_date": 1597858281,
              "type": "url"
            },
            {
              "created_date": 1592473931,
              "id": "hash_md5_6d795170965336a9006f059dd444fc8f",
              "indicator": "6d795170965336a9006f059dd444fc8f",
              "last_valid_date": 1592473931,
              "type": "hash_md5"
            }
          ],
          "reports": [],
          "targets": [],
          "threat_types": [],
          "type": "ip_address",
          "vulnerabilities": []
        },
        "type": "IP",
        "value": "1.2.3.4"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Indicators from CrowdStrike Falcon Intel
>|Type|Value|Id|
>|---|---|---|
>| IP | 1.1.1.1 | ip_address_1.1.1.1 |
>| IP | 2.2.2.2 | ip_address_2.2.2.2 |
>| IP | 1.2.3.4 | ip_address_1.2.3.4 |

### crowdstrike-reset-fetch-indicators
***
Resets the retrieving start time according to the `First Fetch Time` parameter, WARNING: This command will reset your fetch history.

#### Base Command

`crowdstrike-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!crowdstrike-reset-fetch-indicators```

#### Human Readable Output

> Fetch history deleted successfully