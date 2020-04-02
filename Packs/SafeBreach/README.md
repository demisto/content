SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness.  Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.

## Configure SafeBreach for Demisto Integration

1. Open the **Navigation bar** → … → **CLI Console**
2. Type **config accounts** to find out the account id
3. Use the id as the **accountId** parameter in Demisto configuration
4. Type: config apikeys to list existing API keys \
OR \
Add a new one by typing: **config apikeys add --name <key_name>**
5. Use the generated API token as **apiKey** parameter in Demisto configuration
6. Use your SafeBreach Management URL as the url parameter in Demisto configuration


## Configure SafeBreach on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SafeBreach v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | SafeBreach Managment URL | True |
| accountId | Account ID | True |
| apiKey | API Key | True |
| insightCategory | Insight Category | False |
| insightDataType | Insight Data Type | False |
| indicatorLimit | Indicators Limit | False |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedExpirationInterval |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### safebreach-get-insights
***
Get SafeBreach Insights for all security control categories


##### Base Command

`safebreach-get-insights`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightIds | Array of insight ids to fetch | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Name | String | Insight name representing the action required to be taken | 
| SafeBreach.Insight.Id | Number | Insight unique id number | 
| SafeBreach.Insight.DataType | String | Insight data type. Options: Hash, Domain, URI, Command, Port, Protocol | 
| SafeBreach.Insight.Category | String | Security control category name | 
| SafeBreach.Insight.LatestSimulation | Date | Time of the latest simulation from the insight | 
| SafeBreach.Insight.SimulationsCount | Number | Number of the related simulations | 
| SafeBreach.Insight.RiskImpact | Number | Risk impact of the insight on the environment total risk score | 
| SafeBreach.Insight.AffectedTargetsCount | Number | Number of the affected targets | 
| SafeBreach.Insight.SeverityScore | Number | Insight severity numeric value | 
| SafeBreach.Insight.Severity | String | Insight severity mapped to low/medium/high | 
| SafeBreach.Insight.RemediationDataCount | Number | Number of the remediation data points | 
| SafeBreach.Insight.RemediationDataType | String | Type of the remediation data | 
| SafeBreach.Insight.ThreatGroups | Unknown | Array of APT names that are mapped to the insight | 
| SafeBreach.Insight.NetworkDirection | String | Communication direction of Insight, relative to the target (inbound/outbound) | 
| SafeBreach.Insight.AttacksCount | Number | List of all insight related SafeBreach attack ids | 


##### Command Example
```!safebreach-get-insights insightIds=[5,9]```

##### Context Example
```
{
    "SafeBreach": {
        "Insight": [
            {
                "AffectedTargetsCount": 2,
                "AttacksCount": 1,
                "Category": "Web",
                "DataType": "Domain",
                "EarliestSimulation": "2020-03-23T18:45:13.920Z",
                "Id": 5,
                "LatestSimulation": "2020-03-23T18:45:14.942Z",
                "Name": "Blacklist malicious domains",
                "NetworkDirection": "outbound",
                "RemediationDataCount": "<null>",
                "RemediationDataType": "Domain",
                "RiskImpact": 0,
                "Severity": "Medium",
                "SeverityScore": 10,
                "SimulationsCount": 2,
                "ThreatGroups": [
                    "N/A"
                ]
            },
            {
                "AffectedTargetsCount": 3,
                "AttacksCount": 93,
                "Category": "Endpoint",
                "DataType": "Hash",
                "EarliestSimulation": "2020-03-23T09:37:36.409Z",
                "Id": 9,
                "LatestSimulation": "2020-03-23T19:05:55.393Z",
                "Name": "Prevent malware to be written to disk",
                "NetworkDirection": null,
                "RemediationDataCount": "<null>",
                "RemediationDataType": "Hash",
                "RiskImpact": 0.31,
                "Severity": "Medium",
                "SeverityScore": 10,
                "SimulationsCount": 219,
                "ThreatGroups": [
                    "APT28",
                    "Lazarus Group",
                    "APT12",
                    "APT32",
                    "APT34",
                    "APT37",
                    "Dark Caracal",
                    "FIN7",
                    "Leviathan",
                    "N/A",
                    "Naikon",
                    "OilRig",
                    "PittyTiger",
                    "Scarlet Mimic",
                    "Winnti Group",
                    "menuPass"
                ]
            }
        ]
    }
}
```

##### Human Readable Output
### SafeBreach Insights
|Id|Name|Category|Risk Impact|Severity|Affected Targets|Data Type|
|---|---|---|---|---|---|---|
| 5 | Blacklist malicious domains | Web | 0.0 | Medium | 2 | Domain |
| 9 | Prevent malware to be written to disk | Endpoint | 0.31 | Medium | 3 | Hash |


### safebreach-get-remediation-data
***
Get remediation data for a specific SafeBreach Insight


##### Base Command

`safebreach-get-remediation-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightId | The id of the insight to fetch remediation data for | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Id | Number | Insight unique id number | 
| SafeBreach.Insight.SHA256 | String | Malware SHA256 | 
| SafeBreach.Insight.Domain | String | Malicious domains  | 
| SafeBreach.Insight.IP | String | Malicious IPs | 
| SafeBreach.Insight.Port | Number | Ports used during the attack | 
| SafeBreach.Insight.Protocol | String | Protocols used during the attack | 
| SafeBreach.Insight.Proxy | String | Proxies used during the attack | 
| SafeBreach.Insight.URI | String | Malicious URIs | 
| SafeBreach.Insight.DropPath | String | Malware drop paths | 
| SafeBreach.Insight.User | String | Impersonated users running the attacks | 
| SafeBreach.Insight.Command | String | Attack executed commands | 
| SafeBreach.Insight.Registry | String | Attack read/changed registry paths | 
| SafeBreach.Insight.ClientHeader | String | Client HTTP headers used in attacks | 
| SafeBreach.Insight.ServerHeader | String | Server HTTP headers used in attacks | 
| URL.Data | String | Malicious domains, URLs or IPs | 
| File.SHA256 | String | Malicious SHA256 file hashes | 
| Process.CommandLine | String | Suspicious commands | 
| DBotScore.Indicator | String | Indicator value. Can be: IP, SHA1, MD5, SHA256, Email, or Url | 
| DBotScore.Type | String | Indicator type. Can be: ip, file, email, or url | 
| DBotScore.Vendor | String | SafeBreach. This is the vendor reporting the score of the indicator | 
| DBotScore.Score | Number | 3 (Bad). The score of the indicator | 


##### Command Example
```!safebreach-get-remediation-data insightId=5```

##### Context Example
```
{
    "DBotScore": {
        "Indicator": "srv.desk-top-app.info",
        "Score": 3,
        "Type": "url",
        "Vendor": "SafeBreach"
    },
    "SafeBreach": {
        "Insight": {
            "FQDNs/IPs": [
                "srv.desk-top-app.info"
            ],
            "Id": "5"
        }
    },
    "URL": {
        "Data": "srv.desk-top-app.info",
        "Malicious": {
            "Description": "SafeBreach Insights",
            "Vendor": "SafeBreach"
        }
    }
}
```

##### Human Readable Output
### Remediation Data
|FQDNs/IPs|
|---|
| srv.desk-top-app.info |


### safebreach-rerun-insight
***
Rerun a specific SafeBreach Insight related simulations in your environment.


##### Base Command

`safebreach-rerun-insight`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightId | The id of the insight to rerun | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safebreach.Insight.Id | Number | Insight unique id | 
| SafeBreach.Insight.Rerun.Name | String | Insight rerun test name | 
| SafeBreach.Insight.Rerun.Id | String | Id of the rerun insight test | 
| Safebreach.Insight.Rerun.AttacksCount | Number | Count of the attacks executed in the insight rerun test | 
| Safebreach.Test.Id | String | Id of the test | 
| Safebreach.Test.Name | String | Name of the test | 
| Safebreach.Test.AttacksCount | Number | Count of the attacks executed in the insight rerun test | 
| Safebreach.Test.Status | String | Test run status. For insight rerun, starts from PENDING. | 


##### Command Example
```!safebreach-rerun-insight insightId=5```

##### Context Example
```
{
    "SafeBreach": {
        "Insight": {
            "Id": "5",
            "Rerun": [
                {
                    "AttacksCount": 1,
                    "Id": "1584990372711.37",
                    "Name": "Insight (Demisto) - Blacklist malicious domains"
                }
            ]
        },
        "Test": {
            "AttacksCount": 1,
            "Id": "1584990372711.37",
            "Name": "Insight (Demisto) - Blacklist malicious domains",
            "Status": "Pending"
        }
    }
}
```

##### Human Readable Output
### Rerun SafeBreach Insight
|# Attacks|Insight Id|Name|Test Id|
|---|---|---|---|
| 1 | 5 | Insight (Demisto) - Blacklist malicious domains | 1584990372711.37 |


### safebreach-get-indicators
***
Fetches SafeBreach Insights and extracts indicators out of them, creating new or updating existing indicators.


##### Base Command

`safebreach-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limits the maximal number of generated indicators. Default - 1000. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!safebreach-get-indicators limit=10```

##### Context Example
```
{}
```

##### Human Readable Output
### Indicators:
|Value|Type|
|---|---|
| srv.desk-top-app.info | Domain |
| 0cb43a20e3f3295a8bf817317a4cb04dd5f1e0b07887f2964ddaf8b8e52698b8 | File SHA-256 |
| 1d02e38505684c59f7e72b690c39409c8b7a62c2fffe097febf857d99814470e | File SHA-256 |
| 00f4ba5f1db80f1db3324357f0806ff7f158904bdfc56d81fe156454cb6b9274 | File SHA-256 |
| 0779e3d2bbbd2939fcfc4af085bcfb1a20ea741c06e2716da7cd19edc4e14a5f | File SHA-256 |
| 188d570135048b5b4105d922d2ccceb230772eb7d0ca05a4e0aec206fd89aea6 | File SHA-256 |
| 0336565a75d6ff066acac7c5521dd39cf085048c01d2837d3528eec4c4d24ea4 | File SHA-256 |
| 27beaf7e4cbcc3974a40d6d9561628b2b30d1703230775b8af53818025a112f3 | File SHA-256 |
| 2ddc1eddbf795b620ab8582dc66d54cb5d257d0804a4fbf8e17d8fcf29dd5b52 | File SHA-256 |
| 0aa6eda0fef1c89274f0cac855d458870fdd8b5e6e9f587dba57cd7ab4c8950b | File SHA-256 |

