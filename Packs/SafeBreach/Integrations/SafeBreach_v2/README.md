SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness.  Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.
This integration was integrated and tested with version xx of SafeBreach v2

## Configure SafeBreach for Cortex XSOAR Integration

1. Open the **Navigation bar** → … → **CLI Console**
2. Type **config accounts** to find out the account id
3. Use the id as the **accountId** parameter in Cortex XSOAR configuration
4. Type **config apikeys** to list existing API keys \
OR \
Add a new one by typing: **config apikeys add --name <key_name>**
5. Use the generated API token as **apiKey** parameter in Cortex XSOAR configuration
6. Use your SafeBreach Management URL as the **url** parameter in Cortex XSOAR configuration

## Configure SafeBreach on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SafeBreach v2 Phase 2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| SafeBreach Managment URL | For example, https://yourorg.safebreach.com | True |
| Account ID | Obtained with "config accounts" SafeBreach command | True |
| API Key | Generated with "config apikeys add" SafeBreach command | True |
| Insight Category | Network Access,Network Inspection,Endpoint,Email,Web,Data Leak | False |
| Insight Data Type | Hash,Domain,URI,Command,Port,Protocol | False |
| Indicators Limit | Amount of indicators to generate. Default = 1000 | False |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| behavioralReputation | Behavioral Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedExpirationInterval |  | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### safebreach-get-insights
***
Gets SafeBreach Insights for all security control categories.


#### Base Command

`safebreach-get-insights`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightIds | Array of insight IDs to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Name | String | Insight name representing the action required to be taken. | 
| SafeBreach.Insight.Id | Number | Insight unique ID number. | 
| SafeBreach.Insight.DataType | String | Insight data type. Options are Hash, Domain, URI, Command, Port, or Protocol. | 
| SafeBreach.Insight.Category | String | Security control category name. | 
| SafeBreach.Insight.LatestSimulation | Date | Time of the latest simulation from the insight. | 
| SafeBreach.Insight.SimulationsCount | Number | Number of the related simulations. | 
| SafeBreach.Insight.RiskImpact | Number | Risk impact of the insight on the environment total risk score. | 
| SafeBreach.Insight.AffectedTargetsCount | Number | Number of affected targets. | 
| SafeBreach.Insight.SeverityScore | Number | Insight severity numeric value | 
| SafeBreach.Insight.Severity | String | Insight severity mapped to low/medium/high. | 
| SafeBreach.Insight.RemediationDataCount | Number | Number of the remediation data points. | 
| SafeBreach.Insight.RemediationDataType | String | Type of the remediation data. | 
| SafeBreach.Insight.ThreatGroups | Array | Array of APT names that are mapped to the insight. | 
| SafeBreach.Insight.NetworkDirection | String | Communication direction of Insight, relative to the target \(inbound/outbound\). | 
| SafeBreach.Insight.AttacksCount | Number | List of all insight related SafeBreach attack IDs. | 
| SafeBreach.Insight.AffectedTargets | Array | List of the affected targets including name, IP and number of the remediation points | 
| SafeBreach.Insight.RemediationAction | String | Description of an action to take for the remediation | 
| SafeBreach.Insight.ResultsLink | String | Link to the SafeBreach platform Results page filtered for the relevant simulation results | 
| SafeBreach.Insight.AttackIds | Array | SafeBreach Attack Ids | 


##### Command Example
```!safebreach-get-insights insightIds=[5,9]```

##### Context Example
```
{
    "SafeBreach": {
        "Insight": [
            {
                "AffectedTargetsCount": 2,
                "AttacksCount": 36,
                "Category": "Web",
                "DataType": "Domain",
                "EarliestSimulation": "2020-04-07T14:34:15.807Z",
                "Id": 5,
                "LatestSimulation": "2020-04-07T15:54:01.256Z",
                "Name": "Blacklist malicious domains",
                "NetworkDirection": "outbound",
                "RemediationDataCount": 71,
                "RemediationDataType": "FQDN/IP",
                "RiskImpact": 0.42,
                "Severity": "Medium",
                "SeverityScore": 10,
                "SimulationsCount": 399,
                "ThreatGroups": [
                    "APT32",
                    "APT37",
                    "BRONZE BUTLER",
                    "Lazarus Group",
                    "OilRig",
                    "PLATINUM",
                    "APT18",
                    "APT19",
                    "APT29",
                    "APT3",
                    "APT33",
                    "Dragonfly 2.0",
                    "FIN7",
                    "FIN8",
                    "Magic Hound",
                    "Night Dragon",
                    "TEMP.Veles",
                    "Threat Group-3390",
                    "Tropic Trooper",
                    "N/A"
                ]
            },
            {
                "AffectedTargetsCount": 3,
                "AttacksCount": 97,
                "Category": "Endpoint",
                "DataType": "Hash",
                "EarliestSimulation": "2020-04-06T11:17:04.253Z",
                "Id": 9,
                "LatestSimulation": "2020-04-06T12:02:09.109Z",
                "Name": "Prevent malware to be written to disk",
                "NetworkDirection": null,
                "RemediationDataCount": 97,
                "RemediationDataType": "Attack",
                "RiskImpact": 0.36,
                "Severity": "Medium",
                "SeverityScore": 10,
                "SimulationsCount": 229,
                "ThreatGroups": [
                    "APT28",
                    "Lazarus Group",
                    "APT32",
                    "APT34",
                    "APT37",
                    "BRONZE BUTLER",
                    "Dark Caracal",
                    "FIN7",
                    "Leviathan",
                    "N/A",
                    "Naikon",
                    "OilRig",
                    "PittyTiger",
                    "Scarlet Mimic",
                    "Turla",
                    "Winnti Group",
                    "menuPass"
                ]
            }
        ]
    }
}
```



### safebreach-get-remediation-data
***
Gets remediation data for a specific SafeBreach Insight.


#### Base Command

`safebreach-get-remediation-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightId | The ID of the insight for which to fetch remediation data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Id | Number | Insight unique ID number. | 
| SafeBreach.Insight.SHA256 | String | Malware SHA256 hash. | 
| SafeBreach.Insight.Domain | String | Malicious domains. | 
| SafeBreach.Insight.IP | String | Malicious IP addresses. | 
| SafeBreach.Insight.Port | Number | Ports used during the attack. | 
| SafeBreach.Insight.Protocol | String | Protocols used during the attack. | 
| SafeBreach.Insight.Proxy | String | Proxies used during the attack. | 
| SafeBreach.Insight.URI | String | Malicious URIs. | 
| SafeBreach.Insight.DropPath | String | Malware drop paths. | 
| SafeBreach.Insight.User | String | Impersonated users running the attacks. | 
| SafeBreach.Insight.Command | String | Attack executed commands. | 
| SafeBreach.Insight.Registry | String | Attack read/changed registry paths. | 
| SafeBreach.Insight.ClientHeader | String | Client HTTP headers used in the attacks. | 
| SafeBreach.Insight.ServerHeader | String | Server HTTP headers used in the attacks. | 
| URL.Data | String | Malicious domains, URLs, or IP addresses. | 
| File.SHA256 | String | Malicious SHA256 file hashes. | 
| Process.CommandLine | String | Suspicious commands. | 
| DBotScore.Indicator | String | Indicator value. Options are IP, SHA1, MD5, SHA256, Email, or Url. | 
| DBotScore.Type | String | Indicator type. Options are ip, file, email, or url. | 
| DBotScore.Vendor | String | SafeBreach. This is the vendor reporting the score of the indicator. | 
| DBotScore.Score | Number | 3 \(Bad\). The score of the indicator. | 
| SafeBreach.Insight.RemediationData.Splunk | String | Remediation data in a form of a Splunk query | 


##### Command Example
```!safebreach-get-remediation-data insightId=5```

##### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "codeluxsoftware.com.",
            "Score": 3,
            "Type": "url",
            "Vendor": "SafeBreach"
        },
        {
            "Indicator": "866448.com.",
            "Score": 3,
            "Type": "url",
            "Vendor": "SafeBreach"
        },
        {
            "Indicator": "a1.weilwords2.com.br.",
            "Score": 3,
            "Type": "url",
            "Vendor": "SafeBreach"
        }
    ],
    "Domain": [
        {
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            },
            "Name": "codeluxsoftware.com."
        },
        {
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            },
            "Name": "866448.com."
        },
        {
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            },
            "Name": "a1.weilwords2.com.br."
        }
    ],
    "SafeBreach": {
        "Insight": {
            "FQDN/IP": [
                "codeluxsoftware.com.",
                "866448.com.",
                "a1.weilwords2.com.br."
            ],
            "Id": "5"
        }
    },
    "URL": [
        {
            "Data": "codeluxsoftware.com.",
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            }
        },
        {
            "Data": "866448.com.",
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            }
        },
        {
            "Data": "a1.weilwords2.com.br.",
            "Malicious": {
                "Description": "SafeBreach Insights - (5)Blacklist malicious domains",
                "Vendor": "SafeBreach"
            }
        },
    ]
}
```



### safebreach-rerun-insight
***
Reruns a specific SafeBreach Insight related simulations in your environment.


#### Base Command

`safebreach-rerun-insight`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insightIds | The IDs of the insight to rerun. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Id | Number | Insight unique ID. | 
| SafeBreach.Insight.Rerun.Name | String | Insight rerun test name. | 
| SafeBreach.Insight.Rerun.Id | String | ID of the rerun insight test. | 
| SafeBreach.Insight.Rerun.AttacksCount | Number | Count of the attacks executed in the insight rerun test. | 
| SafeBreach.Test.Id | String | ID of the test. | 
| SafeBreach.Test.Name | String | Name of the test. | 
| SafeBreach.Test.AttacksCount | Number | The number of attacks executed in the insight rerun test. | 
| SafeBreach.Test.Status | String | Test run status. For insight rerun, starts from PENDING. | 
| SafeBreach.Test.ScheduledTime | Date | Time when the test was triggered. | 


##### Command Example
```!safebreach-rerun-insight insightIds=5```

##### Context Example
```
{
    "SafeBreach": {
        "Insight": {
            "Id": "5",
            "Rerun": [
                {
                    "AttacksCount": 36,
                    "Id": "1586684450523.75",
                    "Name": "Insight (Demisto) - Blacklist malicious domains",
                    "ScheduledTime": "2020-04-12T09:40:50.533398"
                }
            ]
        },
        "Test": {
            "AttacksCount": 36,
            "Id": "1586684450523.75",
            "Name": "Insight (Demisto) - Blacklist malicious domains",
            "ScheduledTime": "2020-04-12T09:40:50.533414",
            "Status": "Pending"
        }
    }
}
```

##### Human Readable Output
### Rerun SafeBreach Insight
|# Attacks|Insight Id|Name|Test Id|
|---|---|---|---|
| 36 | 5 | Insight (Demisto) - Blacklist malicious domains | 1586684450523.75 |


### safebreach-get-test-status
***
Gets the status of a SafeBreach test for tracking progress of a run.


#### Base Command

`safebreach-get-test-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| testId | The ID of the test to track. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Test.Id | String | ID of the test. | 
| SafeBreach.Test.Name | String | Name of the test. | 
| SafeBreach.Test.Status | String | Test run status. Options are PENDING, RUNNING, CANCELED, or COMPLETED. | 
| SafeBreach.Test.StartTime | Date | Starting time of the test. | 
| SafeBreach.Test.EndTime | Date | Ending time of the test. | 
| SafeBreach.Test.TotalSimulationNumber | Number | Number of simulations for the test. | 


#### Command Example
``` ```

#### Human Readable Output



### safebreach-get-simulation
***
Get SafeBreach simulation


#### Base Command

`safebreach-get-simulation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulationId | The ID of the simulation. By default, taken from the incident. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.Id | String | ID of the simulation result. | 
| SafeBreach.Simulation.FinalStatus | String | Simulation final status. Options are Missed, Detected, Stopped, Prevented, or Inconsistent. | 
| SafeBreach.Simulation.Result | String | Indicates whether the simulation was blocked. | 
| SafeBreach.Simulation.DetectedAction | String | Indicates the overall detected action taken by security controls. | 
| SafeBreach.Simulation.SimulationRunId | Number | The unique simulation run ID \(changes between simulation runs\). | 
| SafeBreach.Simulation.Time | Datetime | Latest simulation run time. | 
| SafeBreach.Simulation.LastChangeTime | Datetime | Time when the simulation result was changed. | 
| SafeBreach.Simulation.Labels | Array | Array of labels applied on the simulation. | 
| SafeBreach.Simulation.Attack.Id | String | ID of the simulated attack. | 
| SafeBreach.Simulation.Attack.Name | String | Name of the simulated attack. | 
| SafeBreach.Simulation.Attack.Description | String | Description of the attack flow. | 
| SafeBreach.Simulation.Attack.Phase | String | The phase of the attack. Option are Infiltration, Exfiltration ,Lateral Movement, or Host Level. | 
| SafeBreach.Simulation.Attack.Type | String | The type of the attack. For example, Real C2 Communication, Malware Transfer, or Malware Write to Disk. | 
| SafeBreach.Simulation.Attack.SecurityControl | String | Related security control category. | 
| SafeBreach.Simulation.Attack.IndicatorBased | Bool | True if this attack is based on an indicator. False if this is behavioral non\-indicator based. | 
| SafeBreach.Simulation.Attacker.Name | String | Name of the attacker simulator. | 
| SafeBreach.Simulation.Attacker.OS | String | OS of the attacker simulator. | 
| SafeBreach.Simulation.Attacker.InternalIp | String | Internal IP address of the attacker simulator. | 
| SafeBreach.Simulation.Attacker.ExternalIp | String | External IP address of the attacker simulator. | 
| SafeBreach.Simulation.Attacker.SimulationDetails | JSON | Simulation run detailed logs from the attacker simulator. | 
| SafeBreach.Simulation.Target.Name | String | Name of the target simulator. | 
| SafeBreach.Simulation.Target.OS | String | OS of the target simulator. | 
| SafeBreach.Simulation.Target.InternalIp | String | Internal IP address of the target simulator. | 
| SafeBreach.Simulation.Target.ExternalIp | String | External IP address of the target simulator. | 
| SafeBreach.Simulation.Target.SimulationDetails | JSON | Simulation run detailed logs from the target simulator. | 
| SafeBreach.Simulation.Network.Direction | String | Attack network direction relative to the target \- inbound/outbound. | 
| SafeBreach.Simulation.Network.SourceIp | String | The IP address that initiated the network communication. | 
| SafeBreach.Simulation.Network.DestinationIp | String | The IP address that received the network communication. | 
| SafeBreach.Simulation.Network.SourcePort | String | The source port of the network communication. | 
| SafeBreach.Simulation.Network.DestinationPort | String | The destination port of the network communication. | 
| SafeBreach.Simulation.Network.Protocol | String | The top\-level protocol of the network communication. | 
| SafeBreach.Simulation.Network.Proxy | String | The proxy name used in the network communication. | 
| SafeBreach.Simulation.Classifications.MITRETechniques | Array | List of attack related MITRE techniques. | 
| SafeBreach.Simulation.Classifications.MITREGroups | Array | List of attack related MITRE threat groups. | 
| SafeBreach.Simulation.Classifications.MITRESoftware | Array | List of attack related MITRE software and tools. | 
| SafeBreach.Simulation.Parameters | JSON | Parameters of the simulation. | 


#### Command Example
``` ```

#### Human Readable Output



### safebreach-rerun-simulation
***
Reruns a specific SafeBreach simulation in your environment.


#### Base Command

`safebreach-rerun-simulation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulationId | The ID of the simulation to rerun. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.Id | Number | Simulation unique ID. | 
| SafeBreach.Simulation.Rerun.Name | String | Simulation rerun test name. | 
| SafeBreach.Simulation.Rerun.Id | String | ID of the rerun test. | 
| SafeBreach.Simulation.Rerun.ScheduledTime | Datetime | Time when the rerun was triggered. | 
| SafeBreach.Test.Id | String | ID of the test. | 
| SafeBreach.Test.Name | String | Name of the test. | 
| SafeBreach.Test.AttacksCount | Number | The number of the attacks executed in the insight rerun test. | 
| SafeBreach.Test.Status | String | Test run status. For insight rerun \- “PENDING” | 
| SafeBreach.Test.ScheduledTime | Datetime | Time when the test was triggered. | 


#### Command Example
``` ```

#### Human Readable Output


