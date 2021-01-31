SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness.  Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.


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
2. Search for SafeBreach v2.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URLs, token, and connection.

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
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedExpirationInterval |  | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |



## SafeBreach Insights
Table below summaries all available SafeBreach insights and their relative ids that should be used when calling the related commands.
Every customer environment might have some of the insights depending on the simulation results that were not blocked in the environment.

| **Insight Id** | **Category** | **Data Type** | **Description** |
| --- | --- | --- | --- |
| 1 |  Network Access | Port | Outbound traffic over non-standard ports
| 2 |  Network Access | Protocol | Outbound traffic over non-standard protocols
| 3 |  Network Access | Port | Outbound traffic over non-SSL protocols using secured ports
| 4 |  Network Access | Port | Outbound traffic over not matching ports and protocols
| 19 |  Network Access | Port | Inbound traffic over non-standard ports
| 20 |  Network Access | Protocol | Inbound traffic over non-standard protocols
| 21 |  Network Access | Port | Inbound traffic over non-SSL protocols using secured ports
| 22 |  Network Access | Port | Inbound traffic over not matching ports and protocols
| 5 |  Web | Domain | Malicious domain resolution
| 6 |  Web | URI  | Malicious URL requests
| 7 |  Network Inspection | Hash | Malware transfer over standard ports
| 10 |  Network Inspection | Protocol | Brute force
| 11 |  Network Inspection | Other  | Inbound C&C communication
| 12 |  Network Inspection | Other  | Outbound C&C communication
| 8 |  Endpoint | Other | Execution of malware or code
| 9 |  Endpoint | Hash | Malware drop to disk
| 13 |  Endpoint | Other  | Malicious host actions
| 14 |  Endpoint | Command  | Data and host information gathering
| 16 |  Data Leak | Other  | Exfiltration of sensitive data assets
| 15 |  Email | Hash  | Email with encrypted malicious attachments
| 24 |  Email |Hash  | Email with non-encrypted malicious attachment 

## Playbooks

#### SafeBreach - Process Non-Behavioral Insights Feed  
- This playbook automatically remediates all non-behavioral indicators generated from SafeBreach Insights. To validate the remediation, it reruns the related insights and classifies the indicators as Remediated or Not Remediated.
A special feed based triggered job is required to initiate this playbook for every new SafeBreach generated indicator.

#### SafeBreach - Process Behavioral Insights Feed (Premium)
- This playbook processes all SafeBreach behavioral indicators. It creates an incident for each SafeBreach Insight, enriched with all the related indicators and additional SafeBreach contextual information.
A special feed based triggered job is required to initiate this playbook for every new SafeBreach generated indicator.

#### SafeBreach - Rerun Insights 
- This is a sub-playbook reruns a list of SafeBreach insights based on Insight Id and waits until they complete. Used in main SafeBreach playbooks, such as "SafeBreach - Handle Insight Incident" and "SafeBreach - Process Non-Behavioral Insights Feed".

#### SafeBreach - Rerun Single Insight 
- This playbook uses the following sub-playbooks, integrations, and scripts.

#### SafeBreach - Compare and Validate Insight Indicators
- This playbook compares SafeBreach Insight indicators before and after the processing. It receives an insight and it's indicators before validation, fetches updated indicators after rerunning the insight, and then compares the results to validate mitigation. Indicators are classified as Remediated or Not Remediated based on their validated status and the appropriate field (SafeBreach Remediation Status) is updated.
  
#### SafeBreach - SafeBreach Create Incidents per Insight and Associate Indicators
- This is a sub-playbook that creates incidents per SafeBreach insight, enriched with all the related indicators and additional SafeBreach insight contextual information. Used in main SafeBreach playbooks, such as "SafeBreach - Process Behavioral Insights Feed" and "SafeBreach - Process Non-Behavioral Insights Feed".  

#### SafeBreach - Handle Insight Incident (Premium)
- This playbook is triggered automatically for each SafeBreach Insight incident:
    1. Adding insight information (including suggested remediation actions);
    2. Assigning it to an analyst to remediate and either “ignore” or “validate.” Validated incidents are rerun with the related SafeBreach Insight and the results are compared to the previous indicator results. The incident is closed once all the indicators are resolved or the analyst “ignores” the incident. Unresolved indicators wait for handling by the analyst.




## Dashboard (Premium) 
SafeBreach Insights dashboard summarizes the current status of actionable insights and related indicators.
 ![SafeBreach Dashboard](https://github.com/demisto/content/raw/6af01e00312a5558e9e2fecdb22534e98414bc9c/Packs/SafeBreach/doc_imgs/xsoar_SafeBreach_dashboard.png)

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


##### Command Example
```!safebreach-get-test-status testId=1585757174467.23```

##### Context Example
```
{
    "SafeBreach": {
        "Test": {
            "EndTime": "2020-04-01T16:10:36.389Z",
            "Id": "1585757174467.23",
            "Name": "Rerun (Demisto) - #(2122) Write SamSam Malware (AA18-337A) to Disk",
            "StartTime": "2020-04-01T16:06:14.471Z",
            "Status": "CANCELED",
            "TotalSimulationNumber": 9
        }
    }
}
```

##### Human Readable Output
### Test Status
|Test Id|Name|Status|Start Time|End Time|Total Simulation Number|
|---|---|---|---|---|---|
| 1585757174467.23 | Rerun (Demisto) - #(2122) Write SamSam Malware (AA18-337A) to Disk | CANCELED | 2020-04-01T16:06:14.471Z | 2020-04-01T16:10:36.389Z | 9 |




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


##### Command Example
```!safebreach-get-simulation simulationId=d937cd0e5fd4e2c9266801b7bd17e097```

##### Context Example
```
{
    "SafeBreach": {
        "Simulation": {
            "Attack": {
                "Description": "**Goal**\n\n1. Verify whether the malware can be written to disk.\n\n**Actions**\n\n1. **Malware Drop**  \n    **Action:** [wannacry](https://attack.mitre.org/software/S0366) malware is written to disk on the target simulator.  \n    **Expected behavior:** The malware written to disk is identified and removed after a pre-defined time period.  \n\n**More Info**  \n",
                "Id": 3055,
                "IndicatorBased": "False",
                "Name": "Write wannacry malware to disk",
                "Phase": "Host Level",
                "SecurityControl": [
                    "Endpoint"
                ],
                "Type": [
                    "Malware Drop"
                ]
            },
            "Attacker": {
                "ExternalIp": "172.31.42.76",
                "InternalIp": "172.31.42.76",
                "Name": "Win10 - Cylance",
                "OS": "WINDOWS",
                "SimulationDetails": {
                    "DETAILS": "Task finished running because of an exception. Traceback: \r\nTraceback (most recent call last):\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\task_action_runner.py\", line 89, in run\n    pythonect_result_object = pythonect_runner(full_pythonect_string, self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\runners\\runner_classes.py\", line 187, in __call__\n    return pythonect.eval(self.pythonect_string, locals_=self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 938, in eval\n    result = _run(graph, root_nodes[0], globals_, locals_, {}, pool, False)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 734, in _run\n    result = runner(__node_main, args=(input_value, last_value, globals_, locals_))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 629, in __apply_current\n    return func(*args, **kwds)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 440, in __node_main\n    return_value = python.eval(current_value, globals_, locals_)\n  File \"<string>\", line 1, in <module>\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\__init__.py\", line 285, in wrapper\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\endpoint\\utils\\file_utils.py\", line 121, in open_or_die\nSBFileNotFoundException: ('File (%s) was removed', 'c:\\\\windows\\\\temp\\\\sb-sim-temp-jvu_fk\\\\sb_107985_bs_9vrn0e\\\\bdata.bin')\n",
                    "ERROR": "",
                    "METADATA": {
                        "executable": [
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\python.exe",
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\safebreach_simulation.py"
                        ],
                        "hostname": "Cylance-Win10-Demisto",
                        "pid": 5584,
                        "ret_code": 0
                    },
                    "OUTPUT": "",
                    "SIMULATION_STEPS": [
                        {
                            "level": "INFO",
                            "message": "File opened",
                            "params": {
                                "mode": "wb",
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107985_bs_9vrn0e\\bdata.bin"
                            },
                            "time": "2020-04-02T09:47:01.500000"
                        },
                        {
                            "level": "INFO",
                            "message": "File written",
                            "params": {
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107985_bs_9vrn0e\\bdata.bin"
                            },
                            "time": "2020-04-02T09:47:01.500000"
                        }
                    ]
                }
            },
            "Classifications": {
                "MITREGroups": [
                    "Lazarus Group"
                ],
                "MITRESoftware": [
                    "(S0366) wannacry"
                ],
                "MITRETechniques": [
                    "(T1107) File Deletion"
                ]
            },
            "DetectedAction": "Prevent",
            "FinalStatus": "Prevented",
            "Id": "d937cd0e5fd4e2c9266801b7bd17e097",
            "Labels": [],
            "LastChangeTime": "2020-03-10T15:13:51.900Z",
            "Network": {
                "DestinationIp": "",
                "DestinationPort": null,
                "Direction": null,
                "Protocol": "N/A",
                "Proxy": null,
                "SourceIp": "",
                "SourcePort": []
            },
            "Parameters": {
                "BINARY": [
                    {
                        "displayName": "Sample binaries",
                        "displayType": "Hash",
                        "displayValue": "sha256",
                        "md5": "246c2781b88f58bc6b0da24ec71dd028",
                        "name": "buffer",
                        "sha256": "16493ecc4c4bc5746acbe96bd8af001f733114070d694db76ea7b5a0de7ad0ab",
                        "value": "16493ecc4c4bc5746acbe96bd8af001f733114070d694db76ea7b5a0de7ad0ab"
                    }
                ],
                "NOT_CLASSIFIED": [
                    {
                        "displayName": "Simulation wait",
                        "displayType": "Not Classified",
                        "displayValue": "10 seconds",
                        "name": "timeout",
                        "value": "10"
                    }
                ],
                "PATH": [
                    {
                        "displayName": "Drop paths",
                        "displayType": "Path",
                        "displayValue": "Temporary folder",
                        "name": "drop_path",
                        "value": "%temp%\\\\\\\\bdata.bin"
                    }
                ],
                "SIMULATION_USER_DESTINATION": [
                    {
                        "displayName": "Impersonated User - Target",
                        "displayValue": "SYSTEM",
                        "name": "Impersonated User - Target",
                        "value": "SYSTEM"
                    }
                ]
            },
            "Result": "Blocked",
            "SimulationRunId": 107985,
            "Target": {
                "ExternalIp": "172.31.42.76",
                "InternalIp": "172.31.42.76",
                "Name": "Win10 - Cylance",
                "OS": "WINDOWS",
                "SimulationDetails": {
                    "DETAILS": "Task finished running because of an exception. Traceback: \r\nTraceback (most recent call last):\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\task_action_runner.py\", line 89, in run\n    pythonect_result_object = pythonect_runner(full_pythonect_string, self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\runners\\runner_classes.py\", line 187, in __call__\n    return pythonect.eval(self.pythonect_string, locals_=self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 938, in eval\n    result = _run(graph, root_nodes[0], globals_, locals_, {}, pool, False)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 734, in _run\n    result = runner(__node_main, args=(input_value, last_value, globals_, locals_))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 629, in __apply_current\n    return func(*args, **kwds)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 440, in __node_main\n    return_value = python.eval(current_value, globals_, locals_)\n  File \"<string>\", line 1, in <module>\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\__init__.py\", line 285, in wrapper\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\endpoint\\utils\\file_utils.py\", line 121, in open_or_die\nSBFileNotFoundException: ('File (%s) was removed', 'c:\\\\windows\\\\temp\\\\sb-sim-temp-jvu_fk\\\\sb_107985_bs_9vrn0e\\\\bdata.bin')\n",
                    "ERROR": "",
                    "METADATA": {
                        "executable": [
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\python.exe",
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\safebreach_simulation.py"
                        ],
                        "hostname": "Cylance-Win10-Demisto",
                        "pid": 5584,
                        "ret_code": 0
                    },
                    "OUTPUT": "",
                    "SIMULATION_STEPS": [
                        {
                            "level": "INFO",
                            "message": "File opened",
                            "params": {
                                "mode": "wb",
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107985_bs_9vrn0e\\bdata.bin"
                            },
                            "time": "2020-04-02T09:47:01.500000"
                        },
                        {
                            "level": "INFO",
                            "message": "File written",
                            "params": {
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107985_bs_9vrn0e\\bdata.bin"
                            },
                            "time": "2020-04-02T09:47:01.500000"
                        }
                    ]
                }
            },
            "Time": "2020-04-02T09:47:12.506Z"
        }
    }
}
```

##### Human Readable Output
### SafeBreach Simulation
|Id|Name|Status|Result|Detected Action|Attacker|Target|
|---|---|---|---|---|---|---|
| d937cd0e5fd4e2c9266801b7bd17e097 | (#3055) Write wannacry malware to disk | Prevented | Fail | Prevent | Win10 - Cylance (172.31.42.76,172.31.42.76) | Win10 - Cylance (172.31.42.76,172.31.42.76) |




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


##### Command Example
```!safebreach-rerun-simulation simulationId=d937cd0e5fd4e2c9266801b7bd17e097```

##### Context Example
```
{
    "SafeBreach": {
        "Simulation": {
            "Id": "d937cd0e5fd4e2c9266801b7bd17e097",
            "Rerun": {
                "Id": "1586684466634.76",
                "Name": "Rerun (Demisto) - #(3055) Write wannacry malware to disk",
                "ScheduledTime": "2020-04-12T09:41:06.643609"
            }
        },
        "Test": {
            "AttacksCount": 1,
            "Id": "1586684466634.76",
            "Name": "Rerun (Demisto) - #(3055) Write wannacry malware to disk",
            "Status": "PENDING"
        }
    }
}
```

##### Human Readable Output
### SafeBreach Rerun Simualtion
|Simulation Id|Test Id|Name|
|---|---|---|
| d937cd0e5fd4e2c9266801b7bd17e097 | 1586684466634.76 | Rerun (Demisto) - #(3055) Write wannacry malware to disk |


### safebreach-get-indicators
***
Fetches SafeBreach Insights from which indicators are extracted, creating new indicators or updating existing indicators.


##### Base Command

`safebreach-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to generate. The default is 1000. | Optional | 
| insightCategory | Multi-select option for the category of the insights to get remediation data for:<br/>Network Access, Network Inspection, Endpoint, Email, Web, Data Leak | Optional | 
| insightDataType | Multi-select option for the remediation data type to get:<br/>Hash, Domain, URI, Command, Port, Protocol, Registry | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!safebreach-get-indicators limit=10```

##### Context Example
```
None
```

##### Human Readable Output
### Indicators:
|Fields|Rawjson|Score|Type|Value|
|---|---|---|---|---|
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 0a2076b9d288411486a0c6367bccf75ea0fd6ba9aaaa9ff046ff3959f60ff35f<br />tags: SafeBreachInsightId: 7 | value: 0a2076b9d288411486a0c6367bccf75ea0fd6ba9aaaa9ff046ff3959f60ff35f<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 0a2076b9d288411486a0c6367bccf75ea0fd6ba9aaaa9ff046ff3959f60ff35f |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 0dcbb073b62f9ec1783d98d826bbfd1f938feb59e8e70180c00ecdfd903c0fe1<br />tags: SafeBreachInsightId: 7 | value: 0dcbb073b62f9ec1783d98d826bbfd1f938feb59e8e70180c00ecdfd903c0fe1<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 0dcbb073b62f9ec1783d98d826bbfd1f938feb59e8e70180c00ecdfd903c0fe1 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: f456baa4593272686b9e07c8d902868991423dddeb5587734985d676c06dc730<br />tags: SafeBreachInsightId: 7 | value: f456baa4593272686b9e07c8d902868991423dddeb5587734985d676c06dc730<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | f456baa4593272686b9e07c8d902868991423dddeb5587734985d676c06dc730 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: e3c6ce5a57623cb0ea51f70322c312ccf23b9e4a7342680fd18f0cce556aaa0f<br />tags: SafeBreachInsightId: 7 | value: e3c6ce5a57623cb0ea51f70322c312ccf23b9e4a7342680fd18f0cce556aaa0f<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | e3c6ce5a57623cb0ea51f70322c312ccf23b9e4a7342680fd18f0cce556aaa0f |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 327c968b4c381d7c8f051c78720610cbb115515a370924c0d414c403524d7a03<br />tags: SafeBreachInsightId: 7 | value: 327c968b4c381d7c8f051c78720610cbb115515a370924c0d414c403524d7a03<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 327c968b4c381d7c8f051c78720610cbb115515a370924c0d414c403524d7a03 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 566ef062b86cc505fac48c50a80c65ae5f8bd19cdf6dc2a9d935045d08a37e60<br />tags: SafeBreachInsightId: 7 | value: 566ef062b86cc505fac48c50a80c65ae5f8bd19cdf6dc2a9d935045d08a37e60<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 566ef062b86cc505fac48c50a80c65ae5f8bd19cdf6dc2a9d935045d08a37e60 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 620f756be7815e24dfb2724839dc616fe46b545fa13fd3a7e063db661e21d596<br />tags: SafeBreachInsightId: 7 | value: 620f756be7815e24dfb2724839dc616fe46b545fa13fd3a7e063db661e21d596<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 620f756be7815e24dfb2724839dc616fe46b545fa13fd3a7e063db661e21d596 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 500f7f7b858b4bb4e4172361327ee8c340bc95442ebf713d60f892347e02af2f<br />tags: SafeBreachInsightId: 7 | value: 500f7f7b858b4bb4e4172361327ee8c340bc95442ebf713d60f892347e02af2f<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 500f7f7b858b4bb4e4172361327ee8c340bc95442ebf713d60f892347e02af2f |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 5fd54218d1c68562e0a98985f79cb03526aa97e95be020a2b8ceaa9c083f9c19<br />tags: SafeBreachInsightId: 7 | value: 5fd54218d1c68562e0a98985f79cb03526aa97e95be020a2b8ceaa9c083f9c19<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 5fd54218d1c68562e0a98985f79cb03526aa97e95be020a2b8ceaa9c083f9c19 |
| description: SafeBreach Insight - Prevent malware network transfer<br />sha256: 1711fbb363aebfe66f2d8dcbf8cddca8d2fd9fa9a6952da5873b7825e57f542d<br />tags: SafeBreachInsightId: 7 | value: 1711fbb363aebfe66f2d8dcbf8cddca8d2fd9fa9a6952da5873b7825e57f542d<br />dataType: SHA256<br />insightId: 7<br />insightTime: 2020-04-07T15:54:01.256Z | 3 | File | 1711fbb363aebfe66f2d8dcbf8cddca8d2fd9fa9a6952da5873b7825e57f542d |


