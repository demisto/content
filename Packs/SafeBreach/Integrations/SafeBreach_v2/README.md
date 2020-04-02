SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness.  Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.
This integration was integrated and tested with version xx of SafeBreach v2
## Configure SafeBreach v2 on Demisto

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
| SafeBreach.Insight.ThreatGroups | Array | Array of APT names that are mapped to the insight | 
| SafeBreach.Insight.NetworkDirection | String | Communication direction of Insight, relative to the target \(inbound/outbound\) | 
| SafeBreach.Insight.AttacksCount | Number | List of all insight related SafeBreach attack ids | 


##### Command Example
```!safebreach-get-insights insightIds=[5,9]```

##### Context Example
```
{
    "SafeBreach": {
        "Insight": [
            {
                "AffectedTargetsCount": 1,
                "AttacksCount": 1,
                "Category": "Web",
                "DataType": "Domain",
                "EarliestSimulation": "2020-03-30T14:34:16.694Z",
                "Id": 5,
                "LatestSimulation": "2020-03-30T14:34:16.694Z",
                "Name": "Blacklist malicious domains",
                "NetworkDirection": "outbound",
                "RemediationDataCount": 1,
                "RemediationDataType": "FQDN/IP",
                "RiskImpact": 0,
                "Severity": "Low",
                "SeverityScore": 5,
                "SimulationsCount": 1,
                "ThreatGroups": [
                    "N/A"
                ]
            },
            {
                "AffectedTargetsCount": 3,
                "AttacksCount": 116,
                "Category": "Endpoint",
                "DataType": "Hash",
                "EarliestSimulation": "2020-03-23T09:37:36.409Z",
                "Id": 9,
                "LatestSimulation": "2020-04-01T16:10:45.892Z",
                "Name": "Prevent malware to be written to disk",
                "NetworkDirection": null,
                "RemediationDataCount": 116,
                "RemediationDataType": "Attack",
                "RiskImpact": 0.44,
                "Severity": "Medium",
                "SeverityScore": 10,
                "SimulationsCount": 242,
                "ThreatGroups": [
                    "APT28",
                    "APT34",
                    "APT32",
                    "OilRig",
                    "APT37",
                    "Lazarus Group",
                    "menuPass",
                    "APT29",
                    "APT3",
                    "APT30",
                    "APT38",
                    "APT39",
                    "BRONZE BUTLER",
                    "Dark Caracal",
                    "DragonOK",
                    "FIN7",
                    "Leviathan",
                    "N/A",
                    "Naikon",
                    "PittyTiger",
                    "Scarlet Mimic",
                    "Soft Cell",
                    "TA459",
                    "Threat Group-3390",
                    "Turla",
                    "Winnti Group",
                    "admin@338"
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
| 5 | Blacklist malicious domains | Web | 0.0 | Low | 1 | Domain |
| 9 | Prevent malware to be written to disk | Endpoint | 0.44 | Medium | 3 | Hash |


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
| DBotScore.Score | Number | 3 \(Bad\). The score of the indicator | 


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
    "Domain": {
        "Domain": "srv.desk-top-app.info",
        "Malicious": {
            "Description": "SafeBreach Insights",
            "Vendor": "SafeBreach"
        }
    },
    "SafeBreach": {
        "Insight": {
            "FQDN/IP": [
                "srv.desk-top-app.info"
            ],
            "Id": "5"
        }
    },
    "URL": {
        "Data": "srv.desk-top-app.info",
        "Malicious": {
            "Description": "SafeBreach Insight - Blacklist malicious domains",
            "Vendor": "SafeBreach"
        }
    }
}
```

##### Human Readable Output
### Remediation Data
|FQDN/IP (1)|
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
| insightId | The id of the insight to rerun | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Insight.Id | Number | Insight unique id | 
| SafeBreach.Insight.Rerun.Name | String | Insight rerun test name | 
| SafeBreach.Insight.Rerun.Id | String | Id of the rerun insight test | 
| SafeBreach.Insight.Rerun.AttacksCount | Number | Count of the attacks executed in the insight rerun test | 
| SafeBreach.Test.Id | String | Id of the test | 
| SafeBreach.Test.Name | String | Name of the test | 
| SafeBreach.Test.AttacksCount | Number | Count of the attacks executed in the insight rerun test | 
| SafeBreach.Test.Status | String | Test run status. For insight rerun, starts from PENDING. | 
| SafeBreach.Test.ScheduledTime | Date | Time at which the test was triggered | 


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
                    "Id": "1585820785074.33",
                    "Name": "Insight (Demisto) - Blacklist malicious domains",
                    "ScheduledTime": "2020-04-02T09:46:25.078203"
                }
            ]
        },
        "Test": {
            "AttacksCount": 1,
            "Id": "1585820785074.33",
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
| 1 | 5 | Insight (Demisto) - Blacklist malicious domains | 1585820785074.33 |


### safebreach-get-indicators
***
Fetches SafeBreach Insights and extracts indicators out of them, creating new or updating existing indicators.


##### Base Command

`safebreach-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limits the maximal number of generated indicators. Default - 1000. | Optional | 
| insightCategory | Multi-select option for category of the insights to get remediation data for:<br/>Network Access, Network Inspection, Endpoint, Email, Web, Data Leak | Optional | 
| insightDataType | Multi-select option for remediation data type to get:<br/>Hash, Domain, URI, Command, Port, Protocol, Registry | Optional | 


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


### safebreach-get-test-status
***
Get status of a SafeBreach test for tracking progress of a run


##### Base Command

`safebreach-get-test-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| testId | The id of the test to track | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Test.Id | String | Id of the test | 
| SafeBreach.Test.Name | String | Name of the test | 
| SafeBreach.Test.Status | String | Test run status. Options: PENDING, RUNNING, CANCELED, COMPLETED | 
| SafeBreach.Test.StartTime | Date | Staring time of the test | 
| SafeBreach.Test.EndTime | Date | Ending time of the test | 
| SafeBreach.Test.TotalSimulationNumber | Number | Number of simulations for the test | 


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


##### Base Command

`safebreach-get-simulation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulationId | The ID of the simulation. By default taken from the incident | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.Id | String | Id of the simulation result | 
| SafeBreach.Simulation.FinalStatus | String | Simulation final status: Missed,Detected,Stopped,Prevented,Inconsistent | 
| SafeBreach.Simulation.Result | String | Indicates whether the simulation was blocked or not | 
| SafeBreach.Simulation.DetectedAction | String | Indicates the overall detected action taken by security controls | 
| SafeBreach.Simulation.SimulationRunId | Number | The unique simulation run id \(changes between simulation runs\) | 
| SafeBreach.Simulation.Time | Datetime | Latest simulation run time | 
| SafeBreach.Simulation.LastChangeTime | Datetime | Time when the simulation result was changed | 
| SafeBreach.Simulation.Labels | Array | Array of labels applied on the simulation | 
| SafeBreach.Simulation.Attack.Id | String | Id of the simulated attack | 
| SafeBreach.Simulation.Attack.Name | String | Name of the simulated attack | 
| SafeBreach.Simulation.Attack.Description | String | Description of the attack flow | 
| SafeBreach.Simulation.Attack.Phase | String | The phase of the attack: Infiltration, Exfiltration ,Lateral Movement,Host Level | 
| SafeBreach.Simulation.Attack.Type | String | The type of the attack. For example:,Real C2 Communication,Malware Transfer,Malware Write to Disk | 
| SafeBreach.Simulation.Attack.SecurityControl | String | Related security control category | 
| SafeBreach.Simulation.Attack.IndicatorBased | Bool | True if this attack is based on an indicator. False if this is behavioral non\-indicator based. | 
| SafeBreach.Simulation.Attacker.Name | String | Name of the attacker simulator | 
| SafeBreach.Simulation.Attacker.OS | String | OS of the attacker simulator | 
| SafeBreach.Simulation.Attacker.InternalIp | String | Internal IP of the attacker simulator | 
| SafeBreach.Simulation.Attacker.ExternalIp | String | External IP of the attacker simulator | 
| SafeBreach.Simulation.Attacker.SimulationDetails | JSON | Simulation run detailed logs from the attacker simulator | 
| SafeBreach.Simulation.Target.Name | String | Name of the target simulator | 
| SafeBreach.Simulation.Target.OS | String | OS of the target simulator | 
| SafeBreach.Simulation.Target.InternalIp | String | Internal IP of the target simulator | 
| SafeBreach.Simulation.Target.ExternalIp | String | External IP of the target simulator | 
| SafeBreach.Simulation.Target.SimulationDetails | JSON | Simulation run detailed logs from the target simulator | 
| SafeBreach.Simulation.Network.Direction | String | Attack network direction relative to the target: inbound / outbound | 
| SafeBreach.Simulation.Network.SourceIp | String | The IP initiated the network communication | 
| SafeBreach.Simulation.Network.DestinationIp | String | The IP received the network communication | 
| SafeBreach.Simulation.Network.SourcePort | String | The source port of the network communication | 
| SafeBreach.Simulation.Network.DestinationPort | String | The destination port of the network communication | 
| SafeBreach.Simulation.Network.Protocol | String | The top level protocol of the network communication | 
| SafeBreach.Simulation.Network.Proxy | String | The proxy name used in the network communication | 
| SafeBreach.Simulation.Classifications.MITRETechniques | Array | List of attack related MITRE techniques | 
| SafeBreach.Simulation.Classifications.MITREGroups | Array | List of attack related MITRE threat groups | 
| SafeBreach.Simulation.Classifications.MITRESoftware | Array | List of attack related MITRE software and tools | 
| SafeBreach.Simulation.Parameters | JSON | Parameters of the simulation | 


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
                    "DETAILS": "Task finished running because of an exception. Traceback: \r\nTraceback (most recent call last):\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\task_action_runner.py\", line 89, in run\n    pythonect_result_object = pythonect_runner(full_pythonect_string, self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\runners\\runner_classes.py\", line 187, in __call__\n    return pythonect.eval(self.pythonect_string, locals_=self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 938, in eval\n    result = _run(graph, root_nodes[0], globals_, locals_, {}, pool, False)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 734, in _run\n    result = runner(__node_main, args=(input_value, last_value, globals_, locals_))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 629, in __apply_current\n    return func(*args, **kwds)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 440, in __node_main\n    return_value = python.eval(current_value, globals_, locals_)\n  File \"<string>\", line 1, in <module>\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\__init__.py\", line 285, in wrapper\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\endpoint\\utils\\file_utils.py\", line 121, in open_or_die\nSBFileNotFoundException: ('File (%s) was removed', 'c:\\\\windows\\\\temp\\\\sb-sim-temp-jvu_fk\\\\sb_107966_bs_hyc99z\\\\bdata.bin')\n",
                    "ERROR": "",
                    "METADATA": {
                        "executable": [
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\python.exe",
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\safebreach_simulation.py"
                        ],
                        "hostname": "Cylance-Win10-Demisto",
                        "pid": 10280,
                        "ret_code": 0
                    },
                    "OUTPUT": "",
                    "SIMULATION_STEPS": [
                        {
                            "level": "INFO",
                            "message": "File opened",
                            "params": {
                                "mode": "wb",
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107966_bs_hyc99z\\bdata.bin"
                            },
                            "time": "2020-04-02T09:41:43.956000"
                        },
                        {
                            "level": "INFO",
                            "message": "File written",
                            "params": {
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107966_bs_hyc99z\\bdata.bin"
                            },
                            "time": "2020-04-02T09:41:43.956000"
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
            "DetectedAction": "None",
            "FinalStatus": "Stopped",
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
            "SimulationRunId": 107966,
            "Target": {
                "ExternalIp": "172.31.42.76",
                "InternalIp": "172.31.42.76",
                "Name": "Win10 - Cylance",
                "OS": "WINDOWS",
                "SimulationDetails": {
                    "DETAILS": "Task finished running because of an exception. Traceback: \r\nTraceback (most recent call last):\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\task_action_runner.py\", line 89, in run\n    pythonect_result_object = pythonect_runner(full_pythonect_string, self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\sbsimulation\\runners\\runner_classes.py\", line 187, in __call__\n    return pythonect.eval(self.pythonect_string, locals_=self.pythonect_params)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 938, in eval\n    result = _run(graph, root_nodes[0], globals_, locals_, {}, pool, False)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 738, in _run\n    return_value = _run_next_virtual_nodes(graph, node, globals_, locals_, flags, pool, result)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 224, in _run_next_virtual_nodes\n    return_value = __resolve_and_merge_results(_run(graph, node, tmp_globals, tmp_locals, {}, pool, True))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 660, in _run\n    return_value = _run_next_graph_nodes(graph, node, globals_, locals_, pool)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 610, in _run_next_graph_nodes\n    nodes_return_value.insert(0, _run(graph, next_nodes[0], globals_, locals_, {}, pool, False))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 734, in _run\n    result = runner(__node_main, args=(input_value, last_value, globals_, locals_))\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 629, in __apply_current\n    return func(*args, **kwds)\n  File \"C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\lib\\site-packages\\pythonect\\internal\\eval.py\", line 440, in __node_main\n    return_value = python.eval(current_value, globals_, locals_)\n  File \"<string>\", line 1, in <module>\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\__init__.py\", line 285, in wrapper\n  File \"c:\\jenkins\\workspace\\multi-branch_master-NLIC56DSK443DP5KDJGAEKHQDPZ2GF\\agent\\project\\dependencies\\framework\\src\\build\\lib\\framework\\endpoint\\utils\\file_utils.py\", line 121, in open_or_die\nSBFileNotFoundException: ('File (%s) was removed', 'c:\\\\windows\\\\temp\\\\sb-sim-temp-jvu_fk\\\\sb_107966_bs_hyc99z\\\\bdata.bin')\n",
                    "ERROR": "",
                    "METADATA": {
                        "executable": [
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\python.exe",
                            "C:\\Program Files\\SafeBreach\\SafeBreach Endpoint Simulator\\app\\20.1.13\\simvenv\\Scripts\\safebreach_simulation.py"
                        ],
                        "hostname": "Cylance-Win10-Demisto",
                        "pid": 10280,
                        "ret_code": 0
                    },
                    "OUTPUT": "",
                    "SIMULATION_STEPS": [
                        {
                            "level": "INFO",
                            "message": "File opened",
                            "params": {
                                "mode": "wb",
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107966_bs_hyc99z\\bdata.bin"
                            },
                            "time": "2020-04-02T09:41:43.956000"
                        },
                        {
                            "level": "INFO",
                            "message": "File written",
                            "params": {
                                "path": "c:\\windows\\temp\\sb-sim-temp-jvu_fk\\sb_107966_bs_hyc99z\\bdata.bin"
                            },
                            "time": "2020-04-02T09:41:43.956000"
                        }
                    ]
                }
            },
            "Time": "2020-04-02T09:41:52.369Z"
        }
    }
}
```

##### Human Readable Output
### SafeBreach Simulation
|Id|Name|Status|Result|Detected Action|Attacker|Target|
|---|---|---|---|---|---|---|
| d937cd0e5fd4e2c9266801b7bd17e097 | (#3055) Write wannacry malware to disk | Stopped | Fail | None | ["Win10 - Cylance (172.31.42.76,172.31.42.76)"] | ["Win10 - Cylance (172.31.42.76,172.31.42.76)"] |


### safebreach-rerun-simulation
***
Rerun a specific SafeBreach simulation in your environment


##### Base Command

`safebreach-rerun-simulation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulationId | The id of the simulation to rerun | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.Id | Number | Simulation unique id | 
| SafeBreach.Simulation.Rerun.Name | String | Simulation rerun test name | 
| SafeBreach.Simulation.Rerun.Id | String | Id of the rerun test | 
| SafeBreach.Simulation.Rerun.ScheduledTime  | Datetime | Time at which the rerun was triggered | 
| SafeBreach.Test.Id | String | Id of the test | 
| SafeBreach.Test.Name | String | Name of the test | 
| SafeBreach.Test.AttacksCount | Number | Count of the attacks executed in the insight rerun test | 
| SafeBreach.Test.Status | String | Test run status. For insight rerun \- “PENDING” | 
| SafeBreach.Test.ScheduledTime | Datetime | Time at which the test was triggered | 


##### Command Example
```!safebreach-rerun-simulation simulationId=d937cd0e5fd4e2c9266801b7bd17e097```

##### Context Example
```
{
    "SafeBreach": {
        "Simulation": {
            "Id": "d937cd0e5fd4e2c9266801b7bd17e097",
            "Rerun": {
                "Id": "1585820802418.34",
                "Name": "Rerun (Demisto) - #(3055) Write wannacry malware to disk",
                "ScheduledTime": "2020-04-02T09:46:42.422750"
            }
        },
        "Test": {
            "AttacksCount": 1,
            "Id": "1585820802418.34",
            "Name": "Rerun (Demisto) - #(3055) Write wannacry malware to disk",
            "Status": "Pending"
        }
    }
}
```

##### Human Readable Output
### SafeBreach Rerun Simualtion
|Simulation Id|Test Id|Name|
|---|---|---|
| d937cd0e5fd4e2c9266801b7bd17e097 | 1585820802418.34 | Rerun (Demisto) - #(3055) Write wannacry malware to disk |

