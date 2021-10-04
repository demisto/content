## Overview
---

Fetch & remediate security incidents identified by Logz.io Cloud SIEM
This integration was integrated and tested with Logz.io platform.
## Logz.io Playbook
---
Logz.Io Handle Alert: used to handle alerts retrieved from Logz.io. The playbook will retrieve the related events that generated the alert using the logzio-get-logs-by-event-id command

## Use Cases
---

Integrate with Logz.io Cloud SIEM to automatically remediate security incidents identified by Logz.io and increase observability into incident details. 
The integration allows Cortex XSOAR users to automatically remediate incidents identified by Logz.io Cloud SIEM using Cortex XSOAR Playbooks.
In addition, users can query Logz.io directly from Cortex XSOAR to investigate open questions or retrieve the logs responsible for triggering security rules.

## Configure Logz.io on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Analytics & SIEM__.
2. Search for Logz.io.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents.__
    * __Incident type__
    * __API token for Logz.io Security account__
    * __API token for Logz.io Operations account__
    * __Region code of your Logz.io account__
    * __Filter on rule names (Lucene syntax)__
    * __Filter by rule severity__
    * __First fetch time range ({number} {time unit}, e.g., 1 hour, 30 minutes)__
    * __Max. number of incidents fetched per run__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. logzio-search-logs
2. logzio-get-logs-by-event-id

### 1. logzio-search-logs
---
Returns logs from your Logz.io Operations account by Lucene query

**Note**: The search time range can span over 2 calender days at most. If you supply a time range greater than that, 
the search window will be the **last** 2 calender days within the range you supplied.
##### Required Permissions
Your Logz.io account type should be PRO or above.
##### Base Command

`logzio-search-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A string specifying the search query, written in Apache Lucene syntax e.g. 'fname:John AND sname:Smith' . | Required | 
| size | An integer specifying the maximum number of results to return. | Optional | 
| from_time | Specifies the earliest timestamp to be returned by the query. | Optional | 
| to_time | Specifies the latest timestamp to be returned by the query. | Optional | 
| timeout | Timeout in seconds | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logzio.Result | Unknown | An array of search results | 
| Logzio.Result.type | string | Log type in the index | 
| Logzio.Result.timestamp | date | The log's timestamp | 


##### Command Example
```!logzio-search-logs query="ThreatType:trojan OR input.type:tcp" size="5"```

##### Context Example
```
{
    "Logzio.Result": [
        {
            "ThreatType": [
                "trojan", 
                "trojan"
            ], 
            "Severity": [
                "3", 
                "3"
            ], 
            "DetectionMessage": [
                "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                "IDS_OAS_DEFAULT_THREAT_MESSAGE"
            ], 
            "@timestamp": "2020-05-06T00:01:04.441+0000", 
            "TargetFileSize": [
                "249952", 
                "249952"
            ], 
            "domain": [
                "Win-Sec-2", 
                "Win-Sec-2"
            ], 
            "tenantGUID": "{00000000-0000-0000-0000-000000000000}", 
            "SecondActionStatus": [
                "False", 
                "False"
            ], 
            "EPOEvents": "EventFwd", 
            "DurationBeforeDetection": [
                "18", 
                "18"
            ], 
            "Cleanable": [
                "True", 
                "True"
            ], 
            "bpsId": "1", 
            "FirstAttemptedAction": [
                "IDS_ALERT_THACT_ATT_CLE", 
                "IDS_ALERT_THACT_ATT_CLE"
            ], 
            "SourceProcessName": [
                "C:\\Windows\\explorer.exe", 
                "C:\\Windows\\explorer.exe"
            ], 
            "AnalyzerName": [
                "McAfee Endpoint Security", 
                "McAfee Endpoint Security"
            ], 
            "AnalyzerContentCreationDate": [
                "2020-02-22T08:24:00Z", 
                "2020-02-22T08:24:00Z"
            ], 
            "TargetAccessTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "TargetCreateTime": [
                "2020-02-23T15:43:21Z", 
                "2020-02-23T15:43:21Z"
            ], 
            "TargetHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "logzio_codec": "plain", 
            "DetectedUTC": [
                "2020-02-23T15:43:40Z", 
                "2020-02-23T15:43:40Z"
            ], 
            "Analyzer": [
                "ENDP_AM_1060", 
                "ENDP_AM_1060"
            ], 
            "TargetHash": [
                "81da244a770c46ace2cf112214f8e75e", 
                "81da244a770c46ace2cf112214f8e75e"
            ], 
            "AttackVectorType": [
                "4", 
                "4"
            ], 
            "tags": [
                "beats-5015", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_logz_http_bulk_json_8070"
            ], 
            "ThreatActionTaken": [
                "IDS_ALERT_ACT_TAK_DEL", 
                "IDS_ALERT_ACT_TAK_DEL"
            ], 
            "ThreatCategory": [
                "av.detect", 
                "av.detect"
            ], 
            "AnalyzerEngineVersion": [
                "6010.8670", 
                "6010.8670"
            ], 
            "SourceHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "FirstActionStatus": [
                "True", 
                "True"
            ], 
            "TargetName": [
                "test.exe", 
                "test.exe"
            ], 
            "TargetFileName": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe"
            ], 
            "tenantId": "1", 
            "log": {
                "source": {
                    "address": "10.0.1.9:49874"
                }
            }, 
            "GMTTime": [
                "2020-02-23T15:43:40", 
                "2020-02-23T15:43:40"
            ], 
            "ThreatEventID": [
                "1027", 
                "1027"
            ], 
            "AMCoreContentVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "AnalyzerDATVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "timestamp": "2020-05-06T00:01:04.441+0000", 
            "NaturalLangDescription": [
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetNametest.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio"
            ], 
            "beat_agent": {
                "ephemeral_id": "8d15318f-3a3e-436c-a93e-1b6e8fec0cfb", 
                "type": "filebeat", 
                "hostname": "SecLinux", 
                "version": "7.5.0", 
                "id": "348cbd8b-b4ce-4531-b6d1-ab6beb37d65f"
            }, 
            "AnalyzerVersion": [
                "10.6.1", 
                "10.6.1"
            ], 
            "TargetUserName": [
                "WinSec3\\Logzio", 
                "WinSec3\\Logzio"
            ], 
            "TaskName": [
                "IDS_OAS_TASK_NAME", 
                "IDS_OAS_TASK_NAME"
            ], 
            "ThreatName": [
                "Trojan-FRTB!81DA244A770C", 
                "Trojan-FRTB!81DA244A770C"
            ], 
            "AnalyzerHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "EPOevent": {
                "SoftwareInfo": {
                    "CommonFields": {
                        "AnalyzerDATVersion": "3990.0", 
                        "Analyzer": "ENDP_AM_1060", 
                        "AnalyzerDetectionMethod": "On-Access Scan", 
                        "AnalyzerVersion": "10.6.1", 
                        "AnalyzerEngineVersion": "6010.8670", 
                        "AnalyzerHostName": "WinSec3", 
                        "AnalyzerName": "McAfee Endpoint Security"
                    }, 
                    "Event": {
                        "EventID": "1027", 
                        "GMTTime": "2020-02-23T15:43:40", 
                        "CustomFields": {
                            "DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                            "TargetFileSize": "249952", 
                            "SecondActionStatus": "false", 
                            "DurationBeforeDetection": "18", 
                            "Cleanable": "true", 
                            "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", 
                            "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", 
                            "TargetAccessTime": "2020-02-23T15:43:22Z", 
                            "AttackVectorType": "4", 
                            "ThreatDetectedOnCreation": "true", 
                            "FirstActionStatus": "true", 
                            "TargetName": "test.exe", 
                            "AMCoreContentVersion": "3990.0", 
                            "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                            "TaskName": "IDS_OAS_TASK_NAME", 
                            "TargetHash": "81da244a770c46ace2cf112214f8e75e", 
                            "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", 
                            "TargetCreateTime": "2020-02-23T15:43:21Z", 
                            "TargetModifyTime": "2020-02-23T15:43:22Z", 
                            "BladeName": "IDS_BLADE_NAME_SPB", 
                            "AnalyzerGTIQuery": "true", 
                            "AccessRequested_obj": {}, 
                            "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
                        }, 
                        "CommonFields": {
                            "ThreatType": "trojan", 
                            "ThreatEventID": "1027", 
                            "TargetHostName": "WinSec3", 
                            "DetectedUTC": "2020-02-23T15:43:40Z", 
                            "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                            "ThreatSeverity": "2", 
                            "ThreatCategory": "av.detect", 
                            "TargetUserName": "WinSec3\\Logzio", 
                            "SourceHostName": "WinSec3", 
                            "ThreatName": "Trojan-FRTB!81DA244A770C", 
                            "SourceProcessName": "C:\\Windows\\explorer.exe", 
                            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", 
                            "ThreatHandled": "true"
                        }, 
                        "Severity": "3"
                    }
                }, 
                "MachineInfo": {
                    "RawMACAddress": "000d3a373482", 
                    "UserName": "SYSTEM", 
                    "MachineName": "WinSec3", 
                    "OSName": "Windows 10 Workstation", 
                    "TimeZoneBias": "0", 
                    "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", 
                    "IPAddress": "10.0.1.10"
                }
            }, 
            "SecondAttemptedAction": [
                "IDS_ALERT_THACT_ATT_DEL", 
                "IDS_ALERT_THACT_ATT_DEL"
            ], 
            "EventID": [
                "1027", 
                "1027"
            ], 
            "input": {
                "type": "tcp"
            }, 
            "type": "mcafee_epo", 
            "tenantNodePath": "1\\2", 
            "TargetModifyTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "AnalyzerDetectionMethod": [
                "On-Access Scan", 
                "On-Access Scan"
            ], 
            "BladeName": [
                "IDS_BLADE_NAME_SPB", 
                "IDS_BLADE_NAME_SPB"
            ], 
            "ThreatSeverity": [
                "2", 
                "2"
            ], 
            "AnalyzerGTIQuery": [
                "True", 
                "True"
            ], 
            "AccessRequested": [
                "", 
                ""
            ], 
            "ecs": {
                "version": "1.1.0"
            }, 
            "ThreatHandled": [
                "True", 
                "True"
            ], 
            "TargetPath": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
            ], 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "ThreatDetectedOnCreation": [
                "True", 
                "True"
            ]
        }, 
        {
            "ThreatType": [
                "trojan", 
                "trojan"
            ], 
            "Severity": [
                "3", 
                "3"
            ], 
            "DetectionMessage": [
                "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                "IDS_OAS_DEFAULT_THREAT_MESSAGE"
            ], 
            "@timestamp": "2020-05-06T02:01:13.778+0000", 
            "TargetFileSize": [
                "249952", 
                "249952"
            ], 
            "domain": [
                "Win-Sec-2", 
                "Win-Sec-2"
            ], 
            "tenantGUID": "{00000000-0000-0000-0000-000000000000}", 
            "SecondActionStatus": [
                "False", 
                "False"
            ], 
            "EPOEvents": "EventFwd", 
            "DurationBeforeDetection": [
                "18", 
                "18"
            ], 
            "Cleanable": [
                "True", 
                "True"
            ], 
            "bpsId": "1", 
            "FirstAttemptedAction": [
                "IDS_ALERT_THACT_ATT_CLE", 
                "IDS_ALERT_THACT_ATT_CLE"
            ], 
            "SourceProcessName": [
                "C:\\Windows\\explorer.exe", 
                "C:\\Windows\\explorer.exe"
            ], 
            "AnalyzerName": [
                "McAfee Endpoint Security", 
                "McAfee Endpoint Security"
            ], 
            "AnalyzerContentCreationDate": [
                "2020-02-22T08:24:00Z", 
                "2020-02-22T08:24:00Z"
            ], 
            "TargetAccessTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "TargetCreateTime": [
                "2020-02-23T15:43:21Z", 
                "2020-02-23T15:43:21Z"
            ], 
            "TargetHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "logzio_codec": "plain", 
            "DetectedUTC": [
                "2020-02-23T15:43:40Z", 
                "2020-02-23T15:43:40Z"
            ], 
            "Analyzer": [
                "ENDP_AM_1060", 
                "ENDP_AM_1060"
            ], 
            "TargetHash": [
                "81da244a770c46ace2cf112214f8e75e", 
                "81da244a770c46ace2cf112214f8e75e"
            ], 
            "AttackVectorType": [
                "4", 
                "4"
            ], 
            "tags": [
                "beats-5015", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_logz_http_bulk_json_8070"
            ], 
            "ThreatActionTaken": [
                "IDS_ALERT_ACT_TAK_DEL", 
                "IDS_ALERT_ACT_TAK_DEL"
            ], 
            "ThreatCategory": [
                "av.detect", 
                "av.detect"
            ], 
            "AnalyzerEngineVersion": [
                "6010.8670", 
                "6010.8670"
            ], 
            "SourceHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "FirstActionStatus": [
                "True", 
                "True"
            ], 
            "TargetName": [
                "test.exe", 
                "test.exe"
            ], 
            "TargetFileName": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe"
            ], 
            "tenantId": "1", 
            "log": {
                "source": {
                    "address": "10.0.1.9:49874"
                }
            }, 
            "GMTTime": [
                "2020-02-23T15:43:40", 
                "2020-02-23T15:43:40"
            ], 
            "ThreatEventID": [
                "1027", 
                "1027"
            ], 
            "AMCoreContentVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "AnalyzerDATVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "timestamp": "2020-05-06T02:01:13.778+0000", 
            "NaturalLangDescription": [
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetNametest.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio"
            ], 
            "beat_agent": {
                "ephemeral_id": "8d15318f-3a3e-436c-a93e-1b6e8fec0cfb", 
                "type": "filebeat", 
                "hostname": "SecLinux", 
                "version": "7.5.0", 
                "id": "348cbd8b-b4ce-4531-b6d1-ab6beb37d65f"
            }, 
            "AnalyzerVersion": [
                "10.6.1", 
                "10.6.1"
            ], 
            "TargetUserName": [
                "WinSec3\\Logzio", 
                "WinSec3\\Logzio"
            ], 
            "TaskName": [
                "IDS_OAS_TASK_NAME", 
                "IDS_OAS_TASK_NAME"
            ], 
            "ThreatName": [
                "Trojan-FRTB!81DA244A770C", 
                "Trojan-FRTB!81DA244A770C"
            ], 
            "AnalyzerHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "EPOevent": {
                "SoftwareInfo": {
                    "CommonFields": {
                        "AnalyzerDATVersion": "3990.0", 
                        "Analyzer": "ENDP_AM_1060", 
                        "AnalyzerDetectionMethod": "On-Access Scan", 
                        "AnalyzerVersion": "10.6.1", 
                        "AnalyzerEngineVersion": "6010.8670", 
                        "AnalyzerHostName": "WinSec3", 
                        "AnalyzerName": "McAfee Endpoint Security"
                    }, 
                    "Event": {
                        "EventID": "1027", 
                        "GMTTime": "2020-02-23T15:43:40", 
                        "CustomFields": {
                            "DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                            "TargetFileSize": "249952", 
                            "SecondActionStatus": "false", 
                            "DurationBeforeDetection": "18", 
                            "Cleanable": "true", 
                            "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", 
                            "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", 
                            "TargetAccessTime": "2020-02-23T15:43:22Z", 
                            "AttackVectorType": "4", 
                            "ThreatDetectedOnCreation": "true", 
                            "FirstActionStatus": "true", 
                            "TargetName": "test.exe", 
                            "AMCoreContentVersion": "3990.0", 
                            "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                            "TaskName": "IDS_OAS_TASK_NAME", 
                            "TargetHash": "81da244a770c46ace2cf112214f8e75e", 
                            "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", 
                            "TargetCreateTime": "2020-02-23T15:43:21Z", 
                            "TargetModifyTime": "2020-02-23T15:43:22Z", 
                            "BladeName": "IDS_BLADE_NAME_SPB", 
                            "AnalyzerGTIQuery": "true", 
                            "AccessRequested_obj": {}, 
                            "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
                        }, 
                        "CommonFields": {
                            "ThreatType": "trojan", 
                            "ThreatEventID": "1027", 
                            "TargetHostName": "WinSec3", 
                            "DetectedUTC": "2020-02-23T15:43:40Z", 
                            "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                            "ThreatSeverity": "2", 
                            "ThreatCategory": "av.detect", 
                            "TargetUserName": "WinSec3\\Logzio", 
                            "SourceHostName": "WinSec3", 
                            "ThreatName": "Trojan-FRTB!81DA244A770C", 
                            "SourceProcessName": "C:\\Windows\\explorer.exe", 
                            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", 
                            "ThreatHandled": "true"
                        }, 
                        "Severity": "3"
                    }
                }, 
                "MachineInfo": {
                    "RawMACAddress": "000d3a373482", 
                    "UserName": "SYSTEM", 
                    "MachineName": "WinSec3", 
                    "OSName": "Windows 10 Workstation", 
                    "TimeZoneBias": "0", 
                    "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", 
                    "IPAddress": "10.0.1.10"
                }
            }, 
            "SecondAttemptedAction": [
                "IDS_ALERT_THACT_ATT_DEL", 
                "IDS_ALERT_THACT_ATT_DEL"
            ], 
            "EventID": [
                "1027", 
                "1027"
            ], 
            "input": {
                "type": "tcp"
            }, 
            "type": "mcafee_epo", 
            "tenantNodePath": "1\\2", 
            "TargetModifyTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "AnalyzerDetectionMethod": [
                "On-Access Scan", 
                "On-Access Scan"
            ], 
            "BladeName": [
                "IDS_BLADE_NAME_SPB", 
                "IDS_BLADE_NAME_SPB"
            ], 
            "ThreatSeverity": [
                "2", 
                "2"
            ], 
            "AnalyzerGTIQuery": [
                "True", 
                "True"
            ], 
            "AccessRequested": [
                "", 
                ""
            ], 
            "ecs": {
                "version": "1.1.0"
            }, 
            "ThreatHandled": [
                "True", 
                "True"
            ], 
            "TargetPath": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
            ], 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "ThreatDetectedOnCreation": [
                "True", 
                "True"
            ]
        }, 
        {
            "ThreatType": [
                "trojan", 
                "trojan"
            ], 
            "Severity": [
                "3", 
                "3"
            ], 
            "DetectionMessage": [
                "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                "IDS_OAS_DEFAULT_THREAT_MESSAGE"
            ], 
            "@timestamp": "2020-05-06T02:16:14.944+0000", 
            "TargetFileSize": [
                "249952", 
                "249952"
            ], 
            "domain": [
                "Win-Sec-2", 
                "Win-Sec-2"
            ], 
            "tenantGUID": "{00000000-0000-0000-0000-000000000000}", 
            "SecondActionStatus": [
                "False", 
                "False"
            ], 
            "EPOEvents": "EventFwd", 
            "DurationBeforeDetection": [
                "18", 
                "18"
            ], 
            "Cleanable": [
                "True", 
                "True"
            ], 
            "bpsId": "1", 
            "FirstAttemptedAction": [
                "IDS_ALERT_THACT_ATT_CLE", 
                "IDS_ALERT_THACT_ATT_CLE"
            ], 
            "SourceProcessName": [
                "C:\\Windows\\explorer.exe", 
                "C:\\Windows\\explorer.exe"
            ], 
            "AnalyzerName": [
                "McAfee Endpoint Security", 
                "McAfee Endpoint Security"
            ], 
            "AnalyzerContentCreationDate": [
                "2020-02-22T08:24:00Z", 
                "2020-02-22T08:24:00Z"
            ], 
            "TargetAccessTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "TargetCreateTime": [
                "2020-02-23T15:43:21Z", 
                "2020-02-23T15:43:21Z"
            ], 
            "TargetHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "logzio_codec": "plain", 
            "DetectedUTC": [
                "2020-02-23T15:43:40Z", 
                "2020-02-23T15:43:40Z"
            ], 
            "Analyzer": [
                "ENDP_AM_1060", 
                "ENDP_AM_1060"
            ], 
            "TargetHash": [
                "81da244a770c46ace2cf112214f8e75e", 
                "81da244a770c46ace2cf112214f8e75e"
            ], 
            "AttackVectorType": [
                "4", 
                "4"
            ], 
            "tags": [
                "beats-5015", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_logz_http_bulk_json_8070"
            ], 
            "ThreatActionTaken": [
                "IDS_ALERT_ACT_TAK_DEL", 
                "IDS_ALERT_ACT_TAK_DEL"
            ], 
            "ThreatCategory": [
                "av.detect", 
                "av.detect"
            ], 
            "AnalyzerEngineVersion": [
                "6010.8670", 
                "6010.8670"
            ], 
            "SourceHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "FirstActionStatus": [
                "True", 
                "True"
            ], 
            "TargetName": [
                "test.exe", 
                "test.exe"
            ], 
            "TargetFileName": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe"
            ], 
            "tenantId": "1", 
            "log": {
                "source": {
                    "address": "10.0.1.9:49874"
                }
            }, 
            "GMTTime": [
                "2020-02-23T15:43:40", 
                "2020-02-23T15:43:40"
            ], 
            "ThreatEventID": [
                "1027", 
                "1027"
            ], 
            "AMCoreContentVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "AnalyzerDATVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "timestamp": "2020-05-06T02:16:14.944+0000", 
            "NaturalLangDescription": [
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetNametest.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio"
            ], 
            "beat_agent": {
                "ephemeral_id": "8d15318f-3a3e-436c-a93e-1b6e8fec0cfb", 
                "type": "filebeat", 
                "hostname": "SecLinux", 
                "version": "7.5.0", 
                "id": "348cbd8b-b4ce-4531-b6d1-ab6beb37d65f"
            }, 
            "AnalyzerVersion": [
                "10.6.1", 
                "10.6.1"
            ], 
            "TargetUserName": [
                "WinSec3\\Logzio", 
                "WinSec3\\Logzio"
            ], 
            "TaskName": [
                "IDS_OAS_TASK_NAME", 
                "IDS_OAS_TASK_NAME"
            ], 
            "ThreatName": [
                "Trojan-FRTB!81DA244A770C", 
                "Trojan-FRTB!81DA244A770C"
            ], 
            "AnalyzerHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "EPOevent": {
                "SoftwareInfo": {
                    "CommonFields": {
                        "AnalyzerDATVersion": "3990.0", 
                        "Analyzer": "ENDP_AM_1060", 
                        "AnalyzerDetectionMethod": "On-Access Scan", 
                        "AnalyzerVersion": "10.6.1", 
                        "AnalyzerEngineVersion": "6010.8670", 
                        "AnalyzerHostName": "WinSec3", 
                        "AnalyzerName": "McAfee Endpoint Security"
                    }, 
                    "Event": {
                        "EventID": "1027", 
                        "GMTTime": "2020-02-23T15:43:40", 
                        "CustomFields": {
                            "DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                            "TargetFileSize": "249952", 
                            "SecondActionStatus": "false", 
                            "DurationBeforeDetection": "18", 
                            "Cleanable": "true", 
                            "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", 
                            "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", 
                            "TargetAccessTime": "2020-02-23T15:43:22Z", 
                            "AttackVectorType": "4", 
                            "ThreatDetectedOnCreation": "true", 
                            "FirstActionStatus": "true", 
                            "TargetName": "test.exe", 
                            "AMCoreContentVersion": "3990.0", 
                            "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                            "TaskName": "IDS_OAS_TASK_NAME", 
                            "TargetHash": "81da244a770c46ace2cf112214f8e75e", 
                            "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", 
                            "TargetCreateTime": "2020-02-23T15:43:21Z", 
                            "TargetModifyTime": "2020-02-23T15:43:22Z", 
                            "BladeName": "IDS_BLADE_NAME_SPB", 
                            "AnalyzerGTIQuery": "true", 
                            "AccessRequested_obj": {}, 
                            "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
                        }, 
                        "CommonFields": {
                            "ThreatType": "trojan", 
                            "ThreatEventID": "1027", 
                            "TargetHostName": "WinSec3", 
                            "DetectedUTC": "2020-02-23T15:43:40Z", 
                            "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                            "ThreatSeverity": "2", 
                            "ThreatCategory": "av.detect", 
                            "TargetUserName": "WinSec3\\Logzio", 
                            "SourceHostName": "WinSec3", 
                            "ThreatName": "Trojan-FRTB!81DA244A770C", 
                            "SourceProcessName": "C:\\Windows\\explorer.exe", 
                            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", 
                            "ThreatHandled": "true"
                        }, 
                        "Severity": "3"
                    }
                }, 
                "MachineInfo": {
                    "RawMACAddress": "000d3a373482", 
                    "UserName": "SYSTEM", 
                    "MachineName": "WinSec3", 
                    "OSName": "Windows 10 Workstation", 
                    "TimeZoneBias": "0", 
                    "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", 
                    "IPAddress": "10.0.1.10"
                }
            }, 
            "SecondAttemptedAction": [
                "IDS_ALERT_THACT_ATT_DEL", 
                "IDS_ALERT_THACT_ATT_DEL"
            ], 
            "EventID": [
                "1027", 
                "1027"
            ], 
            "input": {
                "type": "tcp"
            }, 
            "type": "mcafee_epo", 
            "tenantNodePath": "1\\2", 
            "TargetModifyTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "AnalyzerDetectionMethod": [
                "On-Access Scan", 
                "On-Access Scan"
            ], 
            "BladeName": [
                "IDS_BLADE_NAME_SPB", 
                "IDS_BLADE_NAME_SPB"
            ], 
            "ThreatSeverity": [
                "2", 
                "2"
            ], 
            "AnalyzerGTIQuery": [
                "True", 
                "True"
            ], 
            "AccessRequested": [
                "", 
                ""
            ], 
            "ecs": {
                "version": "1.1.0"
            }, 
            "ThreatHandled": [
                "True", 
                "True"
            ], 
            "TargetPath": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
            ], 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "ThreatDetectedOnCreation": [
                "True", 
                "True"
            ]
        }, 
        {
            "ThreatType": [
                "trojan", 
                "trojan"
            ], 
            "Severity": [
                "3", 
                "3"
            ], 
            "DetectionMessage": [
                "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                "IDS_OAS_DEFAULT_THREAT_MESSAGE"
            ], 
            "@timestamp": "2020-05-06T02:31:16.087+0000", 
            "TargetFileSize": [
                "249952", 
                "249952"
            ], 
            "domain": [
                "Win-Sec-2", 
                "Win-Sec-2"
            ], 
            "tenantGUID": "{00000000-0000-0000-0000-000000000000}", 
            "SecondActionStatus": [
                "False", 
                "False"
            ], 
            "EPOEvents": "EventFwd", 
            "DurationBeforeDetection": [
                "18", 
                "18"
            ], 
            "Cleanable": [
                "True", 
                "True"
            ], 
            "bpsId": "1", 
            "FirstAttemptedAction": [
                "IDS_ALERT_THACT_ATT_CLE", 
                "IDS_ALERT_THACT_ATT_CLE"
            ], 
            "SourceProcessName": [
                "C:\\Windows\\explorer.exe", 
                "C:\\Windows\\explorer.exe"
            ], 
            "AnalyzerName": [
                "McAfee Endpoint Security", 
                "McAfee Endpoint Security"
            ], 
            "AnalyzerContentCreationDate": [
                "2020-02-22T08:24:00Z", 
                "2020-02-22T08:24:00Z"
            ], 
            "TargetAccessTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "TargetCreateTime": [
                "2020-02-23T15:43:21Z", 
                "2020-02-23T15:43:21Z"
            ], 
            "TargetHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "logzio_codec": "plain", 
            "DetectedUTC": [
                "2020-02-23T15:43:40Z", 
                "2020-02-23T15:43:40Z"
            ], 
            "Analyzer": [
                "ENDP_AM_1060", 
                "ENDP_AM_1060"
            ], 
            "TargetHash": [
                "81da244a770c46ace2cf112214f8e75e", 
                "81da244a770c46ace2cf112214f8e75e"
            ], 
            "AttackVectorType": [
                "4", 
                "4"
            ], 
            "tags": [
                "beats-5015", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_logz_http_bulk_json_8070"
            ], 
            "ThreatActionTaken": [
                "IDS_ALERT_ACT_TAK_DEL", 
                "IDS_ALERT_ACT_TAK_DEL"
            ], 
            "ThreatCategory": [
                "av.detect", 
                "av.detect"
            ], 
            "AnalyzerEngineVersion": [
                "6010.8670", 
                "6010.8670"
            ], 
            "SourceHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "FirstActionStatus": [
                "True", 
                "True"
            ], 
            "TargetName": [
                "test.exe", 
                "test.exe"
            ], 
            "TargetFileName": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe"
            ], 
            "tenantId": "1", 
            "log": {
                "source": {
                    "address": "10.0.1.9:49874"
                }
            }, 
            "GMTTime": [
                "2020-02-23T15:43:40", 
                "2020-02-23T15:43:40"
            ], 
            "ThreatEventID": [
                "1027", 
                "1027"
            ], 
            "AMCoreContentVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "AnalyzerDATVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "timestamp": "2020-05-06T02:31:16.087+0000", 
            "NaturalLangDescription": [
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetNametest.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio"
            ], 
            "beat_agent": {
                "ephemeral_id": "8d15318f-3a3e-436c-a93e-1b6e8fec0cfb", 
                "type": "filebeat", 
                "hostname": "SecLinux", 
                "version": "7.5.0", 
                "id": "348cbd8b-b4ce-4531-b6d1-ab6beb37d65f"
            }, 
            "AnalyzerVersion": [
                "10.6.1", 
                "10.6.1"
            ], 
            "TargetUserName": [
                "WinSec3\\Logzio", 
                "WinSec3\\Logzio"
            ], 
            "TaskName": [
                "IDS_OAS_TASK_NAME", 
                "IDS_OAS_TASK_NAME"
            ], 
            "ThreatName": [
                "Trojan-FRTB!81DA244A770C", 
                "Trojan-FRTB!81DA244A770C"
            ], 
            "AnalyzerHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "EPOevent": {
                "SoftwareInfo": {
                    "CommonFields": {
                        "AnalyzerDATVersion": "3990.0", 
                        "Analyzer": "ENDP_AM_1060", 
                        "AnalyzerDetectionMethod": "On-Access Scan", 
                        "AnalyzerVersion": "10.6.1", 
                        "AnalyzerEngineVersion": "6010.8670", 
                        "AnalyzerHostName": "WinSec3", 
                        "AnalyzerName": "McAfee Endpoint Security"
                    }, 
                    "Event": {
                        "EventID": "1027", 
                        "GMTTime": "2020-02-23T15:43:40", 
                        "CustomFields": {
                            "DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                            "TargetFileSize": "249952", 
                            "SecondActionStatus": "false", 
                            "DurationBeforeDetection": "18", 
                            "Cleanable": "true", 
                            "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", 
                            "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", 
                            "TargetAccessTime": "2020-02-23T15:43:22Z", 
                            "AttackVectorType": "4", 
                            "ThreatDetectedOnCreation": "true", 
                            "FirstActionStatus": "true", 
                            "TargetName": "test.exe", 
                            "AMCoreContentVersion": "3990.0", 
                            "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                            "TaskName": "IDS_OAS_TASK_NAME", 
                            "TargetHash": "81da244a770c46ace2cf112214f8e75e", 
                            "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", 
                            "TargetCreateTime": "2020-02-23T15:43:21Z", 
                            "TargetModifyTime": "2020-02-23T15:43:22Z", 
                            "BladeName": "IDS_BLADE_NAME_SPB", 
                            "AnalyzerGTIQuery": "true", 
                            "AccessRequested_obj": {}, 
                            "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
                        }, 
                        "CommonFields": {
                            "ThreatType": "trojan", 
                            "ThreatEventID": "1027", 
                            "TargetHostName": "WinSec3", 
                            "DetectedUTC": "2020-02-23T15:43:40Z", 
                            "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                            "ThreatSeverity": "2", 
                            "ThreatCategory": "av.detect", 
                            "TargetUserName": "WinSec3\\Logzio", 
                            "SourceHostName": "WinSec3", 
                            "ThreatName": "Trojan-FRTB!81DA244A770C", 
                            "SourceProcessName": "C:\\Windows\\explorer.exe", 
                            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", 
                            "ThreatHandled": "true"
                        }, 
                        "Severity": "3"
                    }
                }, 
                "MachineInfo": {
                    "RawMACAddress": "000d3a373482", 
                    "UserName": "SYSTEM", 
                    "MachineName": "WinSec3", 
                    "OSName": "Windows 10 Workstation", 
                    "TimeZoneBias": "0", 
                    "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", 
                    "IPAddress": "10.0.1.10"
                }
            }, 
            "SecondAttemptedAction": [
                "IDS_ALERT_THACT_ATT_DEL", 
                "IDS_ALERT_THACT_ATT_DEL"
            ], 
            "EventID": [
                "1027", 
                "1027"
            ], 
            "input": {
                "type": "tcp"
            }, 
            "type": "mcafee_epo", 
            "tenantNodePath": "1\\2", 
            "TargetModifyTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "AnalyzerDetectionMethod": [
                "On-Access Scan", 
                "On-Access Scan"
            ], 
            "BladeName": [
                "IDS_BLADE_NAME_SPB", 
                "IDS_BLADE_NAME_SPB"
            ], 
            "ThreatSeverity": [
                "2", 
                "2"
            ], 
            "AnalyzerGTIQuery": [
                "True", 
                "True"
            ], 
            "AccessRequested": [
                "", 
                ""
            ], 
            "ecs": {
                "version": "1.1.0"
            }, 
            "ThreatHandled": [
                "True", 
                "True"
            ], 
            "TargetPath": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
            ], 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "ThreatDetectedOnCreation": [
                "True", 
                "True"
            ]
        }, 
        {
            "ThreatType": [
                "trojan", 
                "trojan"
            ], 
            "Severity": [
                "3", 
                "3"
            ], 
            "DetectionMessage": [
                "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                "IDS_OAS_DEFAULT_THREAT_MESSAGE"
            ], 
            "@timestamp": "2020-05-06T01:46:12.663+0000", 
            "TargetFileSize": [
                "249952", 
                "249952"
            ], 
            "domain": [
                "Win-Sec-2", 
                "Win-Sec-2"
            ], 
            "tenantGUID": "{00000000-0000-0000-0000-000000000000}", 
            "SecondActionStatus": [
                "False", 
                "False"
            ], 
            "EPOEvents": "EventFwd", 
            "DurationBeforeDetection": [
                "18", 
                "18"
            ], 
            "Cleanable": [
                "True", 
                "True"
            ], 
            "bpsId": "1", 
            "FirstAttemptedAction": [
                "IDS_ALERT_THACT_ATT_CLE", 
                "IDS_ALERT_THACT_ATT_CLE"
            ], 
            "SourceProcessName": [
                "C:\\Windows\\explorer.exe", 
                "C:\\Windows\\explorer.exe"
            ], 
            "AnalyzerName": [
                "McAfee Endpoint Security", 
                "McAfee Endpoint Security"
            ], 
            "AnalyzerContentCreationDate": [
                "2020-02-22T08:24:00Z", 
                "2020-02-22T08:24:00Z"
            ], 
            "TargetAccessTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "TargetCreateTime": [
                "2020-02-23T15:43:21Z", 
                "2020-02-23T15:43:21Z"
            ], 
            "TargetHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "logzio_codec": "plain", 
            "DetectedUTC": [
                "2020-02-23T15:43:40Z", 
                "2020-02-23T15:43:40Z"
            ], 
            "Analyzer": [
                "ENDP_AM_1060", 
                "ENDP_AM_1060"
            ], 
            "TargetHash": [
                "81da244a770c46ace2cf112214f8e75e", 
                "81da244a770c46ace2cf112214f8e75e"
            ], 
            "AttackVectorType": [
                "4", 
                "4"
            ], 
            "tags": [
                "beats-5015", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_logz_http_bulk_json_8070"
            ], 
            "ThreatActionTaken": [
                "IDS_ALERT_ACT_TAK_DEL", 
                "IDS_ALERT_ACT_TAK_DEL"
            ], 
            "ThreatCategory": [
                "av.detect", 
                "av.detect"
            ], 
            "AnalyzerEngineVersion": [
                "6010.8670", 
                "6010.8670"
            ], 
            "SourceHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "FirstActionStatus": [
                "True", 
                "True"
            ], 
            "TargetName": [
                "test.exe", 
                "test.exe"
            ], 
            "TargetFileName": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe"
            ], 
            "tenantId": "1", 
            "log": {
                "source": {
                    "address": "10.0.1.9:49874"
                }
            }, 
            "GMTTime": [
                "2020-02-23T15:43:40", 
                "2020-02-23T15:43:40"
            ], 
            "ThreatEventID": [
                "1027", 
                "1027"
            ], 
            "AMCoreContentVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "AnalyzerDATVersion": [
                "3990.0", 
                "3990.0"
            ], 
            "timestamp": "2020-05-06T01:46:12.663+0000", 
            "NaturalLangDescription": [
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetNametest.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio"
            ], 
            "beat_agent": {
                "ephemeral_id": "8d15318f-3a3e-436c-a93e-1b6e8fec0cfb", 
                "type": "filebeat", 
                "hostname": "SecLinux", 
                "version": "7.5.0", 
                "id": "348cbd8b-b4ce-4531-b6d1-ab6beb37d65f"
            }, 
            "AnalyzerVersion": [
                "10.6.1", 
                "10.6.1"
            ], 
            "TargetUserName": [
                "WinSec3\\Logzio", 
                "WinSec3\\Logzio"
            ], 
            "TaskName": [
                "IDS_OAS_TASK_NAME", 
                "IDS_OAS_TASK_NAME"
            ], 
            "ThreatName": [
                "Trojan-FRTB!81DA244A770C", 
                "Trojan-FRTB!81DA244A770C"
            ], 
            "AnalyzerHostName": [
                "WinSec3", 
                "WinSec3"
            ], 
            "EPOevent": {
                "SoftwareInfo": {
                    "CommonFields": {
                        "AnalyzerDATVersion": "3990.0", 
                        "Analyzer": "ENDP_AM_1060", 
                        "AnalyzerDetectionMethod": "On-Access Scan", 
                        "AnalyzerVersion": "10.6.1", 
                        "AnalyzerEngineVersion": "6010.8670", 
                        "AnalyzerHostName": "WinSec3", 
                        "AnalyzerName": "McAfee Endpoint Security"
                    }, 
                    "Event": {
                        "EventID": "1027", 
                        "GMTTime": "2020-02-23T15:43:40", 
                        "CustomFields": {
                            "DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", 
                            "TargetFileSize": "249952", 
                            "SecondActionStatus": "false", 
                            "DurationBeforeDetection": "18", 
                            "Cleanable": "true", 
                            "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", 
                            "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", 
                            "TargetAccessTime": "2020-02-23T15:43:22Z", 
                            "AttackVectorType": "4", 
                            "ThreatDetectedOnCreation": "true", 
                            "FirstActionStatus": "true", 
                            "TargetName": "test.exe", 
                            "AMCoreContentVersion": "3990.0", 
                            "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL|TargetName=test.exe|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth|ThreatName=Trojan-FRTB!81DA244A770C|SourceProcessName=C:\\Windows\\explorer.exe|ThreatType=trojan|TargetUserName=WinSec3\\Logzio", 
                            "TaskName": "IDS_OAS_TASK_NAME", 
                            "TargetHash": "81da244a770c46ace2cf112214f8e75e", 
                            "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", 
                            "TargetCreateTime": "2020-02-23T15:43:21Z", 
                            "TargetModifyTime": "2020-02-23T15:43:22Z", 
                            "BladeName": "IDS_BLADE_NAME_SPB", 
                            "AnalyzerGTIQuery": "true", 
                            "AccessRequested_obj": {}, 
                            "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
                        }, 
                        "CommonFields": {
                            "ThreatType": "trojan", 
                            "ThreatEventID": "1027", 
                            "TargetHostName": "WinSec3", 
                            "DetectedUTC": "2020-02-23T15:43:40Z", 
                            "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", 
                            "ThreatSeverity": "2", 
                            "ThreatCategory": "av.detect", 
                            "TargetUserName": "WinSec3\\Logzio", 
                            "SourceHostName": "WinSec3", 
                            "ThreatName": "Trojan-FRTB!81DA244A770C", 
                            "SourceProcessName": "C:\\Windows\\explorer.exe", 
                            "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", 
                            "ThreatHandled": "true"
                        }, 
                        "Severity": "3"
                    }
                }, 
                "MachineInfo": {
                    "RawMACAddress": "000d3a373482", 
                    "UserName": "SYSTEM", 
                    "MachineName": "WinSec3", 
                    "OSName": "Windows 10 Workstation", 
                    "TimeZoneBias": "0", 
                    "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", 
                    "IPAddress": "10.0.1.10"
                }
            }, 
            "SecondAttemptedAction": [
                "IDS_ALERT_THACT_ATT_DEL", 
                "IDS_ALERT_THACT_ATT_DEL"
            ], 
            "EventID": [
                "1027", 
                "1027"
            ], 
            "input": {
                "type": "tcp"
            }, 
            "type": "mcafee_epo", 
            "tenantNodePath": "1\\2", 
            "TargetModifyTime": [
                "2020-02-23T15:43:22Z", 
                "2020-02-23T15:43:22Z"
            ], 
            "AnalyzerDetectionMethod": [
                "On-Access Scan", 
                "On-Access Scan"
            ], 
            "BladeName": [
                "IDS_BLADE_NAME_SPB", 
                "IDS_BLADE_NAME_SPB"
            ], 
            "ThreatSeverity": [
                "2", 
                "2"
            ], 
            "AnalyzerGTIQuery": [
                "True", 
                "True"
            ], 
            "AccessRequested": [
                "", 
                ""
            ], 
            "ecs": {
                "version": "1.1.0"
            }, 
            "ThreatHandled": [
                "True", 
                "True"
            ], 
            "TargetPath": [
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth", 
                "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"
            ], 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "ThreatDetectedOnCreation": [
                "True", 
                "True"
            ]
        }
    ]
}
```

##### Human Readable Output
### Logs
|@metadata|@timestamp|AMCoreContentVersion|AccessRequested|Analyzer|AnalyzerContentCreationDate|AnalyzerDATVersion|AnalyzerDetectionMethod|AnalyzerEngineVersion|AnalyzerGTIQuery|AnalyzerHostName|AnalyzerName|AnalyzerVersion|AttackVectorType|BladeName|Cleanable|DetectedUTC|DetectionMessage|DurationBeforeDetection|EPOEvents|EPOevent|EventID|FirstActionStatus|FirstAttemptedAction|GMTTime|NaturalLangDescription|SecondActionStatus|SecondAttemptedAction|Severity|SourceHostName|SourceProcessName|TargetAccessTime|TargetCreateTime|TargetFileName|TargetFileSize|TargetHash|TargetHostName|TargetModifyTime|TargetName|TargetPath|TargetUserName|TaskName|ThreatActionTaken|ThreatCategory|ThreatDetectedOnCreation|ThreatEventID|ThreatHandled|ThreatName|ThreatSeverity|ThreatType|beat_agent|bpsId|domain|ecs|input|log|logzio_codec|tags|tenantGUID|tenantId|tenantNodePath|timestamp|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| beat: filebeat  version: 7.5.0 type: _doc | 2020-05-06T00:01:04.441+0000 | 3990.0, 3990.0 | ,  | ENDP_AM_1060, ENDP_AM_1060 | 2020-02-22T08:24:00Z, 2020-02-22T08:24:00Z | 3990.0, 3990.0 | On-Access Scan, On-Access Scan | 6010.8670, 6010.8670 | True, True | WinSec3, WinSec3 | McAfee Endpoint Security, McAfee Endpoint Security | 10.6.1, 10.6.1 | 4, 4 | IDS_BLADE_NAME_SPB, IDS_BLADE_NAME_SPB | True, True | 2020-02-23T15:43:40Z, 2020-02-23T15:43:40Z | IDS_OAS_DEFAULT_THREAT_MESSAGE, IDS_OAS_DEFAULT_THREAT_MESSAGE | 18, 18 | EventFwd | SoftwareInfo: {"CommonFields": {"AnalyzerDATVersion": "3990.0", "Analyzer": "ENDP_AM_1060", "AnalyzerDetectionMethod": "On-Access Scan", "AnalyzerVersion": "10.6.1", "AnalyzerEngineVersion": "6010.8670", "AnalyzerHostName": "WinSec3", "AnalyzerName": "McAfee Endpoint Security"}, "Event": {"EventID": "1027", "GMTTime": "2020-02-23T15:43:40", "CustomFields": {"DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", "TargetFileSize": "249952", "TargetModifyTime": "2020-02-23T15:43:22Z", "DurationBeforeDetection": "18", "Cleanable": "true", "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", "TargetAccessTime": "2020-02-23T15:43:22Z", "AttackVectorType": "4", "ThreatDetectedOnCreation": "true", "FirstActionStatus": "true", "TargetName": "test.exe", "AMCoreContentVersion": "3990.0", "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\\Windows\\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\\Logzio", "TaskName": "IDS_OAS_TASK_NAME", "TargetHash": "81da244a770c46ace2cf112214f8e75e", "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", "TargetCreateTime": "2020-02-23T15:43:21Z", "SecondActionStatus": "false", "BladeName": "IDS_BLADE_NAME_SPB", "AnalyzerGTIQuery": "true", "AccessRequested_obj": {}, "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"}, "CommonFields": {"ThreatType": "trojan", "TargetHostName": "WinSec3", "DetectedUTC": "2020-02-23T15:43:40Z", "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", "SourceHostName": "WinSec3", "ThreatSeverity": "2", "ThreatCategory": "av.detect", "TargetUserName": "WinSec3\\Logzio", "SourceProcessName": "C:\\Windows\\explorer.exe", "ThreatName": "Trojan-FRTB!81DA244A770C", "ThreatEventID": "1027", "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", "ThreatHandled": "true"}, "Severity": "3"}} MachineInfo: {"RawMACAddress": "000d3a373482", "UserName": "SYSTEM", "MachineName": "WinSec3", "OSName": "Windows 10 Workstation", "TimeZoneBias": "0", "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", "IPAddress": "10.0.1.10"} | 1027, 1027 | True, True | IDS_ALERT_THACT_ATT_CLE, IDS_ALERT_THACT_ATT_CLE | 2020-02-23T15:43:40, 2020-02-23T15:43:40 | IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio, IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetNametest.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio | False, False | IDS_ALERT_THACT_ATT_DEL, IDS_ALERT_THACT_ATT_DEL | 3, 3 | WinSec3, WinSec3 | C:\Windows\explorer.exe, C:\Windows\explorer.exe | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | 2020-02-23T15:43:21Z, 2020-02-23T15:43:21Z | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe | 249952, 249952 | 81da244a770c46ace2cf112214f8e75e, 81da244a770c46ace2cf112214f8e75e | WinSec3, WinSec3 | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | test.exe, test.exe | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth | WinSec3\Logzio, WinSec3\Logzio | IDS_OAS_TASK_NAME, IDS_OAS_TASK_NAME | IDS_ALERT_ACT_TAK_DEL, IDS_ALERT_ACT_TAK_DEL | av.detect, av.detect | True, True | 1027, 1027 | True, True | Trojan-FRTB!81DA244A770C, Trojan-FRTB!81DA244A770C | 2, 2 | trojan, trojan | ephemeral_id: 8d15318f-3a3e-436c-a93e-1b6e8fec0cfb type: filebeat hostname: SecLinux version: 7.5.0 id: 348cbd8b-b4ce-4531-b6d1-ab6beb37d65f | 1 | Win-Sec-2, Win-Sec-2 | version: 1.1.0 | type: tcp | source: {"address": "10.0.1.9:49874"} | plain | beats-5015, _grokparsefailure, _grokparsefailure, _logz_http_bulk_json_8070 | {00000000-0000-0000-0000-000000000000} | 1 | 1\2 | 2020-05-06T00:01:04.441+0000 | mcafee_epo |
| beat: filebeat  version: 7.5.0 type: _doc | 2020-05-06T02:01:13.778+0000 | 3990.0, 3990.0 | ,  | ENDP_AM_1060, ENDP_AM_1060 | 2020-02-22T08:24:00Z, 2020-02-22T08:24:00Z | 3990.0, 3990.0 | On-Access Scan, On-Access Scan | 6010.8670, 6010.8670 | True, True | WinSec3, WinSec3 | McAfee Endpoint Security, McAfee Endpoint Security | 10.6.1, 10.6.1 | 4, 4 | IDS_BLADE_NAME_SPB, IDS_BLADE_NAME_SPB | True, True | 2020-02-23T15:43:40Z, 2020-02-23T15:43:40Z | IDS_OAS_DEFAULT_THREAT_MESSAGE, IDS_OAS_DEFAULT_THREAT_MESSAGE | 18, 18 | EventFwd | SoftwareInfo: {"CommonFields": {"AnalyzerDATVersion": "3990.0", "Analyzer": "ENDP_AM_1060", "AnalyzerDetectionMethod": "On-Access Scan", "AnalyzerVersion": "10.6.1", "AnalyzerEngineVersion": "6010.8670", "AnalyzerHostName": "WinSec3", "AnalyzerName": "McAfee Endpoint Security"}, "Event": {"EventID": "1027", "GMTTime": "2020-02-23T15:43:40", "CustomFields": {"DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", "TargetFileSize": "249952", "TargetModifyTime": "2020-02-23T15:43:22Z", "DurationBeforeDetection": "18", "Cleanable": "true", "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", "TargetAccessTime": "2020-02-23T15:43:22Z", "AttackVectorType": "4", "ThreatDetectedOnCreation": "true", "FirstActionStatus": "true", "TargetName": "test.exe", "AMCoreContentVersion": "3990.0", "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\\Windows\\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\\Logzio", "TaskName": "IDS_OAS_TASK_NAME", "TargetHash": "81da244a770c46ace2cf112214f8e75e", "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", "TargetCreateTime": "2020-02-23T15:43:21Z", "SecondActionStatus": "false", "BladeName": "IDS_BLADE_NAME_SPB", "AnalyzerGTIQuery": "true", "AccessRequested_obj": {}, "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"}, "CommonFields": {"ThreatType": "trojan", "TargetHostName": "WinSec3", "DetectedUTC": "2020-02-23T15:43:40Z", "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", "SourceHostName": "WinSec3", "ThreatSeverity": "2", "ThreatCategory": "av.detect", "TargetUserName": "WinSec3\\Logzio", "SourceProcessName": "C:\\Windows\\explorer.exe", "ThreatName": "Trojan-FRTB!81DA244A770C", "ThreatEventID": "1027", "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", "ThreatHandled": "true"}, "Severity": "3"}} MachineInfo: {"RawMACAddress": "000d3a373482", "UserName": "SYSTEM", "MachineName": "WinSec3", "OSName": "Windows 10 Workstation", "TimeZoneBias": "0", "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", "IPAddress": "10.0.1.10"} | 1027, 1027 | True, True | IDS_ALERT_THACT_ATT_CLE, IDS_ALERT_THACT_ATT_CLE | 2020-02-23T15:43:40, 2020-02-23T15:43:40 | IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio, IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetNametest.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio | False, False | IDS_ALERT_THACT_ATT_DEL, IDS_ALERT_THACT_ATT_DEL | 3, 3 | WinSec3, WinSec3 | C:\Windows\explorer.exe, C:\Windows\explorer.exe | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | 2020-02-23T15:43:21Z, 2020-02-23T15:43:21Z | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe | 249952, 249952 | 81da244a770c46ace2cf112214f8e75e, 81da244a770c46ace2cf112214f8e75e | WinSec3, WinSec3 | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | test.exe, test.exe | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth | WinSec3\Logzio, WinSec3\Logzio | IDS_OAS_TASK_NAME, IDS_OAS_TASK_NAME | IDS_ALERT_ACT_TAK_DEL, IDS_ALERT_ACT_TAK_DEL | av.detect, av.detect | True, True | 1027, 1027 | True, True | Trojan-FRTB!81DA244A770C, Trojan-FRTB!81DA244A770C | 2, 2 | trojan, trojan | ephemeral_id: 8d15318f-3a3e-436c-a93e-1b6e8fec0cfb type: filebeat hostname: SecLinux version: 7.5.0 id: 348cbd8b-b4ce-4531-b6d1-ab6beb37d65f | 1 | Win-Sec-2, Win-Sec-2 | version: 1.1.0 | type: tcp | source: {"address": "10.0.1.9:49874"} | plain | beats-5015, _grokparsefailure, _grokparsefailure, _logz_http_bulk_json_8070 | {00000000-0000-0000-0000-000000000000} | 1 | 1\2 | 2020-05-06T02:01:13.778+0000 | mcafee_epo |
| beat: filebeat  version: 7.5.0 type: _doc | 2020-05-06T02:16:14.944+0000 | 3990.0, 3990.0 | ,  | ENDP_AM_1060, ENDP_AM_1060 | 2020-02-22T08:24:00Z, 2020-02-22T08:24:00Z | 3990.0, 3990.0 | On-Access Scan, On-Access Scan | 6010.8670, 6010.8670 | True, True | WinSec3, WinSec3 | McAfee Endpoint Security, McAfee Endpoint Security | 10.6.1, 10.6.1 | 4, 4 | IDS_BLADE_NAME_SPB, IDS_BLADE_NAME_SPB | True, True | 2020-02-23T15:43:40Z, 2020-02-23T15:43:40Z | IDS_OAS_DEFAULT_THREAT_MESSAGE, IDS_OAS_DEFAULT_THREAT_MESSAGE | 18, 18 | EventFwd | SoftwareInfo: {"CommonFields": {"AnalyzerDATVersion": "3990.0", "Analyzer": "ENDP_AM_1060", "AnalyzerDetectionMethod": "On-Access Scan", "AnalyzerVersion": "10.6.1", "AnalyzerEngineVersion": "6010.8670", "AnalyzerHostName": "WinSec3", "AnalyzerName": "McAfee Endpoint Security"}, "Event": {"EventID": "1027", "GMTTime": "2020-02-23T15:43:40", "CustomFields": {"DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", "TargetFileSize": "249952", "TargetModifyTime": "2020-02-23T15:43:22Z", "DurationBeforeDetection": "18", "Cleanable": "true", "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", "TargetAccessTime": "2020-02-23T15:43:22Z", "AttackVectorType": "4", "ThreatDetectedOnCreation": "true", "FirstActionStatus": "true", "TargetName": "test.exe", "AMCoreContentVersion": "3990.0", "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\\Windows\\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\\Logzio", "TaskName": "IDS_OAS_TASK_NAME", "TargetHash": "81da244a770c46ace2cf112214f8e75e", "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", "TargetCreateTime": "2020-02-23T15:43:21Z", "SecondActionStatus": "false", "BladeName": "IDS_BLADE_NAME_SPB", "AnalyzerGTIQuery": "true", "AccessRequested_obj": {}, "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"}, "CommonFields": {"ThreatType": "trojan", "TargetHostName": "WinSec3", "DetectedUTC": "2020-02-23T15:43:40Z", "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", "SourceHostName": "WinSec3", "ThreatSeverity": "2", "ThreatCategory": "av.detect", "TargetUserName": "WinSec3\\Logzio", "SourceProcessName": "C:\\Windows\\explorer.exe", "ThreatName": "Trojan-FRTB!81DA244A770C", "ThreatEventID": "1027", "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", "ThreatHandled": "true"}, "Severity": "3"}} MachineInfo: {"RawMACAddress": "000d3a373482", "UserName": "SYSTEM", "MachineName": "WinSec3", "OSName": "Windows 10 Workstation", "TimeZoneBias": "0", "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", "IPAddress": "10.0.1.10"} | 1027, 1027 | True, True | IDS_ALERT_THACT_ATT_CLE, IDS_ALERT_THACT_ATT_CLE | 2020-02-23T15:43:40, 2020-02-23T15:43:40 | IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio, IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetNametest.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio | False, False | IDS_ALERT_THACT_ATT_DEL, IDS_ALERT_THACT_ATT_DEL | 3, 3 | WinSec3, WinSec3 | C:\Windows\explorer.exe, C:\Windows\explorer.exe | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | 2020-02-23T15:43:21Z, 2020-02-23T15:43:21Z | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe | 249952, 249952 | 81da244a770c46ace2cf112214f8e75e, 81da244a770c46ace2cf112214f8e75e | WinSec3, WinSec3 | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | test.exe, test.exe | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth | WinSec3\Logzio, WinSec3\Logzio | IDS_OAS_TASK_NAME, IDS_OAS_TASK_NAME | IDS_ALERT_ACT_TAK_DEL, IDS_ALERT_ACT_TAK_DEL | av.detect, av.detect | True, True | 1027, 1027 | True, True | Trojan-FRTB!81DA244A770C, Trojan-FRTB!81DA244A770C | 2, 2 | trojan, trojan | ephemeral_id: 8d15318f-3a3e-436c-a93e-1b6e8fec0cfb type: filebeat hostname: SecLinux version: 7.5.0 id: 348cbd8b-b4ce-4531-b6d1-ab6beb37d65f | 1 | Win-Sec-2, Win-Sec-2 | version: 1.1.0 | type: tcp | source: {"address": "10.0.1.9:49874"} | plain | beats-5015, _grokparsefailure, _grokparsefailure, _logz_http_bulk_json_8070 | {00000000-0000-0000-0000-000000000000} | 1 | 1\2 | 2020-05-06T02:16:14.944+0000 | mcafee_epo |
| beat: filebeat  version: 7.5.0 type: _doc | 2020-05-06T02:31:16.087+0000 | 3990.0, 3990.0 | ,  | ENDP_AM_1060, ENDP_AM_1060 | 2020-02-22T08:24:00Z, 2020-02-22T08:24:00Z | 3990.0, 3990.0 | On-Access Scan, On-Access Scan | 6010.8670, 6010.8670 | True, True | WinSec3, WinSec3 | McAfee Endpoint Security, McAfee Endpoint Security | 10.6.1, 10.6.1 | 4, 4 | IDS_BLADE_NAME_SPB, IDS_BLADE_NAME_SPB | True, True | 2020-02-23T15:43:40Z, 2020-02-23T15:43:40Z | IDS_OAS_DEFAULT_THREAT_MESSAGE, IDS_OAS_DEFAULT_THREAT_MESSAGE | 18, 18 | EventFwd | SoftwareInfo: {"CommonFields": {"AnalyzerDATVersion": "3990.0", "Analyzer": "ENDP_AM_1060", "AnalyzerDetectionMethod": "On-Access Scan", "AnalyzerVersion": "10.6.1", "AnalyzerEngineVersion": "6010.8670", "AnalyzerHostName": "WinSec3", "AnalyzerName": "McAfee Endpoint Security"}, "Event": {"EventID": "1027", "GMTTime": "2020-02-23T15:43:40", "CustomFields": {"DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", "TargetFileSize": "249952", "TargetModifyTime": "2020-02-23T15:43:22Z", "DurationBeforeDetection": "18", "Cleanable": "true", "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", "TargetAccessTime": "2020-02-23T15:43:22Z", "AttackVectorType": "4", "ThreatDetectedOnCreation": "true", "FirstActionStatus": "true", "TargetName": "test.exe", "AMCoreContentVersion": "3990.0", "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\\Windows\\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\\Logzio", "TaskName": "IDS_OAS_TASK_NAME", "TargetHash": "81da244a770c46ace2cf112214f8e75e", "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", "TargetCreateTime": "2020-02-23T15:43:21Z", "SecondActionStatus": "false", "BladeName": "IDS_BLADE_NAME_SPB", "AnalyzerGTIQuery": "true", "AccessRequested_obj": {}, "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"}, "CommonFields": {"ThreatType": "trojan", "TargetHostName": "WinSec3", "DetectedUTC": "2020-02-23T15:43:40Z", "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", "SourceHostName": "WinSec3", "ThreatSeverity": "2", "ThreatCategory": "av.detect", "TargetUserName": "WinSec3\\Logzio", "SourceProcessName": "C:\\Windows\\explorer.exe", "ThreatName": "Trojan-FRTB!81DA244A770C", "ThreatEventID": "1027", "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", "ThreatHandled": "true"}, "Severity": "3"}} MachineInfo: {"RawMACAddress": "000d3a373482", "UserName": "SYSTEM", "MachineName": "WinSec3", "OSName": "Windows 10 Workstation", "TimeZoneBias": "0", "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", "IPAddress": "10.0.1.10"} | 1027, 1027 | True, True | IDS_ALERT_THACT_ATT_CLE, IDS_ALERT_THACT_ATT_CLE | 2020-02-23T15:43:40, 2020-02-23T15:43:40 | IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio, IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetNametest.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio | False, False | IDS_ALERT_THACT_ATT_DEL, IDS_ALERT_THACT_ATT_DEL | 3, 3 | WinSec3, WinSec3 | C:\Windows\explorer.exe, C:\Windows\explorer.exe | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | 2020-02-23T15:43:21Z, 2020-02-23T15:43:21Z | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe | 249952, 249952 | 81da244a770c46ace2cf112214f8e75e, 81da244a770c46ace2cf112214f8e75e | WinSec3, WinSec3 | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | test.exe, test.exe | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth | WinSec3\Logzio, WinSec3\Logzio | IDS_OAS_TASK_NAME, IDS_OAS_TASK_NAME | IDS_ALERT_ACT_TAK_DEL, IDS_ALERT_ACT_TAK_DEL | av.detect, av.detect | True, True | 1027, 1027 | True, True | Trojan-FRTB!81DA244A770C, Trojan-FRTB!81DA244A770C | 2, 2 | trojan, trojan | ephemeral_id: 8d15318f-3a3e-436c-a93e-1b6e8fec0cfb type: filebeat hostname: SecLinux version: 7.5.0 id: 348cbd8b-b4ce-4531-b6d1-ab6beb37d65f | 1 | Win-Sec-2, Win-Sec-2 | version: 1.1.0 | type: tcp | source: {"address": "10.0.1.9:49874"} | plain | beats-5015, _grokparsefailure, _grokparsefailure, _logz_http_bulk_json_8070 | {00000000-0000-0000-0000-000000000000} | 1 | 1\2 | 2020-05-06T02:31:16.087+0000 | mcafee_epo |
| beat: filebeat  version: 7.5.0 type: _doc | 2020-05-06T01:46:12.663+0000 | 3990.0, 3990.0 | ,  | ENDP_AM_1060, ENDP_AM_1060 | 2020-02-22T08:24:00Z, 2020-02-22T08:24:00Z | 3990.0, 3990.0 | On-Access Scan, On-Access Scan | 6010.8670, 6010.8670 | True, True | WinSec3, WinSec3 | McAfee Endpoint Security, McAfee Endpoint Security | 10.6.1, 10.6.1 | 4, 4 | IDS_BLADE_NAME_SPB, IDS_BLADE_NAME_SPB | True, True | 2020-02-23T15:43:40Z, 2020-02-23T15:43:40Z | IDS_OAS_DEFAULT_THREAT_MESSAGE, IDS_OAS_DEFAULT_THREAT_MESSAGE | 18, 18 | EventFwd | SoftwareInfo: {"CommonFields": {"AnalyzerDATVersion": "3990.0", "Analyzer": "ENDP_AM_1060", "AnalyzerDetectionMethod": "On-Access Scan", "AnalyzerVersion": "10.6.1", "AnalyzerEngineVersion": "6010.8670", "AnalyzerHostName": "WinSec3", "AnalyzerName": "McAfee Endpoint Security"}, "Event": {"EventID": "1027", "GMTTime": "2020-02-23T15:43:40", "CustomFields": {"DetectionMessage": "IDS_OAS_DEFAULT_THREAT_MESSAGE", "TargetFileSize": "249952", "TargetModifyTime": "2020-02-23T15:43:22Z", "DurationBeforeDetection": "18", "Cleanable": "true", "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE", "AnalyzerContentCreationDate": "2020-02-22T08:24:00Z", "TargetAccessTime": "2020-02-23T15:43:22Z", "AttackVectorType": "4", "ThreatDetectedOnCreation": "true", "FirstActionStatus": "true", "TargetName": "test.exe", "AMCoreContentVersion": "3990.0", "NaturalLangDescription": "IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\\Windows\\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\\Logzio", "TaskName": "IDS_OAS_TASK_NAME", "TargetHash": "81da244a770c46ace2cf112214f8e75e", "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL", "TargetCreateTime": "2020-02-23T15:43:21Z", "SecondActionStatus": "false", "BladeName": "IDS_BLADE_NAME_SPB", "AnalyzerGTIQuery": "true", "AccessRequested_obj": {}, "TargetPath": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth"}, "CommonFields": {"ThreatType": "trojan", "TargetHostName": "WinSec3", "DetectedUTC": "2020-02-23T15:43:40Z", "TargetFileName": "C:\\Users\\Logzio\\Downloads\\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\\taskhealth\\test.exe", "SourceHostName": "WinSec3", "ThreatSeverity": "2", "ThreatCategory": "av.detect", "TargetUserName": "WinSec3\\Logzio", "SourceProcessName": "C:\\Windows\\explorer.exe", "ThreatName": "Trojan-FRTB!81DA244A770C", "ThreatEventID": "1027", "ThreatActionTaken": "IDS_ALERT_ACT_TAK_DEL", "ThreatHandled": "true"}, "Severity": "3"}} MachineInfo: {"RawMACAddress": "000d3a373482", "UserName": "SYSTEM", "MachineName": "WinSec3", "OSName": "Windows 10 Workstation", "TimeZoneBias": "0", "AgentGUID": "{d140d3c9-53ed-4367-857d-a5a396a97775}", "IPAddress": "10.0.1.10"} | 1027, 1027 | True, True | IDS_ALERT_THACT_ATT_CLE, IDS_ALERT_THACT_ATT_CLE | 2020-02-23T15:43:40, 2020-02-23T15:43:40 | IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetName=test.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio, IDS_NATURAL_LANG_OAS_DETECTION_DEL\|TargetNametest.exe\|TargetPath=C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\|ThreatName=Trojan-FRTB!81DA244A770C\|SourceProcessName=C:\Windows\explorer.exe\|ThreatType=trojan\|TargetUserName=WinSec3\Logzio | False, False | IDS_ALERT_THACT_ATT_DEL, IDS_ALERT_THACT_ATT_DEL | 3, 3 | WinSec3, WinSec3 | C:\Windows\explorer.exe, C:\Windows\explorer.exe | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | 2020-02-23T15:43:21Z, 2020-02-23T15:43:21Z | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth\test.exe | 249952, 249952 | 81da244a770c46ace2cf112214f8e75e, 81da244a770c46ace2cf112214f8e75e | WinSec3, WinSec3 | 2020-02-23T15:43:22Z, 2020-02-23T15:43:22Z | test.exe, test.exe | C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth, C:\Users\Logzio\Downloads\2019-12-20-Emotet-and-Trickbot-malware-and-artifacts\taskhealth | WinSec3\Logzio, WinSec3\Logzio | IDS_OAS_TASK_NAME, IDS_OAS_TASK_NAME | IDS_ALERT_ACT_TAK_DEL, IDS_ALERT_ACT_TAK_DEL | av.detect, av.detect | True, True | 1027, 1027 | True, True | Trojan-FRTB!81DA244A770C, Trojan-FRTB!81DA244A770C | 2, 2 | trojan, trojan | ephemeral_id: 8d15318f-3a3e-436c-a93e-1b6e8fec0cfb type: filebeat hostname: SecLinux version: 7.5.0 id: 348cbd8b-b4ce-4531-b6d1-ab6beb37d65f | 1 | Win-Sec-2, Win-Sec-2 | version: 1.1.0 | type: tcp | source: {"address": "10.0.1.9:49874"} | plain | beats-5015, _grokparsefailure, _grokparsefailure, _logz_http_bulk_json_8070 | {00000000-0000-0000-0000-000000000000} | 1 | 1\2 | 2020-05-06T01:46:12.663+0000 | mcafee_epo |


### 2. logzio-get-logs-by-event-id
---
Fetches the logs that triggered a security event in Logz.io Cloud SIEM
##### Base Command

`logzio-get-logs-by-event-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Logz.io Alert Event ID (found under Incident details) | Required | 
| size | An integer specifying the maximum number of results to return | Optional | 
| timeout | Timeout in seconds | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logzio.Result | Unknown | An array of search results | 
| Logzio.Result.type | string | Log type in the index | 
| Logzio.Result.timestamp | date | The log's timestamp | 


##### Command Example
```!logzio-get-logs-by-event-id id=9fb0e6a9-90c0-43ac-8e50-23028d8ea76c size=10```

##### Context Example
```
{
    "Logzio.Result": [
        {
            "log_information": {
                "level": "warning"
            }, 
            "logzio_codec": "json", 
            "timestamp": "2020-05-06T08:28:04.640Z", 
            "@timestamp": "2020-05-06T08:28:04.640Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "ecs": {
                "version": "1.4.0"
            }, 
            "beat_agent": {
                "ephemeral_id": "2e94ea91-0375-4b60-8766-ee6d3f254832", 
                "type": "winlogbeat", 
                "hostname": "WinTesting", 
                "version": "7.6.2", 
                "id": "3aa2739f-7d9c-48d1-8d95-9441d5fbffe1"
            }, 
            "message": "Windows Defender Antivirus has detected malware or other potentially unwanted software.\n For more information please see the following:\nhttps://go.microsoft.com/fwlink/?linkid=37020&name=Virus:DOS/EICAR_Test_File&threatid=2147519003&enterprise=0\n \tName: Virus:DOS/EICAR_Test_File\n \tID: 2147519003\n \tSeverity: Severe\n \tCategory: Virus\n \tPath: containerfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip; file:_C:\\Users\\test_user\\Downloads\\eicar_com.zip->eicar.com; webfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip|https://www.eicar.org/download/eicar_com.zip|pid:7500,ProcessStart:132332202146885957\n \tDetection Origin: Internet\n \tDetection Type: Concrete\n \tDetection Source: Downloads and attachments\n \tUser: WinTesting\\test_user\n \tProcess Name: Unknown\n \tSignature Version: AV: 1.315.44.0, AS: 1.315.44.0, NIS: 1.315.44.0\n \tEngine Version: AM: 1.1.17000.7, NIS: 1.1.17000.7", 
            "winlog": {
                "activity_id": "{2baa0795-dcd6-4cf7-b921-d9ad5e9cd6f0}", 
                "task": "", 
                "event_id": 1116, 
                "process": {
                    "pid": 3232, 
                    "thread": {
                        "id": 4992
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "user": {
                    "domain": "NT AUTHORITY", 
                    "identifier": "S-1-5-18", 
                    "type": "User", 
                    "name": "SYSTEM"
                }, 
                "computer_name": "WinTesting", 
                "record_id": 136, 
                "provider_name": "Microsoft-Windows-Windows Defender", 
                "provider_guid": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}", 
                "event_data": {
                    "Type Name": "%%822", 
                    "Error Code": "0x00000000", 
                    "State": "1", 
                    "Category Name": "Virus", 
                    "Additional Actions String": "No additional actions required", 
                    "Post Clean Status": "0", 
                    "Action Name": "%%887", 
                    "Threat ID": "2147519003", 
                    "Signature Version": "AV: 1.315.44.0, AS: 1.315.44.0, NIS: 1.315.44.0", 
                    "Category ID": "42", 
                    "Execution Name": "%%812", 
                    "Detection ID": "{26C3583A-98B2-4E88-9B8A-0E9BDEBEB9B4}", 
                    "Status Code": "1", 
                    "Product Name": "%%827", 
                    "Action ID": "9", 
                    "Path": "containerfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip; file:_C:\\Users\\test_user\\Downloads\\eicar_com.zip->eicar.com; webfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip|https://www.eicar.org/download/eicar_com.zip|pid:7500,ProcessStart:132332202146885957", 
                    "Process Name": "Unknown", 
                    "Detection User": "WinTesting\\test_user", 
                    "Detection Time": "2020-05-06T08:28:04.604Z", 
                    "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=Virus:DOS/EICAR_Test_File&threatid=2147519003&enterprise=0", 
                    "Execution ID": "0", 
                    "Origin Name": "%%847", 
                    "Error Description": "The operation completed successfully. ", 
                    "Type ID": "0", 
                    "Additional Actions ID": "0", 
                    "Threat Name": "Virus:DOS/EICAR_Test_File", 
                    "Severity ID": "5", 
                    "Severity Name": "Severe", 
                    "Engine Version": "AM: 1.1.17000.7, NIS: 1.1.17000.7", 
                    "Source Name": "%%819", 
                    "Origin ID": "4", 
                    "Pre Execution Status": "0", 
                    "Product Version": "4.18.2004.6", 
                    "Source ID": "4"
                }, 
                "channel": "Microsoft-Windows-Windows Defender/Operational", 
                "event_id_description": "Unknown"
            }, 
            "type": "wineventlog", 
            "event": {
                "kind": "event", 
                "code": 1116, 
                "provider": "Microsoft-Windows-Windows Defender", 
                "created": "2020-05-06T08:28:05.674Z"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.6.2", 
                "type": "_doc"
            }
        }
    ]
}
```

##### Human Readable Output
### Logs
|@metadata|@timestamp|beat_agent|ecs|event|log_information|logzio_codec|message|tags|timestamp|type|winlog|
|---|---|---|---|---|---|---|---|---|---|---|---|
| beat: winlogbeat type: _doc version: 7.6.2 | 2020-05-06T08:28:04.640Z | hostname: WinTesting id: 3aa2739f-7d9c-48d1-8d95-9441d5fbffe1 version: 7.6.2 type: winlogbeat ephemeral_id: 2e94ea91-0375-4b60-8766-ee6d3f254832 | version: 1.4.0 | kind: event code: 1116 provider: Microsoft-Windows-Windows Defender created: 2020-05-06T08:28:05.674Z | level: warning | json | Windows Defender Antivirus has detected malware or other potentially unwanted software.  For more information please see the following: https://go.microsoft.com/fwlink/?linkid=37020&name=Virus:DOS/EICAR_Test_File&threatid=2147519003&enterprise=0  	Name: Virus:DOS/EICAR_Test_File  	ID: 2147519003  	Severity: Severe  	Category: Virus  	Path: containerfile:_C:\Users\test_user\Downloads\eicar_com.zip; file:_C:\Users\test_user\Downloads\eicar_com.zip->eicar.com; webfile:_C:\Users\test_user\Downloads\eicar_com.zip\|https://www.eicar.org/download/eicar_com.zip\|pid:7500,ProcessStart:132332202146885957  	Detection Origin: Internet  	Detection Type: Concrete  	Detection Source: Downloads and attachments  	User: WinTesting\test_user  	Process Name: Unknown  	Signature Version: AV: 1.315.44.0, AS: 1.315.44.0, NIS: 1.315.44.0  	Engine Version: AM: 1.1.17000.7, NIS: 1.1.17000.7 | beats-5015, _logzio_codec_json, _jsonparsefailure | 2020-05-06T08:28:04.640Z | wineventlog | channel: Microsoft-Windows-Windows Defender/Operational provider_name: Microsoft-Windows-Windows Defender api: wineventlog computer_name: WinTesting user: {"name": "SYSTEM", "domain": "NT AUTHORITY", "type": "User", "identifier": "S-1-5-18"} provider_guid: {11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78} activity_id: {2baa0795-dcd6-4cf7-b921-d9ad5e9cd6f0} process: {"pid": 3232, "thread": {"id": 4992}} event_data: {"Path": "containerfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip; file:_C:\\Users\\test_user\\Downloads\\eicar_com.zip->eicar.com; webfile:_C:\\Users\\test_user\\Downloads\\eicar_com.zip\|https://www.eicar.org/download/eicar_com.zip\|pid:7500,ProcessStart:132332202146885957", "Action Name": "%%887", "Product Version": "4.18.2004.6", "Severity ID": "5", "Signature Version": "AV: 1.315.44.0, AS: 1.315.44.0, NIS: 1.315.44.0", "Post Clean Status": "0", "Execution Name": "%%812", "Type ID": "0", "Category ID": "42", "Engine Version": "AM: 1.1.17000.7, NIS: 1.1.17000.7", "Threat Name": "Virus:DOS/EICAR_Test_File", "Category Name": "Virus", "Origin ID": "4", "Error Description": "The operation completed successfully. ", "Detection User": "WinTesting\\test_user", "Product Name": "%%827", "State": "1", "Detection Time": "2020-05-06T08:28:04.604Z", "Error Code": "0x00000000", "Source Name": "%%819", "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=Virus:DOS/EICAR_Test_File&threatid=2147519003&enterprise=0", "Threat ID": "2147519003", "Source ID": "4", "Detection ID": "{26C3583A-98B2-4E88-9B8A-0E9BDEBEB9B4}", "Status Code": "1", "Additional Actions ID": "0", "Additional Actions String": "No additional actions required", "Severity Name": "Severe", "Action ID": "9", "Execution ID": "0", "Type Name": "%%822", "Origin Name": "%%847", "Pre Execution Status": "0", "Process Name": "Unknown"} task:  opcode: Info event_id: 1116 record_id: 136 event_id_description: Unknown |
