## Overview
---

Manage Logz.io rules with CLI
This integration was integrated and tested with version xx of Logz.io
## Logz.io Playbook
---

## Use Cases
---

## Configure Logz.io on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Logz.io.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__
    * __Incident type__
    * __Security API Token__
    * __Region Code__
    * __Logzio API Server URL__
    * __Searches part of the rule__
    * __Rules Severities__
    * __Array of Rule Tags__
    * __First fetch time range (<number> <time unit>, e.g., 1 hour, 30 minutes)__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. logzio-fetch-triggered-rules
2. logzio-search-logs
3. logzio-search-logs-by-fields
### 1. logzio-fetch-triggered-rules
---
Fetch triggered rules from Logz.io
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`logzio-fetch-triggered-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Part of the alert name to filter by name (case insensitive) | Optional | 
| severities | Filter by triggered severities (SEVERE/HIGH/MEDIUM/LOW/INFO) of alerts | Optional | 
| tags | List of tags the alert is related to | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 2. logzio-search-logs
---
Get logs from your logz.io accont by query
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`logzio-search-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Lucene query_string to search for | Required | 
| size | Size of results to return | Optional | 
| from_time | Unix time - start time range of the logs to search | Optional | 
| to_time | Unix time - end time range of the logs to search | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!logzio-search-logs size=5```

##### Context Example
```
{
    "Logzio.Logs.Results": [
        {
            "log": {
                "level": "information"
            }, 
            "winlog": {
                "task": "Registry", 
                "event_id": 4658, 
                "process": {
                    "pid": 4, 
                    "thread": {
                        "id": 108
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "computer_name": "Win-Sec-2", 
                "record_id": 10395799, 
                "keywords": [
                    "Audit Success"
                ], 
                "provider_name": "Microsoft-Windows-Security-Auditing", 
                "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", 
                "event_data": {
                    "HandleId": "0x1be0", 
                    "ProcessId": "0xda8", 
                    "ObjectServer": "Security", 
                    "SubjectUserName": "Win-Sec-2$", 
                    "ProcessName": "C:\\Program Files\\McAfee\\DLP\\Agent\\fcags.exe", 
                    "SubjectDomainName": "WORKGROUP", 
                    "SubjectUserSid": "S-1-5-18", 
                    "SubjectLogonId": "0x3e7"
                }, 
                "channel": "Security", 
                "event_id_description": "The handle to an object was closed"
            }, 
            "logzio_codec": "json", 
            "@timestamp": "2020-02-19T21:10:39.577Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure"
            ], 
            "agent": {
                "ephemeral_id": "48f571e0-a499-4cb7-a780-815eb1ae4017", 
                "type": "winlogbeat", 
                "hostname": "Win-Sec-2", 
                "version": "7.5.0", 
                "id": "db37c2d8-8f9e-4243-8ded-9873293e5f4d"
            }, 
            "ecs": {
                "version": "1.1.0"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "message": "The handle to an object was closed.\n\nSubject :\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWin-Sec-2$\n\tAccount Domain:\t\tWORKGROUP\n\tLogon ID:\t\t0x3E7\n\nObject:\n\tObject Server:\t\tSecurity\n\tHandle ID:\t\t0x1be0\n\nProcess Information:\n\tProcess ID:\t\t0xda8\n\tProcess Name:\t\tC:\\Program Files\\McAfee\\DLP\\Agent\\fcags.exe", 
            "type": "wineventlog", 
            "event": {
                "action": "Registry", 
                "kind": "event", 
                "code": 4658, 
                "provider": "Microsoft-Windows-Security-Auditing", 
                "created": "2020-02-19T21:10:41.390Z"
            }, 
            "cloud": {
                "machine": {
                    "type": "Standard_B2s"
                }, 
                "instance": {
                    "id": "bd334415-d6a1-481d-b417-9d81e60d8379", 
                    "name": "Win-Sec-2"
                }, 
                "region": "westus", 
                "provider": "az"
            }
        }, 
        {
            "log": {
                "level": "information"
            }, 
            "winlog": {
                "task": "Handle Manipulation", 
                "event_id": 4690, 
                "process": {
                    "pid": 4, 
                    "thread": {
                        "id": 5316
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "computer_name": "Win-Sec-2", 
                "record_id": 10395830, 
                "keywords": [
                    "Audit Success"
                ], 
                "provider_name": "Microsoft-Windows-Security-Auditing", 
                "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", 
                "event_data": {
                    "TargetHandleId": "0x1bd4", 
                    "SourceHandleId": "0x113c", 
                    "SubjectUserName": "Win-Sec-2$", 
                    "SourceProcessId": "0xda8", 
                    "SubjectDomainName": "WORKGROUP", 
                    "TargetProcessId": "0x4", 
                    "SubjectUserSid": "S-1-5-18", 
                    "SubjectLogonId": "0x3e7"
                }, 
                "channel": "Security", 
                "event_id_description": "An attempt was made to duplicate a handle to an object"
            }, 
            "logzio_codec": "json", 
            "@timestamp": "2020-02-19T21:10:39.581Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure"
            ], 
            "agent": {
                "ephemeral_id": "48f571e0-a499-4cb7-a780-815eb1ae4017", 
                "type": "winlogbeat", 
                "hostname": "Win-Sec-2", 
                "version": "7.5.0", 
                "id": "db37c2d8-8f9e-4243-8ded-9873293e5f4d"
            }, 
            "ecs": {
                "version": "1.1.0"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "message": "An attempt was made to duplicate a handle to an object.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWin-Sec-2$\n\tAccount Domain:\t\tWORKGROUP\n\tLogon ID:\t\t0x3E7\n\nSource Handle Information:\n\tSource Handle ID:\t0x113c\n\tSource Process ID:\t0xda8\n\nNew Handle Information:\n\tTarget Handle ID:\t0x1bd4\n\tTarget Process ID:\t0x4", 
            "type": "wineventlog", 
            "event": {
                "action": "Handle Manipulation", 
                "kind": "event", 
                "code": 4690, 
                "provider": "Microsoft-Windows-Security-Auditing", 
                "created": "2020-02-19T21:10:41.394Z"
            }, 
            "cloud": {
                "machine": {
                    "type": "Standard_B2s"
                }, 
                "instance": {
                    "id": "bd334415-d6a1-481d-b417-9d81e60d8379", 
                    "name": "Win-Sec-2"
                }, 
                "region": "westus", 
                "provider": "az"
            }
        }, 
        {
            "log": {
                "level": "information"
            }, 
            "winlog": {
                "task": "Registry", 
                "event_id": 4658, 
                "process": {
                    "pid": 4, 
                    "thread": {
                        "id": 108
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "computer_name": "Win-Sec-2", 
                "record_id": 10395847, 
                "keywords": [
                    "Audit Success"
                ], 
                "provider_name": "Microsoft-Windows-Security-Auditing", 
                "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", 
                "event_data": {
                    "HandleId": "0x2970", 
                    "ProcessId": "0xe68", 
                    "ObjectServer": "Security", 
                    "SubjectUserName": "Win-Sec-2$", 
                    "ProcessName": "C:\\Windows\\System32\\svchost.exe", 
                    "SubjectDomainName": "WORKGROUP", 
                    "SubjectUserSid": "S-1-5-18", 
                    "SubjectLogonId": "0x3e7"
                }, 
                "channel": "Security", 
                "event_id_description": "The handle to an object was closed"
            }, 
            "logzio_codec": "json", 
            "@timestamp": "2020-02-19T21:10:39.624Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure"
            ], 
            "agent": {
                "ephemeral_id": "48f571e0-a499-4cb7-a780-815eb1ae4017", 
                "type": "winlogbeat", 
                "hostname": "Win-Sec-2", 
                "version": "7.5.0", 
                "id": "db37c2d8-8f9e-4243-8ded-9873293e5f4d"
            }, 
            "ecs": {
                "version": "1.1.0"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "message": "The handle to an object was closed.\n\nSubject :\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWin-Sec-2$\n\tAccount Domain:\t\tWORKGROUP\n\tLogon ID:\t\t0x3E7\n\nObject:\n\tObject Server:\t\tSecurity\n\tHandle ID:\t\t0x2970\n\nProcess Information:\n\tProcess ID:\t\t0xe68\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe", 
            "type": "wineventlog", 
            "event": {
                "action": "Registry", 
                "kind": "event", 
                "code": 4658, 
                "provider": "Microsoft-Windows-Security-Auditing", 
                "created": "2020-02-19T21:10:41.395Z"
            }, 
            "cloud": {
                "machine": {
                    "type": "Standard_B2s"
                }, 
                "instance": {
                    "id": "bd334415-d6a1-481d-b417-9d81e60d8379", 
                    "name": "Win-Sec-2"
                }, 
                "region": "westus", 
                "provider": "az"
            }
        }, 
        {
            "log": {
                "level": "information"
            }, 
            "winlog": {
                "task": "Filtering Platform Connection", 
                "version": 1, 
                "event_id": 5156, 
                "process": {
                    "pid": 4, 
                    "thread": {
                        "id": 5312
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "computer_name": "Win-Sec-2", 
                "record_id": 10395869, 
                "keywords": [
                    "Audit Success"
                ], 
                "provider_name": "Microsoft-Windows-Security-Auditing", 
                "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", 
                "event_data": {
                    "FilterRTID": "97740", 
                    "Direction": "%%14593", 
                    "Protocol": "6", 
                    "ProcessID": "3688", 
                    "RemoteUserID": "S-1-0-0", 
                    "RemoteMachineID": "S-1-0-0", 
                    "Application": "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe", 
                    "LayerRTID": "48", 
                    "DestAddress": "127.0.0.1", 
                    "SourcePort": "49968", 
                    "LayerName": "%%14611", 
                    "SourceAddress": "127.0.0.1", 
                    "DestPort": "5985"
                }, 
                "channel": "Security", 
                "event_id_description": "The Windows Filtering Platform has allowed a connection"
            }, 
            "logzio_codec": "json", 
            "@timestamp": "2020-02-19T21:10:40.961Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure"
            ], 
            "agent": {
                "ephemeral_id": "48f571e0-a499-4cb7-a780-815eb1ae4017", 
                "type": "winlogbeat", 
                "hostname": "Win-Sec-2", 
                "version": "7.5.0", 
                "id": "db37c2d8-8f9e-4243-8ded-9873293e5f4d"
            }, 
            "ecs": {
                "version": "1.1.0"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "message": "The Windows Filtering Platform has permitted a connection.\n\nApplication Information:\n\tProcess ID:\t\t3688\n\tApplication Name:\t\\device\\harddiskvolume2\\windows\\system32\\svchost.exe\n\nNetwork Information:\n\tDirection:\t\tOutbound\n\tSource Address:\t\t127.0.0.1\n\tSource Port:\t\t49968\n\tDestination Address:\t127.0.0.1\n\tDestination Port:\t\t5985\n\tProtocol:\t\t6\n\nFilter Information:\n\tFilter Run-Time ID:\t97740\n\tLayer Name:\t\tConnect\n\tLayer Run-Time ID:\t48", 
            "type": "wineventlog", 
            "event": {
                "action": "Filtering Platform Connection", 
                "kind": "event", 
                "code": 5156, 
                "provider": "Microsoft-Windows-Security-Auditing", 
                "created": "2020-02-19T21:10:42.429Z"
            }, 
            "cloud": {
                "machine": {
                    "type": "Standard_B2s"
                }, 
                "instance": {
                    "id": "bd334415-d6a1-481d-b417-9d81e60d8379", 
                    "name": "Win-Sec-2"
                }, 
                "region": "westus", 
                "provider": "az"
            }
        }, 
        {
            "log": {
                "level": "information"
            }, 
            "winlog": {
                "task": "Handle Manipulation", 
                "event_id": 4690, 
                "process": {
                    "pid": 4, 
                    "thread": {
                        "id": 368
                    }
                }, 
                "api": "wineventlog", 
                "opcode": "Info", 
                "computer_name": "Win-Sec-2", 
                "record_id": 10395890, 
                "keywords": [
                    "Audit Success"
                ], 
                "provider_name": "Microsoft-Windows-Security-Auditing", 
                "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", 
                "event_data": {
                    "TargetHandleId": "0x1c74", 
                    "SourceHandleId": "0x1d4", 
                    "SubjectUserName": "Win-Sec-2$", 
                    "SourceProcessId": "0x62c", 
                    "SubjectDomainName": "WORKGROUP", 
                    "TargetProcessId": "0x4", 
                    "SubjectUserSid": "S-1-5-18", 
                    "SubjectLogonId": "0x3e7"
                }, 
                "channel": "Security", 
                "event_id_description": "An attempt was made to duplicate a handle to an object"
            }, 
            "logzio_codec": "json", 
            "@timestamp": "2020-02-19T21:10:42.346Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure", 
                "_grokparsefailure"
            ], 
            "agent": {
                "ephemeral_id": "48f571e0-a499-4cb7-a780-815eb1ae4017", 
                "type": "winlogbeat", 
                "hostname": "Win-Sec-2", 
                "version": "7.5.0", 
                "id": "db37c2d8-8f9e-4243-8ded-9873293e5f4d"
            }, 
            "ecs": {
                "version": "1.1.0"
            }, 
            "@metadata": {
                "beat": "winlogbeat", 
                "version": "7.5.0", 
                "type": "_doc"
            }, 
            "message": "An attempt was made to duplicate a handle to an object.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWin-Sec-2$\n\tAccount Domain:\t\tWORKGROUP\n\tLogon ID:\t\t0x3E7\n\nSource Handle Information:\n\tSource Handle ID:\t0x1d4\n\tSource Process ID:\t0x62c\n\nNew Handle Information:\n\tTarget Handle ID:\t0x1c74\n\tTarget Process ID:\t0x4", 
            "type": "wineventlog", 
            "event": {
                "action": "Handle Manipulation", 
                "kind": "event", 
                "code": 4690, 
                "provider": "Microsoft-Windows-Security-Auditing", 
                "created": "2020-02-19T21:10:43.706Z"
            }, 
            "cloud": {
                "machine": {
                    "type": "Standard_B2s"
                }, 
                "instance": {
                    "id": "bd334415-d6a1-481d-b417-9d81e60d8379", 
                    "name": "Win-Sec-2"
                }, 
                "region": "westus", 
                "provider": "az"
            }
        }
    ], 
    "Logzio.Logs.Count": 5
}
```

##### Human Readable Output
Integration log: {"query": {"bool": {"must": [{"query_string": {"query": "*"}}, {"range": {"@timestamp": {"from": null, "include_lower": true, "to": null, "include_upper": true}}}]}}, "size": "5"}### Logs
|@metadata|@timestamp|agent|cloud|ecs|event|log|logzio_codec|message|tags|type|winlog|
|---|---|---|---|---|---|---|---|---|---|---|---|
| beat: winlogbeat<br>type: _doc<br>version: 7.5.0 | 2020-02-19T21:10:39.577Z | type: winlogbeat<br>ephemeral_id: 48f571e0-a499-4cb7-a780-815eb1ae4017<br>hostname: Win-Sec-2<br>id: db37c2d8-8f9e-4243-8ded-9873293e5f4d<br>version: 7.5.0 | machine: {"type": "Standard_B2s"}<br>region: westus<br>instance: {"id": "bd334415-d6a1-481d-b417-9d81e60d8379", "name": "Win-Sec-2"}<br>provider: az | version: 1.1.0 | kind: event<br>code: 4658<br>provider: Microsoft-Windows-Security-Auditing<br>action: Registry<br>created: 2020-02-19T21:10:41.390Z | level: information | json | The handle to an object was closed.<br><br>Subject :<br>	Security ID:		S-1-5-18<br>	Account Name:		Win-Sec-2$<br>	Account Domain:		WORKGROUP<br>	Logon ID:		0x3E7<br><br>Object:<br>	Object Server:		Security<br>	Handle ID:		0x1be0<br><br>Process Information:<br>	Process ID:		0xda8<br>	Process Name:		C:\Program Files\McAfee\DLP\Agent\fcags.exe | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure,<br>_grokparsefailure,<br>_grokparsefailure,<br>_grokparsefailure | wineventlog | event_id: 4658<br>event_data: {"ProcessId": "0xda8", "ProcessName": "C:\\Program Files\\McAfee\\DLP\\Agent\\fcags.exe", "SubjectUserSid": "S-1-5-18", "SubjectUserName": "Win-Sec-2$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7", "ObjectServer": "Security", "HandleId": "0x1be0"}<br>computer_name: Win-Sec-2<br>keywords: Audit Success<br>opcode: Info<br>provider_guid: {54849625-5478-4994-a5ba-3e3b0328c30d}<br>task: Registry<br>channel: Security<br>api: wineventlog<br>provider_name: Microsoft-Windows-Security-Auditing<br>record_id: 10395799<br>process: {"pid": 4, "thread": {"id": 108}}<br>event_id_description: The handle to an object was closed |
| beat: winlogbeat<br>type: _doc<br>version: 7.5.0 | 2020-02-19T21:10:39.581Z | type: winlogbeat<br>ephemeral_id: 48f571e0-a499-4cb7-a780-815eb1ae4017<br>hostname: Win-Sec-2<br>id: db37c2d8-8f9e-4243-8ded-9873293e5f4d<br>version: 7.5.0 | provider: az<br>machine: {"type": "Standard_B2s"}<br>region: westus<br>instance: {"id": "bd334415-d6a1-481d-b417-9d81e60d8379", "name": "Win-Sec-2"} | version: 1.1.0 | kind: event<br>code: 4690<br>provider: Microsoft-Windows-Security-Auditing<br>action: Handle Manipulation<br>created: 2020-02-19T21:10:41.394Z | level: information | json | An attempt was made to duplicate a handle to an object.<br><br>Subject:<br>	Security ID:		S-1-5-18<br>	Account Name:		Win-Sec-2$<br>	Account Domain:		WORKGROUP<br>	Logon ID:		0x3E7<br><br>Source Handle Information:<br>	Source Handle ID:	0x113c<br>	Source Process ID:	0xda8<br><br>New Handle Information:<br>	Target Handle ID:	0x1bd4<br>	Target Process ID:	0x4 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure,<br>_grokparsefailure,<br>_grokparsefailure,<br>_grokparsefailure | wineventlog | record_id: 10395830<br>channel: Security<br>opcode: Info<br>event_data: {"TargetProcessId": "0x4", "SubjectUserSid": "S-1-5-18", "SubjectUserName": "Win-Sec-2$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7", "SourceHandleId": "0x113c", "SourceProcessId": "0xda8", "TargetHandleId": "0x1bd4"}<br>event_id: 4690<br>provider_name: Microsoft-Windows-Security-Auditing<br>task: Handle Manipulation<br>computer_name: Win-Sec-2<br>keywords: Audit Success<br>provider_guid: {54849625-5478-4994-a5ba-3e3b0328c30d}<br>process: {"thread": {"id": 5316}, "pid": 4}<br>api: wineventlog<br>event_id_description: An attempt was made to duplicate a handle to an object |
| beat: winlogbeat<br>type: _doc<br>version: 7.5.0 | 2020-02-19T21:10:39.624Z | ephemeral_id: 48f571e0-a499-4cb7-a780-815eb1ae4017<br>hostname: Win-Sec-2<br>id: db37c2d8-8f9e-4243-8ded-9873293e5f4d<br>version: 7.5.0<br>type: winlogbeat | machine: {"type": "Standard_B2s"}<br>region: westus<br>instance: {"id": "bd334415-d6a1-481d-b417-9d81e60d8379", "name": "Win-Sec-2"}<br>provider: az | version: 1.1.0 | action: Registry<br>created: 2020-02-19T21:10:41.395Z<br>kind: event<br>code: 4658<br>provider: Microsoft-Windows-Security-Auditing | level: information | json | The handle to an object was closed.<br><br>Subject :<br>	Security ID:		S-1-5-18<br>	Account Name:		Win-Sec-2$<br>	Account Domain:		WORKGROUP<br>	Logon ID:		0x3E7<br><br>Object:<br>	Object Server:		Security<br>	Handle ID:		0x2970<br><br>Process Information:<br>	Process ID:		0xe68<br>	Process Name:		C:\Windows\System32\svchost.exe | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure,<br>_grokparsefailure,<br>_grokparsefailure,<br>_grokparsefailure | wineventlog | channel: Security<br>task: Registry<br>api: wineventlog<br>computer_name: Win-Sec-2<br>provider_guid: {54849625-5478-4994-a5ba-3e3b0328c30d}<br>event_data: {"ObjectServer": "Security", "HandleId": "0x2970", "ProcessId": "0xe68", "ProcessName": "C:\\Windows\\System32\\svchost.exe", "SubjectUserSid": "S-1-5-18", "SubjectUserName": "Win-Sec-2$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7"}<br>provider_name: Microsoft-Windows-Security-Auditing<br>keywords: Audit Success<br>process: {"thread": {"id": 108}, "pid": 4}<br>event_id: 4658<br>record_id: 10395847<br>opcode: Info<br>event_id_description: The handle to an object was closed |
| beat: winlogbeat<br>type: _doc<br>version: 7.5.0 | 2020-02-19T21:10:40.961Z | ephemeral_id: 48f571e0-a499-4cb7-a780-815eb1ae4017<br>hostname: Win-Sec-2<br>id: db37c2d8-8f9e-4243-8ded-9873293e5f4d<br>version: 7.5.0<br>type: winlogbeat | machine: {"type": "Standard_B2s"}<br>region: westus<br>instance: {"id": "bd334415-d6a1-481d-b417-9d81e60d8379", "name": "Win-Sec-2"}<br>provider: az | version: 1.1.0 | action: Filtering Platform Connection<br>created: 2020-02-19T21:10:42.429Z<br>kind: event<br>code: 5156<br>provider: Microsoft-Windows-Security-Auditing | level: information | json | The Windows Filtering Platform has permitted a connection.<br><br>Application Information:<br>	Process ID:		3688<br>	Application Name:	\device\harddiskvolume2\windows\system32\svchost.exe<br><br>Network Information:<br>	Direction:		Outbound<br>	Source Address:		127.0.0.1<br>	Source Port:		49968<br>	Destination Address:	127.0.0.1<br>	Destination Port:		5985<br>	Protocol:		6<br><br>Filter Information:<br>	Filter Run-Time ID:	97740<br>	Layer Name:		Connect<br>	Layer Run-Time ID:	48 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure,<br>_grokparsefailure,<br>_grokparsefailure,<br>_grokparsefailure | wineventlog | computer_name: Win-Sec-2<br>event_data: {"LayerRTID": "48", "ProcessID": "3688", "Application": "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe", "FilterRTID": "97740", "SourcePort": "49968", "DestAddress": "127.0.0.1", "RemoteMachineID": "S-1-0-0", "Direction": "%%14593", "SourceAddress": "127.0.0.1", "LayerName": "%%14611", "DestPort": "5985", "Protocol": "6", "RemoteUserID": "S-1-0-0"}<br>channel: Security<br>event_id: 5156<br>opcode: Info<br>process: {"pid": 4, "thread": {"id": 5312}}<br>provider_name: Microsoft-Windows-Security-Auditing<br>record_id: 10395869<br>provider_guid: {54849625-5478-4994-a5ba-3e3b0328c30d}<br>version: 1<br>task: Filtering Platform Connection<br>api: wineventlog<br>keywords: Audit Success<br>event_id_description: The Windows Filtering Platform has allowed a connection |
| beat: winlogbeat<br>type: _doc<br>version: 7.5.0 | 2020-02-19T21:10:42.346Z | type: winlogbeat<br>ephemeral_id: 48f571e0-a499-4cb7-a780-815eb1ae4017<br>hostname: Win-Sec-2<br>id: db37c2d8-8f9e-4243-8ded-9873293e5f4d<br>version: 7.5.0 | machine: {"type": "Standard_B2s"}<br>region: westus<br>instance: {"id": "bd334415-d6a1-481d-b417-9d81e60d8379", "name": "Win-Sec-2"}<br>provider: az | version: 1.1.0 | code: 4690<br>provider: Microsoft-Windows-Security-Auditing<br>action: Handle Manipulation<br>created: 2020-02-19T21:10:43.706Z<br>kind: event | level: information | json | An attempt was made to duplicate a handle to an object.<br><br>Subject:<br>	Security ID:		S-1-5-18<br>	Account Name:		Win-Sec-2$<br>	Account Domain:		WORKGROUP<br>	Logon ID:		0x3E7<br><br>Source Handle Information:<br>	Source Handle ID:	0x1d4<br>	Source Process ID:	0x62c<br><br>New Handle Information:<br>	Target Handle ID:	0x1c74<br>	Target Process ID:	0x4 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure,<br>_grokparsefailure,<br>_grokparsefailure,<br>_grokparsefailure | wineventlog | process: {"pid": 4, "thread": {"id": 368}}<br>provider_name: Microsoft-Windows-Security-Auditing<br>channel: Security<br>keywords: Audit Success<br>opcode: Info<br>event_id: 4690<br>computer_name: Win-Sec-2<br>provider_guid: {54849625-5478-4994-a5ba-3e3b0328c30d}<br>record_id: 10395890<br>task: Handle Manipulation<br>api: wineventlog<br>event_data: {"SubjectUserName": "Win-Sec-2$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7", "SourceHandleId": "0x1d4", "SourceProcessId": "0x62c", "TargetHandleId": "0x1c74", "TargetProcessId": "0x4", "SubjectUserSid": "S-1-5-18"}<br>event_id_description: An attempt was made to duplicate a handle to an object |


### 3. logzio-search-logs-by-fields
---
Search raw logs from your Logz.io account by up to 3 fields
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`logzio-search-logs-by-fields`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key1 | First key to search for | Required | 
| value1 | Value for key1 | Required | 
| key2 | Second  key to search for | Optional | 
| value2 | Value for key2 | Optional | 
| key3 | Third  key to search for | Optional | 
| value3 | Value for key3 | Optional | 
| size | Size of result logs | Optional | 
| from_time | Start time range of logs | Optional | 
| to_time | End time range of logs | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* 'Error in API call [%d] - %s' % (response.status_code, response.reason
* 'Error in API call [%d] - %s' % (response.status_code, response.reason
* 'Failed to execute command. Error: {}'.format(str(e
