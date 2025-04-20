This integration allows, via about twenty commands, to interact with the GCenter appliance via its API.
This integration was integrated and tested with version v2.5.3.102 of GCenter.
To simplify GCenter v2.5.3.102 is called GCenter in the Pack.

## Configure GCenter in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GCenter IP address | | True |
| GCenter Version | | False |
| GCenter API token | You must provide either an API token or a username and a password. | False |
| GCenter username |  | False |
| GCenter password |  | False |
| Check the TLS certificate |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gw-get-alert
***
Get an alert by it's uid


#### Base Command

`gw-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uid | Alert identifier. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Alert.Single.sha256 | String | The 256 Shasum Of The File | 
| GCenter.Alert.Single.id | String | The Id Of The Inspectra Alert | 
| GCenter.Alert.Single.flow_id | Number | The Flow Id Of The Alert | 
| GCenter.Alert.Single.severity | Number | The Severity Of The Alert | 
| GCenter.Alert.Single.src_ip | String | The Ip Address Of The Alert'S Source | 
| GCenter.Alert.Single.dest_ip | String | The Ip Address Of The Alert'S Target | 
| GCenter.Alert.Single.src_port | Number | The Port Of The Alert'S Source | 
| GCenter.Alert.Single.dest_port | Number | The Port Of The Alert'S Target | 
| GCenter.Alert.Single.gcap | String | The Gcap That Raised The Alert | 
| GCenter.Alert.Single.type | String | Which Type Of Alert \(Sigflow, Codebreaker...\) | 
| GCenter.Alert.Single.proto | String | The Protocol Used | 
| GCenter.Alert.Single.host | String | The Host Where The Alert Was Found | 
| GCenter.Alert.Single.app_proto | String | The Malware Application Prototype | 
| GCenter.Alert.Single.alert_type | String | Which Event It Is ? | 
| GCenter.Alert.Single.state | String | The State Of The Alert | 
| GCenter.Alert.Single.matched_event | String | Value Of The Id Of An Other Alert That Matched \(Allows The Correlation Between Alerts\) | 
| GCenter.Alert.Single.domain_name | String | For Dga Alerts Only | 
| GCenter.Alert.Single.probability | Number | The Severity Probability | 
| GCenter.Alert.Single.timestamp_detected | Date | When The Alert Was Detected | 
| GCenter.Alert.Single.timestamp_analyzed | Date | When The Alert Was Analysed | 
| GCenter.Alert.Single.retrohunt.timestamp_package | String | Utc Date When The Ioc Was Added To The Lastinfosec Update Package | 
| GCenter.Alert.Single.retrohunt.ioc_creation_date | Date | The Ioc Creation Date | 
| GCenter.Alert.Single.retrohunt.ioc_updated_date | Date | The Ioc Updated Date | 
| GCenter.Alert.Single.retrohunt.description | String | The Alert Description | 
| GCenter.Alert.Single.retrohunt.ioc_type | String | Host, Md5, Sha1, Sha256, Url | 
| GCenter.Alert.Single.retrohunt.ioc_value | String | Characteristic Value Of The Ioc | 
| GCenter.Alert.Single.retrohunt.matched_app_proto | String | The Sigflow Protocol That Contains This Ioc | 
| GCenter.Alert.Single.retrohunt.matched_event_type | String | The Sigflow Event Type That Contains This Ioc | 
| GCenter.Alert.Single.retrohunt.case_id | String | Uuid Of The Box To Which The Ioc Belongs | 
| GCenter.Alert.Single.retrohunt.ioc_id | String | Uuid Of The Ioc | 
| GCenter.Alert.Single.retrohunt.risk | String | Suspicious, High Suspicious, Malicious | 
| GCenter.Alert.Single.retrohunt.usage_mode | String | Usage Mode | 
| GCenter.Alert.Single.retrohunt.tlp | String | Tlp | 
| GCenter.Alert.Single.powershell.file_id | String | The File Id | 
| GCenter.Alert.Single.powershell.scores.proba_obfuscated | Number | The Probability It Is Obfuscated | 
| GCenter.Alert.Single.powershell.scores.analysis | Number | The Powershell Analysis Score | 
| GCenter.Alert.Single.shellcode.file_id | String | The File Id | 
| GCenter.Alert.Single.shellcode.encodings.name | String | The Name Of The Encoding | 
| GCenter.Alert.Single.shellcode.encodings.count | Number | The Number Of The Encoding Elements | 
| GCenter.Alert.Single.shellcode.calls.call | String | The Name Of The Call Of The Alert | 
| GCenter.Alert.Single.shellcode.calls.args | String | The Argument Used For The Call | 
| GCenter.Alert.Single.shellcode.calls.ret | String | The Retention Of The Call | 
| GCenter.Alert.Single.shellcode.calls.index | Number | The Call Index | 
| GCenter.Alert.Single.malware.analyzed_clean | Number | Number Of Engines That Returned A Clean Status | 
| GCenter.Alert.Single.malware.analyzed_infected | Number | Number Of Engines That Returned An Infected Status | 
| GCenter.Alert.Single.malware.analyzed_suspicious | Number | Number Of Engines That Returned A Suspicious Status | 
| GCenter.Alert.Single.malware.analyzed_other | Number | Number Of Engines That Returned Other Statuses | 
| GCenter.Alert.Single.malware.analyzed_error | Number | Number Of Engines That Failed To Analyze The File | 
| GCenter.Alert.Single.malware.code | Number | The Global Code Result | 
| GCenter.Alert.Single.malware.def_time | Date | When The Last Engines Have Ended The Scan  | 
| GCenter.Alert.Single.malware.scan_time | Number | The Scan Time In Ms. | 
| GCenter.Alert.Single.malware.threats_found | String | The Threats Found By The Engines | 
| GCenter.Alert.Single.malware.reporting_token | String | The Reporting Token Returned By The Gbox. | 
| GCenter.Alert.Single.malware.engines_report.0.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.0.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.0.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.1.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.1.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.1.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.2.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.2.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.2.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.3.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.3.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.3.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.4.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.4.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.4.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.5.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.5.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.5.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.6.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.6.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.6.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.7.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.7.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.7.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.8.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.8.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.8.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.9.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.9.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.9.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.10.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.10.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.10.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.11.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.11.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.11.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.12.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.12.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.12.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.13.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.13.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.13.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.14.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.14.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.14.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.engines_report.15.id | String | The Hash Pf The Engine | 
| GCenter.Alert.Single.malware.engines_report.15.threat_details | String | The Threat Found By The Engine | 
| GCenter.Alert.Single.malware.engines_report.15.scan_result | String | Analysis Result | 
| GCenter.Alert.Single.malware.magic_details | String | The File Magic | 
| GCenter.Alert.Single.malware.total_found | String | The Malcore Number Of Engines That Found The File Suspicious / The Total Number Of Engines | 
| GCenter.Alert.Single.sigflow.alert.action | String | Action | 
| GCenter.Alert.Single.sigflow.alert.signature_id | String | Signature Id | 
| GCenter.Alert.Single.sigflow.alert.gid | String | Gid | 
| GCenter.Alert.Single.sigflow.alert.category | String | Category | 
| GCenter.Alert.Single.sigflow.packet | String | Packet | 
| GCenter.Alert.Single.sigflow.in_iface | String | In Which Interface The Alert Occurred | 
| GCenter.Alert.Single.sigflow.stream | Number | Is It Streaming \(\!= 0\) | 
| GCenter.Alert.Single.sigflow.payload | String | Payload | 
| GCenter.Alert.Single.sigflow.payload_printable | String | Payload Printable | 

##### Command Example

```!gw-get-alert uid="d7e612cb-567a-431b-a14b-9f9f4e88c9a4"```

##### Context Example

```json
{
    "sha256": "f16d19ac9697d9892b0f910601a61d041d64",
    "id": "45e6ed3c-1082-4d33-9514-162748d7d41f",
    "flow_id": 1544096072809159,
    "severity": 1,
    "src_ip": "192.168.0.2",
    "dest_ip": "192.168.0.1",
    "src_port": 80,
    "dest_port": 35168,
    "gcap": "test.domain.com",
    "type": "malcore",
    "proto": "TCP",
    "host": "test.domain.com",
    "app_proto": "http",
    "alert_type": "malware",
    "state": "Infected",
    "matched_event": "3d35e491-cfc8-4271-815b-ff018a036c7c",
    "domain_name": "nzpzxcox.com",
    "probability": 0.55555555,
    "timestamp_detected": "2022-03-21T11:34:47.000Z",
    "timestamp_analyzed": "2022-03-21T13:58:42.742Z",
    "dest_geoip": {},
    "src_geoip": {},
    "retrohunt": {
        "timestamp_package": "2022-06-06T22:00:01.632829+0000",
        "ioc_creation_date": "2022-05-27T18:37:30+00:00",
        "ioc_updated_date": "2022-06-06T21:05:12+00:00",
        "description": "'test.domain.com' is a Suspicious Host.",
        "ioc_type": "Host",
        "ioc_value": "test.domain.com",
        "matched_app_proto": "http",
        "matched_event_type": "http",
        "meta_data": {},
        "targeted_organizations": [],
        "targeted_platforms": [],
        "targeted_sectors": [],
        "threat_actor": [],
        "external_links": [],
        "relations": [],
        "campaigns": [],
        "categories": [],
        "families": [],
        "vulnerabilities": [],
        "ttp": [],
        "case_id": "1746d38d-58f3-4b43-b4ee-6f0b43527d49",
        "ioc_id": "183abf8e-b0a5-4ed0-a93f-e5d7927648b8",
        "risk": "Suspicious",
        "usage_mode": "hunting",
        "tlp": "green"
    },
    "powershell": {
        "file_id": "06-08-2022T11:37:11_1348935773_gcap-dean.org",
        "scores": {
            "proba_obfuscated": 0.2,
            "analysis": 241,
            "analysis_detailed": {}
        }
    },
    "shellcode": {
        "file_id": "file_id",
        "encodings": [
            {
                "name": "Bloxor",
                "count": 2
            }
        ],
        "calls": [
            {
                "call": "ws2_32_recv",
                "args": "{'sockfd': 'Socket_1-bind (4)', 'backlog': 19103712}",
                "ret": "90137289",
                "index": 0
            }
        ]
    },
    "malware": {
        "analyzed_clean": 11,
        "analyzed_infected": 5,
        "analyzed_suspicious": 0,
        "analyzed_other": 0,
        "analyzed_error": 0,
        "code": 1,
        "def_time": "2022-05-31T21:45:33Z",
        "scan_time": 3785,
        "threats_found": "Infected : Gen:Variant.Ulise.315566 (B)",
        "reporting_token": "No GBOX",
        "engines_report": {
            "0": {
                "id": "XXX",
                "threat_details": "Gen:Variant.Ulise.315566 (B)",
                "scan_result": "INFECTED"
            },
            "1": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "2": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "3": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "4": {
                "id": "XXX",
                "threat_details": "WinGo/TrojanDownloader.Agent.BD trojan",
                "scan_result": "INFECTED"
            },
            "5": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "6": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "7": {
                "id": "XXX",
                "threat_details": "Trojan.Donut.Win64.545",
                "scan_result": "INFECTED"
            },
            "8": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "9": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "10": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "11": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "12": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "13": {
                "id": "XXX",
                "threat_details": "",
                "scan_result": "CLEAN"
            },
            "14": {
                "id": "XXX",
                "threat_details": "W64/Donut.B.gen!Eldorado",
                "scan_result": "INFECTED"
            },
            "15": {
                "id": "XXX",
                "threat_details": "Trojan.Win64.Crypt",
                "scan_result": "INFECTED"
            }
        },
        "magic_details": "PE32+ executable (DLL) (GUI) x86-64, for MS Windows",
        "total_found": "5/16"
    },
    "sigflow": {
        "alert": {
            "action": "allowed",
            "signature_id": "202",
            "gid": "1",
            "category": "A Network Trojan was detected"
        },
        "packet": "XXXXXXXXXXXXXXXXXX",
        "in_iface": "mon5",
        "stream": 0,
        "payload": "XXXXXXXXXXXXXXXXXX",
        "payload_printable": "XXXXXXXXXXXXXXXXXX",
        "extra_keys": {}
    }
}
```

##### Human Readable Output

>### Elasticsearch alert entry
>|alert_type|app_proto|dest_geoip|dest_ip|dest_port|domain_name|flow_id|gcap|host|id|malware|matched_event|powershell|probability|proto|retrohunt|severity|sha256|shellcode|sigflow|src_geoip|src_ip|src_port|state|timestamp_analyzed|timestamp_detected|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| malware | http |  | 192.168.0.1 | 35168 | nzpzxcox.com | 1544096072809159 | test.domain.com | test.domain.com | 45e6ed3c-1082-4d33-9514-162748d7d41f | analyzed_clean: 11<br>analyzed_infected: 5<br>analyzed_suspicious: 0<br>analyzed_other: 0<br>analyzed_error: 0<br>code: 1<br>def_time: 2022-05-31T21:45:33Z<br>scan_time: 3785<br>threats_found: Infected : Gen:Variant.Ulise.315566 (B)<br>reporting_token: No GBOX<br>engines_report: {"0": {"id": "XXX", "threat_details": "Gen:Variant.Ulise.315566 (B)", "scan_result": "INFECTED"}, "1": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "2": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "3": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "4": {"id": "XXX", "threat_details": "WinGo/TrojanDownloader.Agent.BD trojan", "scan_result": "INFECTED"}, "5": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "6": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "7": {"id": "XXX", "threat_details": "Trojan.Donut.Win64.545", "scan_result": "INFECTED"}, "8": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "9": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "10": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "11": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "12": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "13": {"id": "XXX", "threat_details": "", "scan_result": "CLEAN"}, "14": {"id": "XXX", "threat_details": "W64/Donut.B.gen!Eldorado", "scan_result": "INFECTED"}, "15": {"id": "XXX", "threat_details": "Trojan.Win64.Crypt", "scan_result": "INFECTED"}}<br>magic_details: PE32+ executable (DLL) (GUI) x86-64, for MS Windows<br>total_found: 5/16 | 3d35e491-cfc8-4271-815b-ff018a036c7c | file_id: 06-08-2022T11:37:11_1348935773_gcap-dean.org<br>scores: {"proba_obfuscated": 0.2, "analysis": 241, "analysis_detailed": {}} | 0.55555555 | TCP | timestamp_package: 2022-06-06T22:00:01.632829+0000<br>ioc_creation_date: 2022-05-27T18:37:30+00:00<br>ioc_updated_date: 2022-06-06T21:05:12+00:00<br>description: 'test.domain.com' is a Suspicious Host.<br>ioc_type: Host<br>ioc_value: test.domain.com<br>matched_app_proto: http<br>matched_event_type: http<br>meta_data: {}<br>targeted_organizations: <br>targeted_platforms: <br>targeted_sectors: <br>threat_actor: <br>external_links: <br>relations: <br>campaigns: <br>categories: <br>families: <br>vulnerabilities: <br>ttp: <br>case_id: 1746d38d-58f3-4b43-b4ee-6f0b43527d49<br>ioc_id: 183abf8e-b0a5-4ed0-a93f-e5d7927648b8<br>risk: Suspicious<br>usage_mode: hunting<br>tlp: green | 1 | f16d19ac9697d9892b0f910601a61d041d64 | file_id: file_id<br>encodings: {'name': 'Bloxor', 'count': 2}<br>calls: {'call': 'ws2_32_recv', 'args': "{'sockfd': 'Socket_1-bind (4)', 'backlog': 19103712}", 'ret': '90137289', 'index': 0} | alert: {"action": "allowed", "signature_id": "202", "gid": "1", "category": "A Network Trojan was detected"}<br>packet: XXXXXXXXXXXXXXXXXX<br>in_iface: mon5<br>stream: 0<br>payload: XXXXXXXXXXXXXXXXXX<br>payload_printable: XXXXXXXXXXXXXXXXXX<br>extra_keys: {} |  | 192.168.0.2 | 80 | Infected | 2022-03-21T13:58:42.742Z | 2022-03-21T11:34:47.000Z | malcore |

### gw-es-query
***
Get Elasticsearch data


#### Base Command

`gw-es-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | Index to be queried. Possible values are: suricata, malware, codebreaker, netdata, syslog, machine_learning, retrohunt, iocs. Default is suricata. | Optional | 
| query | Elaticsearch query. Default is {}. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-es-query index="suricata" query="{}"```

### gw-add-malcore-list-entry
***
Add malcore whitelist/blacklist entry


#### Base Command

`gw-add-malcore-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 
| sha256 | SHA256 to be added. | Required | 
| comment | Comment to be added. | Optional | 
| threat | Comment to be added. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Malcore.sha256 | String | Sha256 | 
| GCenter.Malcore.created | Date | Created | 
| GCenter.Malcore.comment | String | Comment | 
| GCenter.Malcore.threat | String | Name Of Threat For Reference | 

##### Command Example

```!gw-add-malcore-list-entry type="white" sha256="d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e"```

##### Context Example

```json
{
    "sha256": "d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e",
    "created": "2022-03-21T16:36:58.957178Z",
    "comment": "test",
    "threat": "undefined"
}
```

##### Human Readable Output

>### Malcore whitelist/blacklist entry
>|comment|created|sha256|threat|
>|---|---|---|---|
>| test | 2022-03-21T16:36:58.957178Z | d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e | undefined |

### gw-del-malcore-list-entry
***
Delete malcore whitelist/blacklist entry


#### Base Command

`gw-del-malcore-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 
| sha256 | SHA256 to be deleted. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-malcore-list-entry type="white" sha256="d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e"```

### gw-add-dga-list-entry
***
Add dga whitelist/blacklist entry


#### Base Command

`gw-add-dga-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 
| domain | Domain name to be added. | Required | 
| comment | Comment to be added. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Dga.domain_name | String | Domain Name | 
| GCenter.Dga.created | Date | Created | 
| GCenter.Dga.comment | String | Comment | 
| GCenter.Dga.is_wildcard | Boolean | Is Wildcard | 

##### Command Example

```!gw-add-dga-list-entry type="white" domain="test.domain.com"```

##### Context Example

```json
{
    "domain_name": "test.domain.com",
    "created": "2022-03-21T16:30:20.012035Z",
    "comment": "test",
    "is_wildcard": false
}
```

##### Human Readable Output

>### DGA whitelist/blacklist entry
>|comment|created|domain_name|is_wildcard|
>|---|---|---|---|
>| test | 2022-03-21T16:30:20.012035Z | test.domain.com | false |

### gw-del-dga-list-entry
***
Delete dga whitelist/blacklist entry


#### Base Command

`gw-del-dga-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 
| domain | Domain name to be deleted. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-dga-list-entry type="white" domain="test.domain.com"```

### gw-add-ignore-asset-name
***
Ignore asset name


#### Base Command

`gw-add-ignore-asset-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name to be ignored. | Required | 
| start | Will be ignored if they start with this name. | Required | 
| end | Will be ignored if they end with this name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.AssetName.id | String | Id | 
| GCenter.Ignore.AssetName.created_at | Date | Created At | 
| GCenter.Ignore.AssetName.created_by | String | Created By | 
| GCenter.Ignore.AssetName.name | String | Ignored Name For The Assets \(Hostnames\). Case Insensitive. | 
| GCenter.Ignore.AssetName.is_startswith_pattern | Boolean | Should The Assets \(Hostnames\) Be Ignored If They Start With This Name ? | 
| GCenter.Ignore.AssetName.is_endswith_pattern | Boolean | Should The Assets \(Hostnames\) Be Ignored If They End With This Name ? | 

##### Command Example

```!gw-add-ignore-asset-name name="test_asset"```

##### Context Example

```json
{
    "id": "1",
    "created_at": "2022-03-21T16:37:54.657263Z",
    "created_by": "admin",
    "name": "test_asset",
    "is_startswith_pattern": true,
    "is_endswith_pattern": false
}
```

##### Human Readable Output

>### Asset name entry
>|created_at|created_by|id|is_endswith_pattern|is_startswith_pattern|name|
>|---|---|---|---|---|---|
>| 2022-03-21T16:37:54.657263Z | admin | 1 | false | true | test_asset |

### gw-add-ignore-kuser-ip
***
Ignore kuser IP


#### Base Command

`gw-add-ignore-kuser-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to be ignored. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.KuserIP.id | String | Id | 
| GCenter.Ignore.KuserIP.created_at | Date | Created At | 
| GCenter.Ignore.KuserIP.created_by | String | Created By | 
| GCenter.Ignore.KuserIP.ip | String | Ignored Ip For The Kerberos Users | 

##### Command Example

```!gw-add-ignore-kuser-ip ip="10.10.10.0"```

##### Context Example

```json
{
    "id": "2",
    "created_at": "2022-03-21T16:38:35.484082Z",
    "created_by": "admin",
    "ip": "10.10.10.0"
}
```

##### Human Readable Output

>### Kuser IP entry
>|created_at|created_by|id|ip|
>|---|---|---|---|
>| 2022-03-21T16:38:35.484082Z | admin | 2 | 10.10.10.0 |

### gw-add-ignore-kuser-name
***
Ignore kuser name


#### Base Command

`gw-add-ignore-kuser-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name to be ignored. | Required | 
| start | Will be ignored if they start with this name. | Required | 
| end | Will be ignored if they end with this name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.KuserName.id | String | Id | 
| GCenter.Ignore.KuserName.created_at | Date | Created At | 
| GCenter.Ignore.KuserName.created_by | String | Created By | 
| GCenter.Ignore.KuserName.name | String | Ignored Name For The Kerberos Users. Case Insensitive. | 
| GCenter.Ignore.KuserName.is_startswith_pattern | Boolean | Should The Kerberos Users Be Ignored If They Start With This Name ? | 
| GCenter.Ignore.KuserName.is_endswith_pattern | Boolean | Should The Kerberos Users Be Ignored If They End With This Name ? | 

##### Command Example

```!gw-add-ignore-kuser-name name="test_kuser"```

##### Context Example

```json
{
    "id": "1",
    "created_at": "2022-03-21T16:39:18.435420Z",
    "created_by": "admin",
    "name": "test_kuser",
    "is_startswith_pattern": true,
    "is_endswith_pattern": false
}
```

##### Human Readable Output

>### Kuser name entry
>|created_at|created_by|id|is_endswith_pattern|is_startswith_pattern|name|
>|---|---|---|---|---|---|
>| 2022-03-21T16:39:18.435420Z | admin | 1 | false | true | test_kuser |

### gw-add-ignore-mac-address
***
Ignore mac address


#### Base Command

`gw-add-ignore-mac-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac | MAC address to be ignored. | Required | 
| start | Will be ignored if they start with this name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.MacAddress.id | String | Id | 
| GCenter.Ignore.MacAddress.created_at | Date | Created At | 
| GCenter.Ignore.MacAddress.created_by | String | Created By | 
| GCenter.Ignore.MacAddress.address | String | Address | 
| GCenter.Ignore.MacAddress.is_startswith_pattern | Boolean | Should The Mac Addresses Be Ignored If They Start With This Address Value ? | 

##### Command Example

```!gw-add-ignore-mac-address mac="50:50:50:50:50:50"```

##### Context Example

```json
{
    "id": "1",
    "created_at": "2022-03-21T16:39:48.363094Z",
    "created_by": "admin",
    "address": "00:50:50:50:50:50",
    "is_startswith_pattern": true
}
```

##### Human Readable Output

>### MAC adrress entry
>|address|created_at|created_by|id|is_startswith_pattern|
>|---|---|---|---|---|
>| 00:50:50:50:50:50 | 2022-03-21T16:39:48.363094Z | admin | 1 | true |

### gw-del-ignore-asset-name
***
Delete an ignore asset ID


#### Base Command

`gw-del-ignore-asset-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ignore_id | Ignore asset ID. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-ignore-asset-name ignore_id=1```

### gw-del-ignore-kuser-ip
***
Delete an ignore kuser IP ID


#### Base Command

`gw-del-ignore-kuser-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ignore_id | Ignore kuser IP ID. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-ignore-kuser-ip ignore_id=1```

### gw-del-ignore-kuser-name
***
Delete an ignore kuser name ID


#### Base Command

`gw-del-ignore-kuser-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ignore_id | Ignore kuser name ID. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-ignore-kuser-name ignore_id=1```

### gw-del-ignore-mac-address
***
Delete an ignore mac address ID


#### Base Command

`gw-del-ignore-mac-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ignore_id | Ignore mac address ID. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-del-ignore-mac-address ignore_id=1```

### gw-send-malware
***
Send malware


#### Base Command

`gw-send-malware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | Filename. | Required | 
| file_id | File entry id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Malware.id | String | The Id Of The Gscan History Message | 
| GCenter.Gscan.Malware.created | Date | Date Of Creation | 
| GCenter.Gscan.Malware.username | String | The User'S Username Who Uploaded The File | 
| GCenter.Gscan.Malware.user_agent | String | The Client'S User-Agent | 
| GCenter.Gscan.Malware.ip_address | String | The Ip Address Of The User Who Uploaded The File | 
| GCenter.Gscan.Malware.file_name | String | Original File Name | 
| GCenter.Gscan.Malware.sha256 | String | Sha256 | 
| GCenter.Gscan.Malware.is_clean | Unknown | Clean | 
| GCenter.Gscan.Malware.is_analysis_successful | Boolean | Scan Succes | 
| GCenter.Gscan.Malware.malcore_code_result | String | Malcore Code Result | 
| GCenter.Gscan.Malware.threat_name | String | Threat Name | 
| GCenter.Gscan.Malware.nb_alerts | Number | Number Or Malcore Alerts | 
| GCenter.Gscan.Malware.nb_engines | Number | Number Or Malcore Engines | 
| GCenter.Gscan.Malware.is_whiteblack_listed | Boolean | Is White Or Black Listed? | 
| GCenter.Gscan.Malware.malcore_code_result_name | String | Malcore Code Result Name | 
| GCenter.Gscan.Malware.status | String | The Malcore Status | 

##### Command Example

```!gw-send-malware filename="test" file_id="331@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5"```

##### Context Example

```json
{
    "id": "1",
    "created": "2022-03-21T16:42:11.996076Z",
    "username": "admin",
    "user_agent": "Mozilla/5.0",
    "ip_address": "10.10.10.10",
    "file_name": "Arch.jpg",
    "sha256": "1a9487d49d842ebdee5ad870065eb74dc7044",
    "is_clean": null,
    "is_analysis_successful": false,
    "malcore_code_result": "5",
    "threat_name": "",
    "nb_alerts": 0,
    "nb_engines": 0,
    "is_whiteblack_listed": false,
    "malcore_code_result_name": "Unknown",
    "status": "Unknown"
}
```

##### Human Readable Output

>### Malcore analysis result
>|created|file_name|id|ip_address|is_analysis_successful|is_clean|is_whiteblack_listed|malcore_code_result|malcore_code_result_name|nb_alerts|nb_engines|sha256|status|threat_name|user_agent|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-03-21T16:42:11.996076Z | Arch.jpg | 1 | 10.10.10.10 | false |  | false | 5 | Unknown | 0 | 0 | 1a9487d49d842ebdee5ad870065eb74dc7044 | Unknown |  | Mozilla/5.0 | admin |

### gw-send-powershell
***
Send powershell


#### Base Command

`gw-send-powershell`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | Filename. | Required | 
| file_id | File entry id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Powershell.id | String | The Id Of The Gscan History Message | 
| GCenter.Gscan.Powershell.created | Date | Date Of Creation | 
| GCenter.Gscan.Powershell.username | String | The User'S Username Who Uploaded The File | 
| GCenter.Gscan.Powershell.user_agent | String | The Client'S User-Agent | 
| GCenter.Gscan.Powershell.ip_address | String | The Ip Address Of The User Who Uploaded The File | 
| GCenter.Gscan.Powershell.file_name | String | Original File Name | 
| GCenter.Gscan.Powershell.sha256 | String | Sha256 | 
| GCenter.Gscan.Powershell.is_clean | Boolean | Clean | 
| GCenter.Gscan.Powershell.is_analysis_successful | Boolean | Scan Succes | 
| GCenter.Gscan.Powershell.status | String | Status | 
| GCenter.Gscan.Powershell.proba_obfuscated | Number | Proba_Obfuscated | 
| GCenter.Gscan.Powershell.analysis_score | Number | Analysis_Score | 
| GCenter.Gscan.Powershell.is_whiteblack_listed | Boolean | Is White Or Black Listed? | 

##### Command Example

```!gw-send-powershell filename="test" file_id="331@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5"```

##### Context Example

```json
{
    "id": "2",
    "created": "2022-03-21T16:43:35.591406Z",
    "username": "admin",
    "user_agent": "Mozilla/5.0",
    "ip_address": "10.10.10.10",
    "file_name": "Arch.jpg",
    "sha256": "1a9487d49d842ebdee5ad870065eb74dc7044",
    "is_clean": true,
    "is_analysis_successful": true,
    "status": "Clean",
    "proba_obfuscated": 0,
    "analysis_score": 0,
    "is_whiteblack_listed": false
}
```

##### Human Readable Output

>### Powershell analysis result
>|analysis_score|created|file_name|id|ip_address|is_analysis_successful|is_clean|is_whiteblack_listed|proba_obfuscated|sha256|status|user_agent|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 2022-03-21T16:43:35.591406Z | Arch.jpg | 2 | 10.10.10.10 | true | true | false | 0 | 1a9487d49d842ebdee5ad870065eb74dc7044 | Clean | Mozilla/5.0 | admin |

### gw-send-shellcode
***
Send shellcode


#### Base Command

`gw-send-shellcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | Filename. | Required | 
| file_id | File entry id. | Required | 
| deep | Deep scan. | Optional | 
| timeout | Deep scan timeout. Default is 120. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Shellcode.id | String | The Id Of The Gscan History Message | 
| GCenter.Gscan.Shellcode.created | Date | Date Of Creation | 
| GCenter.Gscan.Shellcode.username | String | The User'S Username Who Uploaded The File | 
| GCenter.Gscan.Shellcode.user_agent | String | The Client'S User-Agent | 
| GCenter.Gscan.Shellcode.ip_address | String | The Ip Address Of The User Who Uploaded The File | 
| GCenter.Gscan.Shellcode.file_name | String | Original File Name | 
| GCenter.Gscan.Shellcode.sha256 | String | Sha256 | 
| GCenter.Gscan.Shellcode.is_clean | Boolean | Clean | 
| GCenter.Gscan.Shellcode.is_analysis_successful | Boolean | Scan Succes | 
| GCenter.Gscan.Shellcode.status | String | Status | 
| GCenter.Gscan.Shellcode.architecture | Unknown | Architecture | 
| GCenter.Gscan.Shellcode.is_whiteblack_listed | Boolean | Is White Or Black Listed? | 

##### Command Example

```!gw-send-shellcode filename="test" file_id="331@dfca9ea2-5198-4d64-8c36-5282ac3b2dc5" deep=false timeout=120```

##### Context Example

```json
{
    "id": "3",
    "created": "2022-03-21T16:44:26.214241Z",
    "username": "admin",
    "user_agent": "Mozilla/5.0",
    "ip_address": "10.10.10.10",
    "file_name": "Arch.jpg",
    "sha256": "1a9487d49d842ebdee5ad870065eb74dc7044",
    "is_clean": true,
    "is_analysis_successful": true,
    "status": "Clean",
    "architecture": null,
    "encodings": [],
    "is_whiteblack_listed": false
}
```

##### Human Readable Output

>### Shellcode analysis result
>|architecture|created|encodings|file_name|id|ip_address|is_analysis_successful|is_clean|is_whiteblack_listed|sha256|status|user_agent|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2022-03-21T16:44:26.214241Z |  | Arch.jpg | 3 | 10.10.10.10 | true | true | false | 1a9487d49d842ebdee5ad870065eb74dc7044 | Clean | Mozilla/5.0 | admin |

### gw-es-wrapper
***
Get Elasticsearch data using a wrapper


#### Base Command

`gw-es-wrapper`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | index. Possible values are: suricata, codebreaker, malware, netdata, syslog, machine_learning, retrohunt, iocs. | Required | 
| aggs_term | List and count each distinct values of a document field using the terms aggregation<br/>If aggs_term is empty list hits value<br/>Exemple : "src_ip,dest_ip". Possible values are: src_ip, dest_ip, http.hostname, tls.sni, SHA256. | Optional | 
| must_match | Filter document that match the value using the term query<br/>Exemple : "alert.severity=1,app_proto=http". | Optional | 
| must_exists | Filter document with existing key using the exists query<br/>Exemple : "http.hostname,http.url". | Optional | 
| timerange | Set the lower timerange in hour based on the now keyword. Default is 24. | Optional | 
| formatted | True to get the list of aggregation value False to get entire response. Possible values are: True, False. Default is True. | Optional | 
| size | Set the number of aggregate or hits value that can be returned. Default is 100. | Optional | 


#### Context Output

There is no context output for this command.

##### Command Example

```!gw-es-wrapper index="malware" aggs_term="src_ip" must_match="state=Infected" timerange="240" formatted="True"```

##### Context Example

```json
{
    "src_ip": [
        "10.10.10.10"
    ]
}
```

##### Human Readable Output

>### Elasticsearch wrapper result
>|src_ip|
>|---|
>| 10.10.10.10 |

### gw-get-malcore-list-entry
***
Get the malcore whitelist/blacklist


#### Base Command

`gw-get-malcore-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Malcore.List.sha256 | String | Sha256 | 
| GCenter.Malcore.List.created | Date | Created | 
| GCenter.Malcore.List.comment | String | Comment | 
| GCenter.Malcore.List.threat | String | Name Of Threat For Reference | 

##### Command Example

```!gw-get-malcore-list-entry type=black```

##### Context Example

```json
[
    {
        "sha256": "d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351f",
        "created": "2022-09-13T08:16:21.400100Z",
        "comment": "added by cortex",
        "threat": "undefined"
    },
    {
        "sha256": "d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e",
        "created": "2022-09-13T08:16:09.880381Z",
        "comment": "added by cortex",
        "threat": "undefined"
    }
]
```

##### Human Readable Output

>### Malcore whitelist/blacklist entry
>|comment|created|sha256|threat|
>|---|---|---|---|
>| added by cortex | 2022-09-13T08:16:21.400100Z | d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351f | undefined |
>| added by cortex | 2022-09-13T08:16:09.880381Z | d955e262d7a05fc436e65c2a312593e4c7031482d90cebd29e69059053b1351e | undefined |

### gw-get-dga-list-entry
***
Get the dga whitelist/blacklist


#### Base Command

`gw-get-dga-list-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | List type. Possible values are: white, black. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Dga.List.domain_name | String | Domain Name | 
| GCenter.Dga.List.created | Date | Created | 
| GCenter.Dga.List.comment | String | Comment | 
| GCenter.Dga.List.is_wildcard | Boolean | Is Wildcard | 

##### Command Example

```!gw-get-dga-list-entry type=black```

##### Context Example

```json
[
    {
        "domain_name": "test.domain.com",
        "created": "2022-03-21T16:30:20.012035Z",
        "comment": "added by cortex",
        "is_wildcard": false
    }
]
```

##### Human Readable Output

>### DGA whitelist/blacklist entry
>|comment|created|domain_name|is_wildcard|
>|---|---|---|---|
>| added by cortex | 2022-03-21T16:30:20.012035Z | test.domain.com | false |

### gw-get-ignore-asset-name
***
Get all the ignored asset names


#### Base Command

`gw-get-ignore-asset-name`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.AssetName.List.id | String | Id | 
| GCenter.Ignore.AssetName.List.created_at | Date | Created At | 
| GCenter.Ignore.AssetName.List.created_by | String | Created By | 
| GCenter.Ignore.AssetName.List.name | String | Ignored Name For The Assets (Hostnames). Case Insensitive. | 
| GCenter.Ignore.AssetName.List.is_startswith_pattern | Boolean | Should The Assets (Hostnames) Be Ignored If They Start With This Name ? | 
| GCenter.Ignore.AssetName.List.is_endswith_pattern | Boolean | Should The Assets (Hostnames) Be Ignored If They End With This Name ? | 

##### Command Example

```!gw-get-ignore-asset-name```

##### Context Example

```json
[
    {
        "id": "1",
        "created_at": "2022-09-13T13:31:18.427519Z",
        "created_by": "admin",
        "name": "test",
        "is_startswith_pattern": false,
        "is_endswith_pattern": true
    },
    {
        "id": "2",
        "created_at": "2022-09-13T13:31:31.049593Z",
        "created_by": "admin",
        "name": "test2",
        "is_startswith_pattern": true,
        "is_endswith_pattern": false
    }
]
```

##### Human Readable Output

>### Asset name entry
>|created_at|created_by|id|is_endswith_pattern|is_startswith_pattern|name|
>|---|---|---|---|---|---|
>| 2022-09-13T13:31:18.427519Z | admin | 1 | true | false | test |
>| 2022-09-13T13:31:31.049593Z | admin | 2 | false | true | test2 |

### gw-get-ignore-kuser-ip
***
Get all the ignored kuser IP


#### Base Command

`gw-get-ignore-kuser-ip`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.KuserIP.List.id | String | Id | 
| GCenter.Ignore.KuserIP.List.created_at | Date | Created At | 
| GCenter.Ignore.KuserIP.List.created_by | String | Created By | 
| GCenter.Ignore.KuserIP.List.ip | String | Ignored Ip For The Kerberos Users | 

##### Command Example

```!gw-get-ignore-kuser-ip```

##### Context Example

```json
[
    {
        "id": "1",
        "created_at": "2022-09-13T12:06:29.575735Z",
        "created_by": "admin",
        "ip": "10.10.10.0"
    },
    {
        "id": "2",
        "created_at": "2022-09-13T13:30:26.791512Z",
        "created_by": "admin",
        "ip": "10.10.10.0"
    }
]
```

##### Human Readable Output

>### Kuser IP entry
>|created_at|created_by|id|ip|
>|---|---|---|---|
>| 2022-09-13T12:06:29.575735Z | admin | 1 | 10.10.10.0 |
>| 2022-09-13T13:30:26.791512Z | admin | 2 | 10.10.10.0 |

### gw-get-ignore-kuser-name
***
Get all the ignored kuser name


#### Base Command

`gw-get-ignore-kuser-name`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.KuserName.List.id | String | Id | 
| GCenter.Ignore.KuserName.List.created_at | Date | Created At | 
| GCenter.Ignore.KuserName.List.created_by | String | Created By | 
| GCenter.Ignore.KuserName.List.name | String | Ignored Name For The Kerberos Users. Case Insensitive. | 
| GCenter.Ignore.KuserName.List.is_startswith_pattern | Boolean | Should The Kerberos Users Be Ignored If They Start With This Name ? | 
| GCenter.Ignore.KuserName.List.is_endswith_pattern | Boolean | Should The Kerberos Users Be Ignored If They End With This Name ? | 

##### Command Example

```!gw-get-ignore-kuser-name```

##### Context Example

```json
[
    {
        "id": "1",
        "created_at": "2022-09-13T13:27:50.136561Z",
        "created_by": "admin",
        "name": "test",
        "is_startswith_pattern": true,
        "is_endswith_pattern": false
    },
    {
        "id": "2",
        "created_at": "2022-09-13T13:28:02.072013Z",
        "created_by": "admin",
        "name": "test2",
        "is_startswith_pattern": false,
        "is_endswith_pattern": true
    }
]
```

##### Human Readable Output

>### Kuser name entry
>|created_at|created_by|id|is_endswith_pattern|is_startswith_pattern|name|
>|---|---|---|---|---|---|
>| 2022-09-13T13:27:50.136561Z | admin | 1 | false | true | test |
>| 2022-09-13T13:28:02.072013Z | admin | 2 | true | false | test2 |

### gw-get-ignore-mac-address
***
Get all the ignored mac addresses


#### Base Command

`gw-get-ignore-mac-address`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Ignore.MacAddress.List.id | String | Id | 
| GCenter.Ignore.MacAddress.List.created_at | Date | Created At | 
| GCenter.Ignore.MacAddress.List.created_by | String | Created By | 
| GCenter.Ignore.MacAddress.List.address | String | Address | 
| GCenter.Ignore.MacAddress.List.is_startswith_pattern | Boolean | Should The Mac Addresses Be Ignored If They Start With This Address Value ? | 

##### Command Example

```!gw-get-ignore-mac-address```

##### Context Example

```json
[
    {
        "id": "1",
        "created_at": "2022-09-13T13:25:55.679624Z",
        "created_by": "admin",
        "address": "00:50:50:50:50:50",
        "is_startswith_pattern": true
    },
    {
        "id": "2",
        "created_at": "2022-09-13T13:26:11.338296Z",
        "created_by": "admin",
        "address": "00:40:40:40:40:40",
        "is_startswith_pattern": true
    }
]
```

##### Human Readable Output

>### MAC adrress entry
>|address|created_at|created_by|id|is_startswith_pattern|
>|---|---|---|---|---|
>| 00:50:50:50:50:50 | 2022-09-13T13:25:55.679624Z | admin | 1 | true |
>| 00:40:40:40:40:40 | 2022-09-13T13:26:11.338296Z | admin | 2 | true |

### gw-get-file-infected
***
Get a file from an uuid.
If there is no uuid, get all the files infected from a time interval.


#### Base Command

`gw-get-file-infected`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timerange | Set the lower timerange in minute based on the now keyword when uuid is not given<br/>Default value to 60 minutes. | Optional | 
| size | Set the number of aggregate value that can be returned when uuid is not given<br/>Get all the values by default. | Optional | 
| uuid | The uuid of the file to get. | Optional | 
| state | The state of the files to get, in list, when uuid is not given<br/>Default value to Infected,Suspicious. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gcenter.File.Infected | String | File infected |

##### Command Example

```!gw-get-file-infected timerange="1440"```

##### Context Example

```json
[
    {
        "Content": "",
        "ContentFormat": "text",
        "File": "malcore_b34fc6de9763e3640f93dda3f7a97470af6f009089bca588272a03807ae9f5bf_2022-12-12_18-21-40.zip",
        "FileID": "f956f5cd-bad2-4f9c-ab75-cc6b16e58873",
        "Type": "3"
    }
]
```

##### Human Readable Output

>### Files infected entry
>|Contents|ContentsFormat|File|FileID|Type|
>|---|---|---|---|---|
>|  | text | malcore_b34fc6de9763e3640f93dda3f7a97470af6f009089bca588272a03807ae9f5bf_2022-12-12_18-21-40.zip | f956f5cd-bad2-4f9c-ab75-cc6b16e58873 | 3 |