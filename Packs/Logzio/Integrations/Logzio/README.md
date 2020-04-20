## Overview
---

Fetch incidents from Logz.io Cloud SIEM to activate Demisto Playbooks
This integration was integrated and tested with version xx of Logz.io


## Use Cases
---

Integrate with Logz.io Cloud SIEM to automatically remediate security incidents identified by Logz.io and increase observability into incident details. 
The integration allows Demisto users to automatically remediate incidents identified by Logz.io Cloud SIEM using Demisto Playbooks.
In addition, users can query Logz.io directly from Demisto to investigate open questions or retrieve the logs responsible for triggering security rules. 


## Prerequisites 
---

1. Logz.io Cloud SIEM - You’ll need to have a Logz.io Cloud SIEM add-on. If you need to add it, please contact support@logz.io. 

2. API Tokens - You’ll need to have active API Tokens for each of the relevant Logz.io accounts. Keep in mind that API tokens are specific to account ID. Your Logz.io Operations accounts and associated Security account have separate API Tokens. 


## Logz.io Playbook
---

Logz.io provides a sample playbook to get you started. You can add as many playbooks as you’ll need to keep increasing your security. 


## Configure Logz.io on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Analytics & SIEM__.
2. Search for Logz.io.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__
    * __Incident type__
    * __API token for Logz.io Security account__
    * __API token for Logz.io Operations account__
    * __Region code of your Logz.io account__
    * __Filter on rule names (Lucene syntax)__
    * __Filter by rule severity__
    * __First-time retroactive fetch (e.g., 12 hours, 7 days)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. logzio-search-logs
2. logzio-get-logs-by-rule-id
### 1. logzio-search-logs
---
Returns logs from your Logz.io Operations account by Lucene query
##### Required Permissions
Your Logz.io account type should be PRO or above.
##### Base Command

`logzio-search-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A string  specifying the search query, written in Lucene syntax.  | Required | 
| size | An integer specifying the maximum number  of results to return | Optional | 
| from_time | Unix timestamp. Specifies the earliest timestamp to be returned by the query.  | Optional | 
| to_time | Unix timestamp. Specifies the latest timestamp to be returned by the query.  | Optional | 


##### Context Output

```
{
    "Logzio.Logs.Results": [], 
    "Logzio.Logs.Count": 0
}
```
##### Command Example
```!logzio-search-logs query="action:Teardown AND protocol:TCP" size=10```

##### Context Example
```
{
    "Logzio.Logs.Results": [
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:02:12.458Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2807 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/36939 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:60909"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:02:09 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2807", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "36939", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:02:12.458Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2809 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/22578 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:60909"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:02:09 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2809", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "22578", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:02:12.458Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2808 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/21436 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:60909"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:02:09 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2808", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "21436", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T02:04:05.999Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2869 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/61195 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:35071"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 02:04:02 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2869", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "61195", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T02:04:05.999Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2868 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/62326 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:35071"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 02:04:02 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2868", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "62326", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T02:04:05.999Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2867 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/21600 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:35071"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 02:04:02 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2867", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "21600", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T01:35:02.408Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:11:07", 
            "message": "<190>Mar 26 2020 01:34:59: %ASA-6-302014: Teardown TCP connection 2854 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/15756 duration 0:11:07 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:46448"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 01:34:59 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2854", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "15756", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:33:44.100Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2823 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/47532 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:33309"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:33:41 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2823", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "47532", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:33:44.099Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2822 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/61990 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:33309"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:33:41 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2822", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "61990", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }, 
        {
            "protocol": "TCP", 
            "@timestamp": "2020-03-26T00:33:44.099Z", 
            "dst_interface": "identity", 
            "_logzio_pattern": 4032921, 
            "duration": "0:10:06", 
            "message": "<190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2824 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/41993 duration 0:10:06 bytes 0 Connection timeout", 
            "src_port": "6514", 
            "log": {
                "source": {
                    "address": "10.0.250.193:33309"
                }
            }, 
            "logzio_codec": "json", 
            "log_timestamp": "Mar 26 00:33:41 2020", 
            "src_ip": "10.0.250.44", 
            "input": {
                "type": "tcp"
            }, 
            "type": "cisco-asa", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json", 
                "_jsonparsefailure"
            ], 
            "connection_id": "2824", 
            "reason": "Connection timeout", 
            "src_interface": "mgmt", 
            "ecs": {
                "version": "1.1.0"
            }, 
            "dst_ip": "10.0.250.193", 
            "ciscotag": "ASA-6-302014", 
            "bytes": "0", 
            "dst_port": "41993", 
            "action": "Teardown", 
            "beat_agent": {
                "ephemeral_id": "f6acc59c-b3f2-4b22-81a2-27144692a89b", 
                "type": "filebeat", 
                "hostname": "ip-10-0-250-44", 
                "version": "7.4.0", 
                "id": "d6130ca5-9587-4210-9698-edfd367abb6d"
            }, 
            "syslog_pri": "190", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.4.0", 
                "type": "_doc"
            }
        }
    ], 
    "Logzio.Logs.Count": 10
}
```

##### Human Readable Output
### Logs
|@metadata|@timestamp|_logzio_pattern|action|beat_agent|bytes|ciscotag|connection_id|dst_interface|dst_ip|dst_port|duration|ecs|input|log|log_timestamp|logzio_codec|message|protocol|reason|src_interface|src_ip|src_port|syslog_pri|tags|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:02:12.458Z | 4032921 | Teardown | version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d | 0 | ASA-6-302014 | 2807 | identity | 10.0.250.193 | 36939 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:60909"} | Mar 26 00:02:09 2020 | json | <190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2807 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/36939 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:02:12.458Z | 4032921 | Teardown | hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b | 0 | ASA-6-302014 | 2809 | identity | 10.0.250.193 | 22578 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:60909"} | Mar 26 00:02:09 2020 | json | <190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2809 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/22578 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:02:12.458Z | 4032921 | Teardown | type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0 | 0 | ASA-6-302014 | 2808 | identity | 10.0.250.193 | 21436 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:60909"} | Mar 26 00:02:09 2020 | json | <190>Mar 26 2020 00:02:09: %ASA-6-302014: Teardown TCP connection 2808 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/21436 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T02:04:05.999Z | 4032921 | Teardown | hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b | 0 | ASA-6-302014 | 2869 | identity | 10.0.250.193 | 61195 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:35071"} | Mar 26 02:04:02 2020 | json | <190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2869 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/61195 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T02:04:05.999Z | 4032921 | Teardown | version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d | 0 | ASA-6-302014 | 2868 | identity | 10.0.250.193 | 62326 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:35071"} | Mar 26 02:04:02 2020 | json | <190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2868 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/62326 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T02:04:05.999Z | 4032921 | Teardown | id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44 | 0 | ASA-6-302014 | 2867 | identity | 10.0.250.193 | 21600 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:35071"} | Mar 26 02:04:02 2020 | json | <190>Mar 26 2020 02:04:02: %ASA-6-302014: Teardown TCP connection 2867 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/21600 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T01:35:02.408Z | 4032921 | Teardown | ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0<br>type: filebeat | 0 | ASA-6-302014 | 2854 | identity | 10.0.250.193 | 15756 | 0:11:07 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:46448"} | Mar 26 01:34:59 2020 | json | <190>Mar 26 2020 01:34:59: %ASA-6-302014: Teardown TCP connection 2854 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/15756 duration 0:11:07 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:33:44.100Z | 4032921 | Teardown | version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d | 0 | ASA-6-302014 | 2823 | identity | 10.0.250.193 | 47532 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:33309"} | Mar 26 00:33:41 2020 | json | <190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2823 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/47532 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:33:44.099Z | 4032921 | Teardown | type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b<br>hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0 | 0 | ASA-6-302014 | 2822 | identity | 10.0.250.193 | 61990 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:33309"} | Mar 26 00:33:41 2020 | json | <190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2822 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/61990 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |
| beat: filebeat<br>type: _doc<br>version: 7.4.0 | 2020-03-26T00:33:44.099Z | 4032921 | Teardown | hostname: ip-10-0-250-44<br>id: d6130ca5-9587-4210-9698-edfd367abb6d<br>version: 7.4.0<br>type: filebeat<br>ephemeral_id: f6acc59c-b3f2-4b22-81a2-27144692a89b | 0 | ASA-6-302014 | 2824 | identity | 10.0.250.193 | 41993 | 0:10:06 | version: 1.1.0 | type: tcp | source: {"address": "10.0.250.193:33309"} | Mar 26 00:33:41 2020 | json | <190>Mar 26 2020 00:33:41: %ASA-6-302014: Teardown TCP connection 2824 for mgmt:10.0.250.44/6514 to identity:10.0.250.193/41993 duration 0:10:06 bytes 0 Connection timeout | TCP | Connection timeout | mgmt | 10.0.250.44 | 6514 | 190 | beats-5015,<br>_logzio_codec_json,<br>_jsonparsefailure | cisco-asa |


### 2. logzio-get-logs-by-rule-id
---
Returns the raw logs that triggered the security rule in Logz.io. 
##### Required Permissions
Your Logz.io account type should be PRO or above.
##### Base Command

`logzio-get-logs-by-rule-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Security rule ID in Logz.io. In Demisto, it appears under the field 'alertEventId'. | Required | 
| size | An integer specifying the maximum number of results to return | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!logzio-get-logs-by-rule-id id=e9ef3227-7ed8-4060-8c25-4d78e9571537```

##### Context Example
```
{
    "Logzio.Logs.Results": [
        {
            "log": {
                "file": {}, 
                "offset": 1624454
            }, 
            "logzio_codec": "json", 
            "output_message": "Error File below / or /root opened for writing", 
            "@timestamp": "2020-03-29T14:46:17.236Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json"
            ], 
            "output_fields": {
                "proc.cmdline": "micro /etc/ssh/sshd_config", 
                "fd.name": "/root/.config/micro/buffers/history", 
                "user.name": "root", 
                "evt.time": 1585493176520316700, 
                "container.image.repository": "nginx", 
                "proc.name": "micro", 
                "proc.pname": "micro", 
                "container.id": "3ef0a1a5172c"
            }, 
            "rule": "Write below root", 
            "output": "17:46:16.520316598: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/buffers/history program=micro container_id=3ef0a1a5172c image=nginx)", 
            "priority": "Error", 
            "ecs": {
                "version": "1.4.0"
            }, 
            "time": "2020-03-29T14:46:16.520316598Z", 
            "input": {
                "type": "log"
            }, 
            "source_string": "/events.txt", 
            "beat_agent": {
                "ephemeral_id": "d48ac506-a40b-4ff0-bef7-0325648ce451", 
                "type": "filebeat", 
                "hostname": "ubuntu-VirtualBox", 
                "version": "7.6.1", 
                "id": "6eda6199-a716-4c01-94a5-03b4bde48a14"
            }, 
            "message": "{\"output\":\"17:46:16.520316598: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/buffers/history program=micro container_id=3ef0a1a5172c image=nginx)\",\"priority\":\"Error\",\"rule\":\"Write below root\",\"time\":\"2020-03-29T14:46:16.520316598Z\", \"output_fields\": {\"container.id\":\"3ef0a1a5172c\",\"container.image.repository\":\"nginx\",\"evt.time\":1585493176520316598,\"fd.name\":\"/root/.config/micro/buffers/history\",\"proc.cmdline\":\"micro /etc/ssh/sshd_config\",\"proc.name\":\"micro\",\"proc.pname\":\"micro\",\"user.name\":\"root\"}}", 
            "type": "falco", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.6.1", 
                "type": "_doc"
            }
        }, 
        {
            "log": {
                "file": {}, 
                "offset": 1623840
            }, 
            "logzio_codec": "json", 
            "output_message": "Error File below / or /root opened for writing", 
            "@timestamp": "2020-03-29T14:46:14.236Z", 
            "tags": [
                "beats-5015", 
                "_logzio_codec_json"
            ], 
            "output_fields": {
                "proc.cmdline": "micro /etc/ssh/sshd_config", 
                "fd.name": "/root/.config/micro/backups/%etc%ssh%sshd_config", 
                "user.name": "root", 
                "evt.time": 1585493172518809000, 
                "container.image.repository": "nginx", 
                "proc.name": "micro", 
                "proc.pname": "micro", 
                "container.id": "3ef0a1a5172c"
            }, 
            "rule": "Write below root", 
            "output": "17:46:12.518809016: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/backups/%etc%ssh%sshd_config program=micro container_id=3ef0a1a5172c image=nginx)", 
            "priority": "Error", 
            "ecs": {
                "version": "1.4.0"
            }, 
            "time": "2020-03-29T14:46:12.518809016Z", 
            "input": {
                "type": "log"
            }, 
            "source_string": "/events.txt", 
            "beat_agent": {
                "ephemeral_id": "d48ac506-a40b-4ff0-bef7-0325648ce451", 
                "type": "filebeat", 
                "hostname": "ubuntu-VirtualBox", 
                "version": "7.6.1", 
                "id": "6eda6199-a716-4c01-94a5-03b4bde48a14"
            }, 
            "message": "{\"output\":\"17:46:12.518809016: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/backups/%etc%ssh%sshd_config program=micro container_id=3ef0a1a5172c image=nginx)\",\"priority\":\"Error\",\"rule\":\"Write below root\",\"time\":\"2020-03-29T14:46:12.518809016Z\", \"output_fields\": {\"container.id\":\"3ef0a1a5172c\",\"container.image.repository\":\"nginx\",\"evt.time\":1585493172518809016,\"fd.name\":\"/root/.config/micro/backups/%etc%ssh%sshd_config\",\"proc.cmdline\":\"micro /etc/ssh/sshd_config\",\"proc.name\":\"micro\",\"proc.pname\":\"micro\",\"user.name\":\"root\"}}", 
            "type": "falco", 
            "@metadata": {
                "beat": "filebeat", 
                "version": "7.6.1", 
                "type": "_doc"
            }
        }
    ],
    "Logzio.Logs.Count": 3
}
```

##### Human Readable Output
### Logs
|@metadata|@timestamp|beat_agent|ecs|input|log|logzio_codec|message|output|output_fields|output_message|priority|rule|source_string|tags|time|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| beat: filebeat<br>type: _doc<br>version: 7.6.1 | 2020-03-29T14:46:17.236Z | hostname: ubuntu-VirtualBox<br>id: 6eda6199-a716-4c01-94a5-03b4bde48a14<br>version: 7.6.1<br>type: filebeat<br>ephemeral_id: d48ac506-a40b-4ff0-bef7-0325648ce451 | version: 1.4.0 | type: log | offset: 1624454<br>file: {} | json | {"output":"17:46:16.520316598: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/buffers/history program=micro container_id=3ef0a1a5172c image=nginx)","priority":"Error","rule":"Write below root","time":"2020-03-29T14:46:16.520316598Z", "output_fields": {"container.id":"3ef0a1a5172c","container.image.repository":"nginx","evt.time":1585493176520316598,"fd.name":"/root/.config/micro/buffers/history","proc.cmdline":"micro /etc/ssh/sshd_config","proc.name":"micro","proc.pname":"micro","user.name":"root"}} | 17:46:16.520316598: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/buffers/history program=micro container_id=3ef0a1a5172c image=nginx) | container.id: 3ef0a1a5172c<br>container.image.repository: nginx<br>evt.time: 1585493176520316598<br>fd.name: /root/.config/micro/buffers/history<br>proc.cmdline: micro /etc/ssh/sshd_config<br>proc.name: micro<br>proc.pname: micro<br>user.name: root | Error File below / or /root opened for writing | Error | Write below root | /events.txt | beats-5015,<br>_logzio_codec_json | 2020-03-29T14:46:16.520316598Z | falco |
| beat: filebeat<br>type: _doc<br>version: 7.6.1 | 2020-03-29T14:46:14.236Z | version: 7.6.1<br>type: filebeat<br>ephemeral_id: d48ac506-a40b-4ff0-bef7-0325648ce451<br>hostname: ubuntu-VirtualBox<br>id: 6eda6199-a716-4c01-94a5-03b4bde48a14 | version: 1.4.0 | type: log | offset: 1623840<br>file: {} | json | {"output":"17:46:12.518809016: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/backups/%etc%ssh%sshd_config program=micro container_id=3ef0a1a5172c image=nginx)","priority":"Error","rule":"Write below root","time":"2020-03-29T14:46:12.518809016Z", "output_fields": {"container.id":"3ef0a1a5172c","container.image.repository":"nginx","evt.time":1585493172518809016,"fd.name":"/root/.config/micro/backups/%etc%ssh%sshd_config","proc.cmdline":"micro /etc/ssh/sshd_config","proc.name":"micro","proc.pname":"micro","user.name":"root"}} | 17:46:12.518809016: Error File below / or /root opened for writing (user=root command=micro /etc/ssh/sshd_config parent=micro file=/root/.config/micro/backups/%etc%ssh%sshd_config program=micro container_id=3ef0a1a5172c image=nginx) | container.id: 3ef0a1a5172c<br>container.image.repository: nginx<br>evt.time: 1585493172518809016<br>fd.name: /root/.config/micro/backups/%etc%ssh%sshd_config<br>proc.cmdline: micro /etc/ssh/sshd_config<br>proc.name: micro<br>proc.pname: micro<br>user.name: root | Error File below / or /root opened for writing | Error | Write below root | /events.txt | beats-5015,<br>_logzio_codec_json | 2020-03-29T14:46:12.518809016Z | falco |

