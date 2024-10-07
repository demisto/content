Smokescreen IllusionBLACK is a deception-based threat defense platform designed to accurately and efficiently detect targeted threats including reconnaissance, lateral movement, malware-less attacks, social engineering, Man-in-the-Middle attacks, and ransomware in real-time.
This integration was integrated and tested with version v3.10.7.4 of Smokescreen IllusionBLACK
## Permissions

## Configure Smokescreen IllusionBLACK in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| client_id | IllusionBLACK API Client Id | True |
| token | IllusionBLACK External API Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| first_fetch | First fetch time for fetching incidents \(2 days, 3 weeks, etc\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### illusionblack-get-ad-decoys
***
Gets a list of Active Directory decoys.


##### Base Command

`illusionblack-get-ad-decoys`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.AdDecoy | Unknown | IllusionBLACK AD Decoy users. | 


##### Command Example
```!illusionblack-get-ad-decoys```

##### Context Example
```
{
    "IllusionBlack": {
        "AdDecoy": {
            "first_name": "felix",
            "last_name": "hunt",
            "ou": "mumbai",
            "state": "added",
            "user_name": "sqladmin"
        }
    }
}
```

##### Human Readable Output
### IllusionBLACK AD Decoys
|First Name|Last Name|Ou|State|User Name|
|---|---|---|---|---|
| felix | hunt | mumbai | added | sqladmin |


### illusionblack-get-network-decoys
***
Gets a list of Network decoys.


##### Base Command

`illusionblack-get-network-decoys`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.NetworkDecoy | Unknown | IllusionBLACK Network decoys. | 


##### Command Example
```!illusionblack-get-network-decoys```

##### Context Example
```
{
    "IllusionBlack": {
        "NetworkDecoy": [
            {
                "ip": "10.20.23.61",
                "mac": "d0:43:1e:cd:cb:c2",
                "name": "CTX-BACKUPS31",
                "services": "web"
            },
            {
                "ip": "10.20.23.64",
                "mac": "a0:48:1c:ee:08:38",
                "name": "GCP-CYBERARK",
                "services": "web"
            },
            {
                "ip": "10.20.23.63",
                "mac": "00:fd:45:fa:6f:4d",
                "name": "NEW-XEN",
                "services": "web"
            },
            {
                "ip": "10.20.23.65",
                "mac": "14:b3:1f:08:84:6d",
                "name": "PRIM-CYBERARK",
                "services": "web, shares"
            },
            {
                "ip": "10.20.23.62",
                "mac": "20:a6:cd:00:6e:70",
                "name": "SAP44",
                "services": "web, shares"
            },
            {
                "ip": "10.20.23.60",
                "mac": "90:b1:1c:73:64:fc",
                "name": "ARCOSNEW",
                "services": "web"
            }
        ]
    }
}
```

##### Human Readable Output
### IllusionBLACK Network Decoys
|Ip|Mac|Name|Services|
|---|---|---|---|
| 10.20.23.61 | d0:43:1e:cd:cb:c2 | CTX-BACKUPS31 | web |
| 10.20.23.64 | a0:48:1c:ee:08:38 | GCP-CYBERARK | web |
| 10.20.23.63 | 00:fd:45:fa:6f:4d | NEW-XEN | web |
| 10.20.23.65 | 14:b3:1f:08:84:6d | PRIM-CYBERARK | web, shares |
| 10.20.23.62 | 20:a6:cd:00:6e:70 | SAP44 | web, shares |
| 10.20.23.60 | 90:b1:1c:73:64:fc | ARCOSNEW | web |


### illusionblack-get-ti-decoys
***
Gets a list of Threat Intel decoys.


##### Base Command

`illusionblack-get-ti-decoys`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.TIDecoy | Unknown | IllusionBLACK TI Decoys. | 


##### Command Example
```!illusionblack-get-ti-decoys```

##### Context Example
```
{
    "IllusionBlack": {
        "TIDecoy": {
            "dataset": "Finacle",
            "ip": "10.20.23.67",
            "name": "dev.smokescreen.io",
            "server_type": "nginx/1.14.0 (Ubuntu)"
        }
    }
}
```

##### Human Readable Output
### IllusionBLACK TI Decoys
|Dataset|Ip|Name|Server Type|
|---|---|---|---|
| Finacle | 10.20.23.67 | dev.smokescreen.io | nginx/1.14.0 (Ubuntu) |


### illusionblack-is-host-decoy
***
Checks if a host or IP address is a network decoy.


##### Base Command

`illusionblack-is-host-decoy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Hostname or IP address to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.IsHostDecoy.Host | String | The IP address or hostname submitted to IllusionBLACK to check. | 
| IllusionBlack.IsHostDecoy.Value | Boolean | The boolean value whether the host is a decoy or not. | 


##### Command Example
```!illusionblack-is-host-decoy host="SAP44"```

##### Context Example
```
{
    "IllusionBlack": {
        "IsHostDecoy": {
            "Host": "SAP44",
            "Value": true
        }
    }
}
```

##### Human Readable Output
True

### illusionblack-is-user-decoy
***
Checks if an Active Directory user is a decoy.


##### Base Command

`illusionblack-is-user-decoy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Active Directory user name to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.IsUserDecoy.User | String | The AD username submitted to IllusionBLACK to check. | 
| IllusionBlack.IsUserDecoy.Value | Boolean | The boolean value whether the user is a decoy or not. | 


##### Command Example
```!illusionblack-is-user-decoy user="sqladmin"```

##### Context Example
```
{
    "IllusionBlack": {
        "IsUserDecoy": {
            "User": "sqladmin",
            "Value": true
        }
    }
}
```

##### Human Readable Output
True

### illusionblack-is-subdomain-decoy
***
Checks if a subdomain is a Threat Intel decoy.


##### Base Command

`illusionblack-is-subdomain-decoy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subdomain | Subdomain to check. For example: dec.smokescreen.io. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.IsSubdomainDecoy.Subdomain | String | The subdomain submitted to IllusionBLACK to check. | 
| IllusionBlack.IsSubdomainDecoy.Value | Boolean | The boolean value whether the subdomain is a decoy or not. | 


##### Command Example
```!illusionblack-is-subdomain-decoy subdomain="experience.illusionblack.com"```

##### Context Example
```
{
    "IllusionBlack": {
        "IsSubdomainDecoy": {
            "Subdomain": "experience.illusionblack.com",
            "Value": false
        }
    }
}
```

##### Human Readable Output
False

### illusionblack-get-events
***
Gets events from IllusionBLACK.


##### Base Command

`illusionblack-get-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of events. It can be between 1 and 1000. | Optional | 
| query | IllusionBLACK query. For example: &quot;attacker.ip is \&quot;1.2.3.4\&quot;&quot; | Optional | 
| from | ISO 8601 formatted date string. | Optional | 
| to | ISO 8601 formatted date string. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.Event | Unknown | IllusionBLACK Events. | 


##### Command Example
```!illusionblack-get-events limit=3```

##### Context Example
```
{
    "IllusionBlack": {
        "Event": [
            {
                "attacker.id": "ADMIN-PC-001\\admin",
                "attacker.name": "ADMIN-PC-001\\admin",
                "attacker.score": 175,
                "attacker.threat_parse_ids": [
                    "lm_file_open",
                    "lm_file_active_monitoring"
                ],
                "decoy.appliance.id": "cmc",
                "decoy.appliance.name": "CMC",
                "decoy.client.id": "experience",
                "decoy.client.name": "experience",
                "decoy.group": "Endpoint",
                "decoy.id": "endpoint:admin-pc-001",
                "decoy.name": "admin-pc-001",
                "decoy.type": "endpoint",
                "file.name": "C:\\Users\\admin\\Desktop\\passwords\\Passwords.xlsx",
                "file.operation": "67",
                "file.operation_string": "Read",
                "file.process.command_line": "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -executionpolicy bypass",
                "file.process.domain_name": "ADMIN-PC-001",
                "file.process.exit_code": -1,
                "file.process.id": "10228",
                "file.process.image_name": "powershell.exe",
                "file.process.user_name": "admin",
                "file.process.user_sid": "S-1-5-21-399445878-2258755057-882339928-1000",
                "file.thread_id": "8588",
                "id": "2020-02-25T09:49:15Z-76c99a22-03b9-439e-8638-37306c2d8e7f",
                "kill_chain_phase": "Data Theft",
                "mitre_ids": [
                    "T1005"
                ],
                "record_type": "event",
                "severity": "high",
                "sub_type": "file",
                "threat_parse_ids": [
                    "lm_file_open"
                ],
                "timestamp": "2020-04-12T08:57:01Z",
                "type": "endpoint",
                "whitelisted": false
            },
            {
                "attacker.id": "NT AUTHORITY\\SYSTEM",
                "attacker.name": "NT AUTHORITY\\SYSTEM",
                "attacker.score": 250,
                "attacker.threat_parse_ids": [
                    "filetheft_unattend",
                    "lm_file_active_monitoring",
                    "lm_file_open"
                ],
                "decoy.appliance.id": "cmc",
                "decoy.appliance.name": "CMC",
                "decoy.client.id": "experience",
                "decoy.client.name": "experience",
                "decoy.group": "Endpoint",
                "decoy.id": "endpoint:admin-pc-001",
                "decoy.name": "admin-pc-001",
                "decoy.type": "endpoint",
                "file.name": "C:\\Users\\admin\\Desktop\\passwords\\Passwords.xlsx",
                "file.operation": "67",
                "file.operation_string": "Read",
                "file.process.command_line": "",
                "file.process.domain_name": "NT AUTHORITY",
                "file.process.exit_code": -1,
                "file.process.id": "2824",
                "file.process.image_name": "MsMpEng.exe",
                "file.process.user_name": "SYSTEM",
                "file.process.user_sid": "S-1-5-18",
                "file.thread_id": "724",
                "id": "2020-02-25T09:49:15Z-0950f80f-7571-4382-b4b8-5e04c160c4c0",
                "kill_chain_phase": "Data Theft",
                "mitre_ids": [
                    "T1005"
                ],
                "record_type": "event",
                "severity": "high",
                "sub_type": "file",
                "threat_parse_ids": [
                    "lm_file_open"
                ],
                "timestamp": "2020-04-12T08:57:01Z",
                "type": "endpoint",
                "whitelisted": false
            },
            {
                "attacker.id": "ADMIN-PC-001\\admin",
                "attacker.name": "ADMIN-PC-001\\admin",
                "attacker.score": 175,
                "attacker.threat_parse_ids": [
                    "lm_file_open",
                    "lm_file_active_monitoring"
                ],
                "decoy.appliance.id": "cmc",
                "decoy.appliance.name": "CMC",
                "decoy.client.id": "experience",
                "decoy.client.name": "experience",
                "decoy.group": "Endpoint",
                "decoy.id": "endpoint:admin-pc-001",
                "decoy.name": "admin-pc-001",
                "decoy.type": "endpoint",
                "file.name": "C:\\Users\\admin\\Desktop\\docs\\vulnerability assessment report\\vulnerability assessment report.xlsx",
                "file.operation": "65",
                "file.operation_string": "Cleanup",
                "file.process.command_line": "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -executionpolicy bypass",
                "file.process.domain_name": "ADMIN-PC-001",
                "file.process.exit_code": -1,
                "file.process.id": "10228",
                "file.process.image_name": "powershell.exe",
                "file.process.user_name": "admin",
                "file.process.user_sid": "S-1-5-21-399445878-2258755057-882339928-1000",
                "file.thread_id": "0",
                "id": "2020-02-25T09:45:48Z-fa248a98-bc8a-4275-93c7-e63ff1ee8d34",
                "kill_chain_phase": "Data Theft",
                "mitre_ids": [
                    "T1005"
                ],
                "record_type": "event",
                "severity": "high",
                "sub_type": "file",
                "threat_parse_ids": [
                    "lm_file_active_monitoring"
                ],
                "timestamp": "2020-04-12T08:53:20Z",
                "type": "endpoint",
                "whitelisted": false
            }
        ]
    }
}
```

##### Human Readable Output
### IllusionBLACK Events
|attacker.id|attacker.name|attacker.score|attacker.threat_parse_ids|decoy.appliance.id|decoy.appliance.name|decoy.client.id|decoy.client.name|decoy.group|decoy.id|decoy.name|decoy.type|file.name|file.operation|file.operation_string|file.process.command_line|file.process.domain_name|file.process.exit_code|file.process.id|file.process.image_name|file.process.user_name|file.process.user_sid|file.thread_id|id|kill_chain_phase|mitre_ids|record_type|severity|sub_type|threat_parse_ids|timestamp|type|whitelisted|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADMIN-PC-001\admin | ADMIN-PC-001\admin | 175 | lm_file_open,<br/>lm_file_active_monitoring | cmc | CMC | experience | experience | Endpoint | endpoint:admin-pc-001 | admin-pc-001 | endpoint | C:\Users\admin\Desktop\passwords\Passwords.xlsx | 67 | Read | "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass | ADMIN-PC-001 | -1 | 10228 | powershell.exe | admin | S-1-5-21-399445878-2258755057-882339928-1000 | 8588 | 2020-02-25T09:49:15Z-76c99a22-03b9-439e-8638-37306c2d8e7f | Data Theft | T1005 | event | high | file | lm_file_open | 2020-04-12T08:57:01Z | endpoint | false |
| NT AUTHORITY\SYSTEM | NT AUTHORITY\SYSTEM | 250 | filetheft_unattend,<br/>lm_file_active_monitoring,<br/>lm_file_open | cmc | CMC | experience | experience | Endpoint | endpoint:admin-pc-001 | admin-pc-001 | endpoint | C:\Users\admin\Desktop\passwords\Passwords.xlsx | 67 | Read |  | NT AUTHORITY | -1 | 2824 | MsMpEng.exe | SYSTEM | S-1-5-18 | 724 | 2020-02-25T09:49:15Z-0950f80f-7571-4382-b4b8-5e04c160c4c0 | Data Theft | T1005 | event | high | file | lm_file_open | 2020-04-12T08:57:01Z | endpoint | false |
| ADMIN-PC-001\admin | ADMIN-PC-001\admin | 175 | lm_file_open,<br/>lm_file_active_monitoring | cmc | CMC | experience | experience | Endpoint | endpoint:admin-pc-001 | admin-pc-001 | endpoint | C:\Users\admin\Desktop\docs\vulnerability assessment report\vulnerability assessment report.xlsx | 65 | Cleanup | "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass | ADMIN-PC-001 | -1 | 10228 | powershell.exe | admin | S-1-5-21-399445878-2258755057-882339928-1000 | 0 | 2020-02-25T09:45:48Z-fa248a98-bc8a-4275-93c7-e63ff1ee8d34 | Data Theft | T1005 | event | high | file | lm_file_active_monitoring | 2020-04-12T08:53:20Z | endpoint | false |


### illusionblack-get-event-by-id
***
Gets a single event by the event ID.


##### Base Command

`illusionblack-get-event-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | IllusionBLACK Event ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IllusionBlack.Event | Unknown | IllusionBLACK Single Event. | 
| IllusionBlack.Event.attacker.id | Unknown | IllusionBLACK Event Attacker ID. | 
| IllusionBlack.Event.decoy.id | Unknown | IllusionBLACK Event Decoy ID. | 
| IllusionBlack.Event.id | Unknown | IllusionBLACK Event ID. | 
| IllusionBlack.Event.severity | Unknown | IllusionBLACK Event Severity. | 
| IllusionBlack.Event.type | Unknown | IllusionBLACK Event Attack Type. | 


##### Command Example
```!illusionblack-get-event-by-id id="2020-02-25T09:49:15Z-0950f80f-7571-4382-b4b8-5e04c160c4c0"```

##### Context Example
```
{
    "IllusionBlack": {
        "Event": {
            "attacker.id": "NT AUTHORITY\\SYSTEM",
            "attacker.name": "NT AUTHORITY\\SYSTEM",
            "attacker.score": 250,
            "attacker.threat_parse_ids": [
                "filetheft_unattend",
                "lm_file_active_monitoring",
                "lm_file_open"
            ],
            "decoy.appliance.id": "cmc",
            "decoy.appliance.name": "CMC",
            "decoy.client.id": "experience",
            "decoy.client.name": "experience",
            "decoy.group": "Endpoint",
            "decoy.id": "endpoint:admin-pc-001",
            "decoy.name": "admin-pc-001",
            "decoy.type": "endpoint",
            "file.name": "C:\\Users\\admin\\Desktop\\passwords\\Passwords.xlsx",
            "file.operation": "67",
            "file.operation_string": "Read",
            "file.process.command_line": "",
            "file.process.domain_name": "NT AUTHORITY",
            "file.process.exit_code": -1,
            "file.process.id": "2824",
            "file.process.image_name": "MsMpEng.exe",
            "file.process.user_name": "SYSTEM",
            "file.process.user_sid": "S-1-5-18",
            "file.thread_id": "724",
            "id": "2020-02-25T09:49:15Z-0950f80f-7571-4382-b4b8-5e04c160c4c0",
            "kill_chain_phase": "Data Theft",
            "mitre_ids": [
                "T1005"
            ],
            "record_type": "event",
            "severity": "high",
            "sub_type": "file",
            "threat_parse_ids": [
                "lm_file_open"
            ],
            "timestamp": "2020-04-12T08:57:01Z",
            "type": "endpoint",
            "whitelisted": false
        }
    }
}
```

##### Human Readable Output
### IllusionBLACK Single Event
|attacker.id|attacker.name|attacker.score|attacker.threat_parse_ids|decoy.appliance.id|decoy.appliance.name|decoy.client.id|decoy.client.name|decoy.group|decoy.id|decoy.name|decoy.type|file.name|file.operation|file.operation_string|file.process.command_line|file.process.domain_name|file.process.exit_code|file.process.id|file.process.image_name|file.process.user_name|file.process.user_sid|file.thread_id|id|kill_chain_phase|mitre_ids|record_type|severity|sub_type|threat_parse_ids|timestamp|type|whitelisted|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| NT AUTHORITY\SYSTEM | NT AUTHORITY\SYSTEM | 250 | filetheft_unattend,<br/>lm_file_active_monitoring,<br/>lm_file_open | cmc | CMC | experience | experience | Endpoint | endpoint:admin-pc-001 | admin-pc-001 | endpoint | C:\Users\admin\Desktop\passwords\Passwords.xlsx | 67 | Read |  | NT AUTHORITY | -1 | 2824 | MsMpEng.exe | SYSTEM | S-1-5-18 | 724 | 2020-02-25T09:49:15Z-0950f80f-7571-4382-b4b8-5e04c160c4c0 | Data Theft | T1005 | event | high | file | lm_file_open | 2020-04-12T08:57:01Z | endpoint | false |
