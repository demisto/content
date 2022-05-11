This is the Gatewatcher integration for getting started.
This integration was integrated and tested with version v2.5.3.102 of Gcenterv102

## Configure GCenter v2.5.3.102 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GCenter v2.5.3.102.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | GCenter IP address | True |
    | GCenter API token | False |
    | GCenter username | False |
    | GCenter password | False |
    | Check the TLS certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gw-list-alerts
***
List all alerts


#### Base Command

`gw-list-alerts`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
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

There is no context output for this command.
### gw-es-query
***
Get Elasticsearch data


#### Base Command

`gw-es-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| index | Index to be queried. Possible values are: suricata, malware, codebreaker, netdata, syslog. Default is suricata. | Required | 
| query | Elaticsearch query. Default is {}. | Required | 


#### Context Output

There is no context output for this command.
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
| GCenter.Malcore.sha256 | String |  | 
| GCenter.Malcore.created | Date |  | 
| GCenter.Malcore.comment | String |  | 
| GCenter.Malcore.threat | String |  | 

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
| GCenter.Dga.domain_name | String |  | 
| GCenter.Dga.created | Date |  | 
| GCenter.Dga.comment | String |  | 
| GCenter.Dga.is_wildcard | Boolean |  | 

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
| GCenter.Ignore.AssetName.id | String |  | 
| GCenter.Ignore.AssetName.created_at | Date |  | 
| GCenter.Ignore.AssetName.created_by | String |  | 
| GCenter.Ignore.AssetName.name | String |  | 
| GCenter.Ignore.AssetName.is_startswith_pattern | Boolean |  | 
| GCenter.Ignore.AssetName.is_endswith_pattern | Boolean |  | 

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
| GCenter.Ignore.KuserIP.id | String |  | 
| GCenter.Ignore.KuserIP.created_at | Date |  | 
| GCenter.Ignore.KuserIP.created_by | String |  | 
| GCenter.Ignore.KuserIP.ip | String |  | 

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
| GCenter.Ignore.KuserName.id | String |  | 
| GCenter.Ignore.KuserName.created_at | Date |  | 
| GCenter.Ignore.KuserName.created_by | String |  | 
| GCenter.Ignore.KuserName.name | String |  | 
| GCenter.Ignore.KuserName.is_startswith_pattern | Boolean |  | 
| GCenter.Ignore.KuserName.is_endswith_pattern | Boolean |  | 

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
| GCenter.Ignore.MacAddress.id | String |  | 
| GCenter.Ignore.MacAddress.created_at | Date |  | 
| GCenter.Ignore.MacAddress.created_by | String |  | 
| GCenter.Ignore.MacAddress.address | String |  | 
| GCenter.Ignore.MacAddress.is_startswith_pattern | Boolean |  | 

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
### gw-send-malware
***
Send malware


#### Base Command

`gw-send-malware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filename. | Required | 
| content | File content. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Malware.id | String |  | 
| GCenter.Gscan.Malware.created | Date |  | 
| GCenter.Gscan.Malware.username | String |  | 
| GCenter.Gscan.Malware.user_agent | String |  | 
| GCenter.Gscan.Malware.ip_address | String |  | 
| GCenter.Gscan.Malware.file_name | String |  | 
| GCenter.Gscan.Malware.sha256 | String |  | 
| GCenter.Gscan.Malware.is_clean | Unknown |  | 
| GCenter.Gscan.Malware.is_analysis_successful | Boolean |  | 
| GCenter.Gscan.Malware.malcore_code_result | String |  | 
| GCenter.Gscan.Malware.threat_name | String |  | 
| GCenter.Gscan.Malware.nb_alerts | Number |  | 
| GCenter.Gscan.Malware.nb_engines | Number |  | 
| GCenter.Gscan.Malware.is_whiteblack_listed | Boolean |  | 
| GCenter.Gscan.Malware.malcore_code_result_name | String |  | 
| GCenter.Gscan.Malware.status | String |  | 

### gw-send-powershell
***
Send powershell


#### Base Command

`gw-send-powershell`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filename. | Required | 
| content | File content. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Powershell.id | String |  | 
| GCenter.Gscan.Powershell.created | Date |  | 
| GCenter.Gscan.Powershell.username | String |  | 
| GCenter.Gscan.Powershell.user_agent | String |  | 
| GCenter.Gscan.Powershell.ip_address | String |  | 
| GCenter.Gscan.Powershell.file_name | String |  | 
| GCenter.Gscan.Powershell.sha256 | String |  | 
| GCenter.Gscan.Powershell.is_clean | Boolean |  | 
| GCenter.Gscan.Powershell.is_analysis_successful | Boolean |  | 
| GCenter.Gscan.Powershell.status | String |  | 
| GCenter.Gscan.Powershell.proba_obfuscated | Number |  | 
| GCenter.Gscan.Powershell.analysis_score | Number |  | 
| GCenter.Gscan.Powershell.is_whiteblack_listed | Boolean |  | 

### gw-send-shellcode
***
Send shellcode


#### Base Command

`gw-send-shellcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filename. | Required | 
| content | File content. | Required | 
| deep | Deep scan. | Required | 
| timeout | Deep scan timeout. Default is 120. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCenter.Gscan.Shellcode.id | String |  | 
| GCenter.Gscan.Shellcode.created | Date |  | 
| GCenter.Gscan.Shellcode.username | String |  | 
| GCenter.Gscan.Shellcode.user_agent | String |  | 
| GCenter.Gscan.Shellcode.ip_address | String |  | 
| GCenter.Gscan.Shellcode.file_name | String |  | 
| GCenter.Gscan.Shellcode.sha256 | String |  | 
| GCenter.Gscan.Shellcode.is_clean | Boolean |  | 
| GCenter.Gscan.Shellcode.is_analysis_successful | Boolean |  | 
| GCenter.Gscan.Shellcode.status | String |  | 
| GCenter.Gscan.Shellcode.architecture | Unknown |  | 
| GCenter.Gscan.Shellcode.is_whiteblack_listed | Boolean |  | 
