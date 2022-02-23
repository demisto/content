FireEye Endpoint Security is an integrated solution that detects what others miss and protects endpoint against known and unknown threats. This  integration provides access to information about endpoints, acquisitions, alerts, indicators, and containment. Customers can extract critical data and effectively operate security operations automated playbook


Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-fireeye-endpoint-security-(hx)-v2).

## Configure FireEye Endpoint Security (HX) v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEye Endpoint Security (HX) v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1:3000) | True |
    | User Name | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Fetch limit | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 3 days) | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-hx-get-host-information
***
Get information on a host associated with an agent.


#### Base Command

`fireeye-hx-get-host-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The agent ID. If the agent ID is not specified, the host Name must be specified. | Optional | 
| hostName | The host name. If the host name is not specified, the agent ID must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal,contain,contain_fail,containing,contained,uncontain,uncontaining,wtfc,wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

#### Command example
```!fireeye-hx-get-host-information hostName=XXX```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": {
            "_id": "YYYns3oui1fpzgYYY",
            "agent_version": "31.28.17",
            "containment_missing_software": false,
            "containment_queued": false,
            "containment_state": "normal",
            "domain": "WORKGROUP",
            "excluded_from_containment": false,
            "gmt_offset_seconds": -28800,
            "hostname": "XXX",
            "initial_agent_checkin": "2021-03-21T13:27:48.058Z",
            "last_alert": {
                "_id": 365,
                "url": "/hx/api/v3/alerts/365"
            },
            "last_alert_timestamp": "2022-02-23T07:28:34.043+00:00",
            "last_audit_timestamp": "2022-02-23T07:28:33.969Z",
            "last_exploit_block": null,
            "last_exploit_block_timestamp": null,
            "last_poll_ip": "192.168.1.163",
            "last_poll_timestamp": "2022-02-23T09:08:31.000Z",
            "os": {
                "bitness": "64-bit",
                "kernel_version": null,
                "patch_level": null,
                "platform": "win",
                "product_name": "Windows 10 Pro"
            },
            "primary_ip_address": "192.168.1.163",
            "primary_mac": "00-50-56-89-1c-5b",
            "reported_clone": false,
            "stats": {
                "acqs": 15,
                "alerting_conditions": 1,
                "alerts": 1,
                "exploit_alerts": 0,
                "exploit_blocks": 0,
                "false_positive_alerts": 0,
                "false_positive_alerts_by_source": {},
                "generic_alerts": 0,
                "malware_alerts": 0,
                "malware_cleaned_count": 0,
                "malware_false_positive_alerts": 0,
                "malware_quarantined_count": 0
            },
            "sysinfo": {
                "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY/sysinfo"
            },
            "timezone": "Pacific Standard Time",
            "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Get Host Information
>|Host Name|Host IP|Agent ID|Agent Version|OS|Last Poll|Containment State|Domain|Last Alert|
>|---|---|---|---|---|---|---|---|---|
>| XXX | 192.168.1.163 | YYYns3oui1fpzgYYY | 31.28.17 | win | 2022-02-23T09:08:31.000Z | normal | WORKGROUP | _id: 365<br/>url: /hx/api/v3/alerts/365 |


### fireeye-hx-get-all-hosts-information
***
Get information on all hosts.


#### Base Command

`fireeye-hx-get-all-hosts-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal,contain,contain_fail,containing,contained,uncontain,uncontaining,wtfc,wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

#### Command example
```!fireeye-hx-get-all-hosts-information limit=1```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": {
            "Agent ID": "YYYns3oui1fpzgYYY",
            "Agent Version": "31.28.17",
            "Containment State": "normal",
            "Domain": "WORKGROUP",
            "Host IP": "192.168.1.163",
            "Host Name": "XXX",
            "Last Alert": {
                "_id": 365,
                "url": "/hx/api/v3/alerts/365"
            },
            "Last Poll": "2022-02-23T09:08:31.000Z",
            "OS": "win"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Get Hosts Information
>|Host Name|Host IP|Agent ID|Agent Version|OS|Last Poll|Containment State|Domain|Last Alert|
>|---|---|---|---|---|---|---|---|---|
>| XXX | 192.168.1.163 | YYYns3oui1fpzgYYY | 31.28.17 | win | 2022-02-23T09:08:31.000Z | normal | WORKGROUP | _id: 365<br/>url: /hx/api/v3/alerts/365 |


### fireeye-hx-host-containment
***
Apply containment for a specific host, so that it no longer has access to other systems, If the user does not have the necessary permissions, the command will not approve the request, The permissions necessary to approve the request are api_admin role.


#### Base Command

`fireeye-hx-host-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostName | The host name to be contained. If the hostName is not specified, the agentId must be specified. | Optional | 
| agentId | The agent id running on the host to be contained. If the agentId is not specified, the hostName must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal,contain,contain_fail,containing,contained,uncontain,uncontaining,wtfc,wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

#### Command example
```!fireeye-hx-host-containment hostName=XXX```
#### Context Example
```json
{
    "Endpoint": {
        "Domain": "WORKGROUP",
        "Hostname": "XXX",
        "ID": "YYYns3oui1fpzgYYY",
        "IPAddress": "192.168.1.163",
        "MACAddress": "00-50-56-89-1c-5b",
        "OS": "win",
        "OSVersion": "Windows 10 Pro"
    },
    "FireEyeHX": {
        "Hosts": {
            "_id": "YYYns3oui1fpzgYYY",
            "agent_version": "31.28.17",
            "containment_missing_software": false,
            "containment_queued": true,
            "containment_state": "contain",
            "domain": "WORKGROUP",
            "excluded_from_containment": false,
            "gmt_offset_seconds": -28800,
            "hostname": "XXX",
            "initial_agent_checkin": "2021-03-21T13:27:48.058Z",
            "last_alert": {
                "_id": 365,
                "url": "/hx/api/v3/alerts/365"
            },
            "last_alert_timestamp": "2022-02-23T07:28:34.043+00:00",
            "last_audit_timestamp": "2022-02-23T07:28:33.969Z",
            "last_exploit_block": null,
            "last_exploit_block_timestamp": null,
            "last_poll_ip": "192.168.1.163",
            "last_poll_timestamp": "2022-02-23T09:08:31.000Z",
            "os": {
                "bitness": "64-bit",
                "kernel_version": null,
                "patch_level": null,
                "platform": "win",
                "product_name": "Windows 10 Pro"
            },
            "primary_ip_address": "192.168.1.163",
            "primary_mac": "00-50-56-89-1c-5b",
            "reported_clone": false,
            "stats": {
                "acqs": 15,
                "alerting_conditions": 1,
                "alerts": 1,
                "exploit_alerts": 0,
                "exploit_blocks": 0,
                "false_positive_alerts": 0,
                "false_positive_alerts_by_source": {},
                "generic_alerts": 0,
                "malware_alerts": 0,
                "malware_cleaned_count": 0,
                "malware_false_positive_alerts": 0,
                "malware_quarantined_count": 0
            },
            "sysinfo": {
                "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY/sysinfo"
            },
            "timezone": "Pacific Standard Time",
            "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Domain|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|
>|---|---|---|---|---|---|---|
>| WORKGROUP | XXX | YYYns3oui1fpzgYYY | 192.168.1.163 | 00-50-56-89-1c-5b | win | Windows 10 Pro |


### fireeye-hx-cancel-containment
***
Release a specific host from containment.


#### Base Command

`fireeye-hx-cancel-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostName | The host name to be contained. If the hostName is not specified, the agentId must be specified. | Optional | 
| agentId | The agent id running on the host to be contained. If the agentId is not specified, the hostName must be specified. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-cancel-containment hostName=XXX```
#### Human Readable Output

>Success

### fireeye-hx-initiate-data-acquisition
***
Initiate a data acquisition process to gather artifacts from the system disk and memory.


#### Base Command

`fireeye-hx-initiate-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | string | The acquisition state | 
| FireEyeHX.Acquisitions.Data.md5 | string | File md5 | 
| FireEyeHX.Acquisitions.Data.host._id | string | Agent ID | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | string | FIreEye HX instance | 
| FireEyeHX.Acquisitions.Data.finish_time | date | Time when the acquisition finished | 

### fireeye-hx-get-host-set-information
***
Get a list of all host sets known to your HX Series appliance.


#### Base Command

`fireeye-hx-get-host-set-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetID | ID of a specific host set to get. | Optional | 
| offset | Specifies which record to start with in the response. The offset value must be an unsigned 32-bit integer. The default is 0. | Optional | 
| limit | Specifies how many records are returned. The limit value must be an unsigned 32-bit integer. The default is 50. | Optional | 
| search | Searches the names of all host sets connected to the specified HX appliance. | Optional | 
| sort | Sorts the results by the specified field in ascending or descending order. The default is sorting by name in ascending order. Sortable fields are _id (host set ID) and name (host set name). | Optional | 
| name | Specifies the name of host set to look for. | Optional | 
| type | Specifies the type of host sets to search for. Possible values are: venn, static. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | number | host set id | 
| FireEyeHX.HostSets._revision | string | Revision number | 
| FireEyeHX.HostSets.name | string | Host set name | 
| FireEyeHX.HostSets.type | string | Host set type \(static/dynamic/hidden\) | 
| FireEyeHX.HostSets.url | string | Host set FireEye url | 

#### Command example
```!fireeye-hx-get-host-set-information hostSetID=1001```
#### Context Example
```json
{
    "FireEyeHX": {
        "HostSets": {
            "_id": 1001,
            "_revision": "20210308150955358783164361",
            "name": "Demisto",
            "type": "venn",
            "url": "/hx/api/v3/host_sets/1001"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Get Host Sets Information
>|Name|ID|Type|
>|---|---|---|
>| Demisto | 1001 | venn |


### fireeye-hx-list-policy
***
Get a list of all policy.


#### Base Command

`fireeye-hx-list-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| policyName | The name of the policy. | Optional | 
| policyId | Unique policy ID. | Optional | 
| enabled | The policy is enabled ("true") or disabled ("false"). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Policy._id | Unknown | Unique policy ID | 
| FireEyeHX.Policy.name | Unknown | The name of the policy | 
| FireEyeHX.Policy.description | Unknown | Description of the policy | 
| FireEyeHX.Policy.policy_type_id | Unknown | Unique policy type ID | 
| FireEyeHX.Policy.priority | Unknown | The priority order of the policy | 
| FireEyeHX.Policy.enabled | Unknown | The policy is enabled ("true") or disabled ("false") | 
| FireEyeHX.Policy.default | Unknown | True if it is the default policy. There can only be one policy marked as default | 
| FireEyeHX.Policy.migrated | Unknown | True if it is a migrated policy | 
| FireEyeHX.Policy.created_by | Unknown | The user who created the policy | 
| FireEyeHX.Policy.created_at | Unknown | Time the policy was first created | 
| FireEyeHX.Policy.updated_at | Unknown | Time the policy was last updated | 
| FireEyeHX.Policy.categories | Unknown | Collection of categories the policy is associated with | 
| FireEyeHX.Policy.display_created_at | Unknown | Time since the display was first created | 
| FireEyeHX.Policy.display_updated_at | Unknown | Time since the display was last updated | 

#### Command example
```!fireeye-hx-list-policy limit=2 policyName=Demisto```
#### Context Example
```json
{
    "FireEyeHX": {
        "Policy": {
            "data": {
                "entries": [],
                "limit": 2,
                "offset": 0,
                "query": {
                    "limit": "2",
                    "name": "Demisto",
                    "offset": "0"
                },
                "sort": {},
                "total": 0
            },
            "details": [],
            "message": "OK",
            "route": "/hx/api/v3/policies"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX List Policies
>**No entries.**


### fireeye-hx-list-host-set-policy
***
Get a list of all policies for all host sets.


#### Base Command

`fireeye-hx-list-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| hostSetId | The host set ID | Optional | 
| policyId | Unique policy ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets.Policy.policy_id | Unknown | Unique policy ID | 
| FireEyeHX.HostSets.Policy.persist_id | Unknown | The host set ID | 

#### Command example
```!fireeye-hx-list-host-set-policy limit=1```
#### Context Example
```json
{
    "FireEyeHX": {
        "HostSets": {
            "Policy": [
                {
                    "persist_id": 1001,
                    "policy_id": "YYYYY-d452-4685-a8b5-afbeYYYY"
                },
                {
                    "persist_id": 1002,
                    "policy_id": "YYYYY-d452-4685-a8b5-afbeYYYY"
                },
                {
                    "persist_id": 1005,
                    "policy_id": "YYYYY-5471-4ae1-918d-YYYYY"
                },
                {
                    "persist_id": 1005,
                    "policy_id": "YYYYY-d452-4685-a8b5-afbeYYYY"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Host Set Policies
>|Policy Id|Host Set Id|
>|---|---|
>| YYYYY-d452-4685-a8b5-afbeYYYY | 1001 |
>| YYYYY-d452-4685-a8b5-afbeYYYY | 1002 |
>| YYYYY-5471-4ae1-918d-YYYYY | 1005 |
>| YYYYY-d452-4685-a8b5-afbeYYYY | 1005 |


### fireeye-hx-list-containment
***
Fetches all containment states across known hosts.


#### Base Command

`fireeye-hx-list-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| state_update_time | must be from type of -&gt; String: date-time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown |   | 
| FireEyeHX.Hosts.last_sysinfo | Unknown |   | 
| FireEyeHX.Hosts.requested_by_actor | Unknown |   | 
| FireEyeHX.Hosts.requested_on | Unknown |   | 
| FireEyeHX.Hosts.contained_by_actor | Unknown |   | 
| FireEyeHX.Hosts.contained_on | Unknown |   | 
| FireEyeHX.Hosts.queued | Unknown |   | 
| FireEyeHX.Hosts.excluded | Unknown |   | 
| FireEyeHX.Hosts.missing_software | Unknown |   | 
| FireEyeHX.Hosts.reported_clone | Unknown |   | 
| FireEyeHX.Hosts.state | Unknown |   | 
| FireEyeHX.Hosts.state_update_time | Unknown |   | 
| FireEyeHX.Hosts.url | Unknown |   | 

#### Command example
```!fireeye-hx-list-containment limit=2```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": [
            {
                "_id": "YYYns3oui1fpzgYYY",
                "contained_by_actor": null,
                "contained_on": null,
                "excluded": false,
                "last_sysinfo": "2022-02-23T07:28:33.969Z",
                "missing_software": false,
                "queued": false,
                "reported_clone": false,
                "requested_by_actor": null,
                "requested_on": null,
                "state": "normal",
                "state_update_time": "2022-02-22T14:00:31.056Z",
                "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
            },
            {
                "_id": "YYYY4zpidezwYYYY",
                "contained_by_actor": null,
                "contained_on": null,
                "excluded": false,
                "last_sysinfo": "2022-02-23T08:23:25.592Z",
                "missing_software": false,
                "queued": false,
                "reported_clone": false,
                "requested_by_actor": null,
                "requested_on": null,
                "state": "normal",
                "state_update_time": "2021-03-17T12:54:56.481Z",
                "url": "/hx/api/v3/hosts/YYYY4zpidezwYYYY"
            }
        ]
    }
}
```

#### Human Readable Output

>### List Containment
>|Id|State|Request Origin|Request Date|Containment Origin|Containment Date|Last System information date|
>|---|---|---|---|---|---|---|
>| YYYns3oui1fpzgYYY | normal |  |  |  |  | 2022-02-23T07:28:33.969Z |
>| YYYY4zpidezwYYYY | normal |  |  |  |  | 2022-02-23T08:23:25.592Z |


### fireeye-hx-search-list
***
Fetches all enterprise searches.


#### Base Command

`fireeye-hx-search-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Specifies how many records are returned, The default is 50. | Optional | 
| state | Filter by search state, you can choose between STOPPED or RUNNING. Possible values are: RUNNING, STOPPED. | Optional | 
| sort | Sorts the results by the specified field, The default is sorting by _id. Possible values are: _id, state, host_set._id, update_time, create_time, update_actor._id, update_actor.username, create_actor._id, create_actor.username. | Optional | 
| hostSetId | Filter searches by host set ID - &lt;Integer&gt;. | Optional | 
| searchId | Gets a single enterprise search record, If you enter this argument there is no need another arguments. | Optional | 
| actorUsername | Filter searches by username that created searches - &lt;String&gt;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Unknown | Unique search ID | 
| FireEyeHX.Search.state | Unknown | The state of the search whether it stopped or running | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search | 
| FireEyeHX.Search.update_time | Unknown | Time the search was updated last | 
| FireEyeHX.Search.create_time | Unknown | Time the search was created | 
| FireEyeHX.Search.scripts.platform | Unknown | Platform this script is used for | 
| FireEyeHX.Search.update_actor | Unknown | Actor who last updated the search | 
| FireEyeHX.Search.create_actor | Unknown | Actor who created the search | 
| FireEyeHX.Search.error | Unknown | Collection of errors per agents for the search | 
| FireEyeHX.Search._revision | Unknown | ETag that can be used for concurrency checking | 
| FireEyeHX.Search.input_type | Unknown | The input method that was used to start the search | 
| FireEyeHX.Search.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host_set | Unknown | Host Set infomaition | 
| FireEyeHX.Search.stats | Unknown |  | 
| FireEyeHX.Search.stats.hosts | Unknown | Number of hosts running this operation | 
| FireEyeHX.Search.stats.skipped_hosts | Unknown | Number of hosts that were skipped | 
| FireEyeHX.Search.stats.search_state | Unknown | Number of search in different states | 
| FireEyeHX.Search.stats.search_issues | Unknown | Issues encountered for searches | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown |  | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown |  | 
| FireEyeHX.Search.stats.settings.search_type | Unknown | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | Unknown | Whether a search is exhaustive or not | 
| FireEyeHX.Search.stats.settings.mode | Unknown | Whether a search is HOST type or GRID type | 
| FireEyeHX.Search.stats.settings.displayname | Unknown | Name of the search | 

#### Command example
```!fireeye-hx-search-list limit=1```
#### Context Example
```json
{
    "FireEyeHX": {
        "Search": {
            "_id": 143,
            "_revision": "20220223091811214662597541",
            "create_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "create_time": "2022-02-23T09:18:11.214Z",
            "error": null,
            "host_set": null,
            "input_type": "api",
            "scripts": [
                {
                    "_id": "0864f1d46dd470c9934de71584dd95f6d91a714e",
                    "download": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e.json",
                    "platform": "win",
                    "url": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e"
                },
                {
                    "_id": "0864f1d46dd470c9934de71584dd95f6d91a714e",
                    "download": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e.json",
                    "platform": "osx",
                    "url": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e"
                }
            ],
            "settings": {
                "displayname": null,
                "exhaustive": true,
                "mode": "HOST",
                "query_terms": {
                    "exhaustive_terms": [],
                    "terms": [
                        {
                            "field": "IP Address",
                            "operator": "equals",
                            "value": "8.8.8.8"
                        }
                    ]
                },
                "search_type": "QUERY"
            },
            "state": "RUNNING",
            "stats": {
                "hosts": 1,
                "running_state": {
                    "ABORTED": 0,
                    "CANCELLED": 0,
                    "COMPLETE": 0,
                    "DELETED": 0,
                    "FAILED": 0,
                    "NEW": 1,
                    "QUEUED": 0,
                    "REFRESH": 0
                },
                "search_issues": {},
                "search_state": {
                    "ERROR": 0,
                    "MATCHED": 0,
                    "NOT_MATCHED": 0,
                    "PENDING": 1
                },
                "skipped_hosts": 0
            },
            "update_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "update_time": "2022-02-23T09:18:11.214Z",
            "url": "/hx/api/v3/searches/143"
        }
    }
}
```

#### Human Readable Output

>|Id|State|Host Set|Created By|Created At|Updated By|Updated At|
>|---|---|---|---|---|---|---|
>| 143 | RUNNING |  | _id: 1001<br/>username: test-admin | 2022-02-23T09:18:11.214Z | _id: 1001<br/>username: test-admin | 2022-02-23T09:18:11.214Z |


### fireeye-hx-search-stop
***
Stops a specific running search.


#### Base Command

`fireeye-hx-search-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | Unique search ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Unknown | Unique search ID | 
| FireEyeHX.Search.state | Unknown | The state of the search whether it stopped or running | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search | 
| FireEyeHX.Search.update_time | Unknown | Time the search was updated last | 
| FireEyeHX.Search.create_time | Unknown | Time the search was created | 
| FireEyeHX.Search.scripts.platform | Unknown | Platform this script is used for | 
| FireEyeHX.Search.update_actor | Unknown | Actor who last updated the search | 
| FireEyeHX.Search.create_actor | Unknown | Actor who created the search | 
| FireEyeHX.Search.error | Unknown | Collection of errors per agents for the search | 
| FireEyeHX.Search._revision | Unknown | ETag that can be used for concurrency checking | 
| FireEyeHX.Search.input_type | Unknown | The input method that was used to start the search | 
| FireEyeHX.Search.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host_set | Unknown | Host Set informaition | 
| FireEyeHX.Search.stats | Unknown |  | 
| FireEyeHX.Search.stats.hosts | Unknown | Number of hosts running this operation | 
| FireEyeHX.Search.stats.skipped_hosts | Unknown | Number of hosts that were skipped | 
| FireEyeHX.Search.stats.search_state | Unknown | Number of search in different states | 
| FireEyeHX.Search.stats.search_issues | Unknown | Issues encountered for searches | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown |  | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown |  | 
| FireEyeHX.Search.stats.settings.search_type | Unknown | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | Unknown | Whether a search is exhaustive or not | 
| FireEyeHX.Search.stats.settings.mode | Unknown | Whether a search is HOST type or GRID type | 
| FireEyeHX.Search.stats.settings.displayname | Unknown | Name of the search | 

#### Command example
```!fireeye-hx-search-stop searchId=141```
#### Context Example
```json
{
    "FireEyeHX": {
        "Search": {
            "_id": 141,
            "_revision": "20220223091838188310597550",
            "create_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "create_time": "2022-02-23T09:05:54.645Z",
            "error": null,
            "host_set": null,
            "input_type": "api",
            "scripts": [
                {
                    "_id": "0864f1d46dd470c9934de71584dd95f6d91a714e",
                    "download": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e.json",
                    "platform": "win",
                    "url": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e"
                },
                {
                    "_id": "0864f1d46dd470c9934de71584dd95f6d91a714e",
                    "download": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e.json",
                    "platform": "osx",
                    "url": "/hx/api/v3/scripts/0864f1d46dd470c9934de71584dd95f6d91a714e"
                }
            ],
            "settings": {
                "displayname": null,
                "exhaustive": true,
                "mode": "HOST",
                "query_terms": {
                    "exhaustive_terms": [],
                    "terms": [
                        {
                            "field": "IP Address",
                            "operator": "equals",
                            "value": "8.8.8.8"
                        }
                    ]
                },
                "search_type": "QUERY"
            },
            "state": "STOPPED",
            "stats": {
                "hosts": 1,
                "running_state": {
                    "ABORTED": 0,
                    "CANCELLED": 0,
                    "COMPLETE": 1,
                    "DELETED": 0,
                    "FAILED": 0,
                    "NEW": 0,
                    "QUEUED": 0,
                    "REFRESH": 0
                },
                "search_issues": {},
                "search_state": {
                    "ERROR": 0,
                    "MATCHED": 1,
                    "NOT_MATCHED": 0,
                    "PENDING": 0
                },
                "skipped_hosts": 0
            },
            "update_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "update_time": "2022-02-23T09:18:38.188Z",
            "url": "/hx/api/v3/searches/141"
        }
    }
}
```

#### Human Readable Output

>Results
>Search Id 141: Success

### fireeye-hx-search-result-get
***
Fetches the result for a specific enterprise search.


#### Base Command

`fireeye-hx-search-result-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | Unique search ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.host._id | Unknown | Unique agent ID | 
| FireEyeHX.Search.host.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host.hostname | Unknown | Name of the host | 
| FireEyeHX.Search.results._id | Unknown | Unique ID | 
| FireEyeHX.Search.results.type | Unknown | Type of the search result data | 
| FireEyeHX.Search.results.data | Unknown | Object containing data relating to the search result for the host | 

#### Command example
```!fireeye-hx-search-result-get searchId=141```
#### Context Example
```json
{
    "FireEyeHX": {
        "Search": {
            "host": {
                "_id": "YYYns3oui1fpzgYYY",
                "hostname": "XXX",
                "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
            },
            "results": [
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "64924",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-01-20T09:41:51.470Z",
                        "Timestamp - Event": "2022-01-20T09:41:51.470Z",
                        "Username": "XXX\\User"
                    },
                    "id": 1,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "64925",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-01-20T09:41:51.470Z",
                        "Timestamp - Event": "2022-01-20T09:41:51.470Z",
                        "Username": "XXX\\User"
                    },
                    "id": 2,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "64926",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-01-20T09:41:51.470Z",
                        "Timestamp - Event": "2022-01-20T09:41:51.470Z",
                        "Username": "XXX\\User"
                    },
                    "id": 3,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "56687",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-01-31T06:56:37.591Z",
                        "Timestamp - Event": "2022-01-31T06:56:37.591Z",
                        "Username": "XXX\\User"
                    },
                    "id": 4,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "58763",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-02-01T07:51:38.928Z",
                        "Timestamp - Event": "2022-02-01T07:51:38.928Z",
                        "Username": "XXX\\User"
                    },
                    "id": 5,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "58766",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-02-01T07:53:03.630Z",
                        "Timestamp - Event": "2022-02-01T07:53:03.630Z",
                        "Username": "XXX\\User"
                    },
                    "id": 6,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "59099",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-02-01T12:04:14.969Z",
                        "Timestamp - Event": "2022-02-01T12:04:14.969Z",
                        "Username": "XXX\\User"
                    },
                    "id": 7,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "55107",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-02-07T10:51:46.951Z",
                        "Timestamp - Event": "2022-02-07T10:51:46.951Z",
                        "Username": "XXX\\User"
                    },
                    "id": 8,
                    "type": "IPv4 Network Event"
                },
                {
                    "data": {
                        "IP Address": "8.8.8.8",
                        "Local IP Address": "192.168.1.163",
                        "Local Port": "55107",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "8.8.8.8",
                        "Remote Port": "443",
                        "Timestamp - Accessed": "2022-02-07T10:53:17.233Z",
                        "Timestamp - Event": "2022-02-07T10:53:17.233Z",
                        "Username": "XXX\\User"
                    },
                    "id": 9,
                    "type": "IPv4 Network Event"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Host Id YYYns3oui1fpzgYYY
>Host Name XXX
>|Item Type|Summary|
>|---|---|
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 64924,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 64925,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 64926,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 56687,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-31T06:56:37.591Z,<br/>**Timestamp - Accessed:** 2022-01-31T06:56:37.591Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 58763,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T07:51:38.928Z,<br/>**Timestamp - Accessed:** 2022-02-01T07:51:38.928Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 58766,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T07:53:03.630Z,<br/>**Timestamp - Accessed:** 2022-02-01T07:53:03.630Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 59099,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T12:04:14.969Z,<br/>**Timestamp - Accessed:** 2022-02-01T12:04:14.969Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 55107,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-07T10:51:46.951Z,<br/>**Timestamp - Accessed:** 2022-02-07T10:51:46.951Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** 192.168.1.163,<br/>**Remote IP Address:** 8.8.8.8,<br/>**IP Address:** 8.8.8.8,<br/>**Port:** 443,<br/>**Local Port:** 55107,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-07T10:53:17.233Z,<br/>**Timestamp - Accessed:** 2022-02-07T10:53:17.233Z |


### fireeye-hx-search
***
Search endpoints to check all hosts or a subset of hosts for a specific file or indicator.


#### Base Command

`fireeye-hx-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | searchId. | Optional | 
| agentsIds | IDs of agents to be searched. | Optional | 
| hostsNames | Names of hosts to be searched. | Optional | 
| hostSet | Id of host set to be searched. | Optional | 
| hostSetName | Name of host set to be searched. | Optional | 
| limit | Limit results count (once limit is reached, the search is stopped). | Optional | 
| exhaustive | Should search be exhaustive or quick. Possible values are: yes, no. Default is True. | Optional | 
| ipAddress | A valid IPv4 address to search for. | Optional | 
| ipAddressOperator | Which operator to apply to the given IP address. Possible values are: equals, not equals. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| fileMD5Hash | A 32-character MD5 hash value to search for. | Optional | 
| fileMD5HashOperator | Which operator to apply to the given MD5 hash. Possible values are: equals, not equals. | Optional | 
| fileFullPath | Full path of file to search. | Optional | 
| fileFullPathOperator | Which operator to apply to the given file path. Possible values are: equals, not equals, contains, not contains. | Optional | 
| dnsHostname | DNS value to search for. | Optional | 
| dnsHostnameOperator | Which operator to apply to the given DNS. Possible values are: equals, not equals, contains, not contains. | Optional | 
| stopSearch | Method in which search should be stopped after finding &lt;limit&gt; number of results. Possible values are: stopAndDelete, stop. | Optional | 
| fieldSearchName | searchable fields - if this argument selected, the 'fieldSearchOperator' and 'fieldSearchValue'  arguments are required. Possible values are: Application Name, Browser Name, Browser Version, Cookie Flags, Cookie Name, Cookie Value, Driver Device Name, Driver Module Name, Executable Exported Dll Name, Executable Exported Function Name, Executable Imported Function Name, Executable Imported Module Name, Executable Injected, Executable PE Type, Executable Resource Name, File Attributes, File Certificate Issuer, File Certificate Subject, File Download Mime Type, File Download Referrer, File Download Type, File Name, File SHA1 Hash, File SHA256 Hash, File Signature Exists, File Signature Verified, File Stream Name, File Text Written, Group Name, HTTP Header, Host Set, Hostname, Local IP Address, Local Port, Parent Process Name, Parent Process Path, Port, Port Protocol, Port State, Process Arguments, Process Name, Quarantine Event Sender Address, Quarantine Event Sender Name, Registry Key Full Path, Registry Key Value Name, Registry Key Value Text, Remote IP Address, Remote Port, Service DLL, Service Mode, Service Name, Service Status, Service Type, Size in bytes, Syslog Event ID, Syslog Event Message, Syslog Facility. | Optional | 
| fieldSearchOperator | Which operator to apply to the given search field. Possible values are: equals, not equals, contains, not contains, less than, greater than. | Optional | 
| fieldSearchValue | One or more values that match the selected search type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.results.Timestamp - Modified | string | Time when the entry was last modified | 
| FireEyeHX.Search.results.File Text Written | string | The file text content | 
| FireEyeHX.Search.results.File Name | string | Name of the file | 
| FireEyeHX.Search.results.File Full Path | string | The full path of the file | 
| FireEyeHX.Search.results.File Bytes Written | string | Number of bytes written to the file | 
| FireEyeHX.Search.results.Size in bytes | string | Size of the file in bytes | 
| FireEyeHX.Search.results.Browser Version | string | Version of the browser | 
| FireEyeHX.Search.results.Browser Name | string | Name of the browser | 
| FireEyeHX.Search.results.Cookie Name | string | Name of the cookie | 
| FireEyeHX.Search.results.DNS Hostname | string | Name of the DNS host | 
| FireEyeHX.Search.results.URL | string | The event URL | 
| FireEyeHX.Search.results.Username | string | The event username | 
| FireEyeHX.Search.results.File MD5 Hash | string | MD5 hash of the file | 
| FireEyeHX.Search.host._id | string | ID of the host | 
| FireEyeHX.Search.host.hostname | string | Name of host | 
| FireEyeHX.Search.host.url | string | Inner FireEye host url | 
| FireEyeHX.Search.results.data | string | ID of performed search | 
| FireEyeHX.Search.results.Timestamp - Accessed | string | Last accessed time | 
| FireEyeHX.Search.results.Port | number | Port | 
| FireEyeHX.Search.results.Process ID | string | ID of the process | 
| FireEyeHX.Search.results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.results.Local Port | number | Local Port | 
| FireEyeHX.Search.results.Username | string | Username | 
| FireEyeHX.Search.results.Remote Port | number | Remote Port | 
| FireEyeHX.Search.results.IP Address | string | IP Address | 
| FireEyeHX.Search.results.Process Name | string | Process Name | 
| FireEyeHX.Search.results.Timestamp - Event | string | Timestamp - Event | 
| FireEyeHX.Search.results.type | string | The type of the event | 
| FireEyeHX.Search.results.id | string | ID of the result | 

#### Command example
```!fireeye-hx-search hostsNames=XXX ipAddress=8.8.8.8 ipAddressOperator=equals polling=false```
#### Human Readable Output

>Search started,
>Search ID: 143

### fireeye-hx-get-alert
***
Get details of a specific alert.


#### Base Command

`fireeye-hx-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Unknown | FireEye alert ID. | 
| FireEyeHX.Alerts.agent._id | Unknown | FireEye agent ID. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | Host containment state. | 
| FireEyeHX.Alerts.condition._id | Unknown | The condition unique ID. | 
| FireEyeHX.Alerts.event_at | Unknown | Time when the event occoured. | 
| FireEyeHX.Alerts.matched_at | Unknown | Time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | Unknown | Time when the event was reported. | 
| FireEyeHX.Alerts.source | Unknown | Source of alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | Source alert ID. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | Appliance ID | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | Source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | Indicator ID. | 
| FireEyeHX.Alerts.resolution | Unknown | Alert resulotion. | 
| FireEyeHX.Alerts.event_type | Unknown | Event type. | 

#### Command example
```!fireeye-hx-get-alert alertId=8```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": null,
        "Score": 0,
        "Type": "file",
        "Vendor": "FireEyeHX v2"
    },
    "File": {
        "Extension": "exe",
        "Name": "feyeqatest.exe",
        "Path": "C:\\Users\\User\\Desktop\\\u37cb\\feyeqatest.exe"
    },
    "FireEyeHX": {
        "Alerts": {
            "_id": 8,
            "agent": {
                "_id": "YYYns3oui1fpzgYYY",
                "containment_state": "normal",
                "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
            },
            "appliance": {
                "_id": "86285DC29A17"
            },
            "condition": {
                "_id": "07p68ZtTsFCDx6Vv7s6FDg==",
                "url": "/hx/api/v3/conditions/07p68ZtTsFCDx6Vv7s6FDg=="
            },
            "decorator_statuses": [],
            "decorators": [],
            "event_at": "2022-01-25T10:25:19.665Z",
            "event_id": 59302205,
            "event_type": "fileWriteEvent",
            "event_values": {
                "fileWriteEvent/closed": 1,
                "fileWriteEvent/drive": "C",
                "fileWriteEvent/eventReason": "Unknown",
                "fileWriteEvent/fileExtension": "exe",
                "fileWriteEvent/fileName": "feyeqatest.exe",
                "fileWriteEvent/filePath": "Users\\User\\Desktop\\\u37cb",
                "fileWriteEvent/fullPath": "C:\\Users\\User\\Desktop\\\u37cb\\feyeqatest.exe",
                "fileWriteEvent/numBytesSeenWritten": 0,
                "fileWriteEvent/openDuration": 0,
                "fileWriteEvent/openTime": "2022-01-25T10:25:19.665Z",
                "fileWriteEvent/parentPid": 5560,
                "fileWriteEvent/parentProcessPath": "C:\\Windows\\System32\\userinit.exe",
                "fileWriteEvent/pid": 5604,
                "fileWriteEvent/process": "explorer.exe",
                "fileWriteEvent/processPath": "C:\\Windows",
                "fileWriteEvent/size": 70,
                "fileWriteEvent/timestamp": "2022-01-25T10:25:19.665Z",
                "fileWriteEvent/username": "XXX\\User",
                "fileWriteEvent/writes": 0
            },
            "indicator": {
                "_id": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                "category": "mandiant_unrestricted",
                "display_name": "FIREEYE END2END TEST",
                "name": "FIREEYE END2END TEST",
                "signature": null,
                "uri_name": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                "url": "/hx/api/v3/indicators/mandiant_unrestricted/2b4753b0_9972_477e_ba16_1a7c29058cee"
            },
            "is_false_positive": false,
            "matched_at": "2022-01-25T10:25:34.000Z",
            "matched_source_alerts": [],
            "md5values": [],
            "multiple_match": null,
            "reported_at": "2022-01-25T10:25:44.011Z",
            "resolution": "ALERT",
            "source": "IOC",
            "subtype": null,
            "url": "/hx/api/v3/alerts/8"
        }
    }
}
```

#### Human Readable Output

>### File
>|Name|md5|Extension|Path|
>|---|---|---|---|
>| feyeqatest.exe |  | exe | C:\Users\User\Desktop\㟋\feyeqatest.exe |


### fireeye-hx-suppress-alert
***
Suppress alert by ID.


#### Base Command

`fireeye-hx-suppress-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert id. The alert id is listed in the output of 'get-alerts' command. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-suppress-alert alertId=18```
#### Human Readable Output

>Alert 18 suppressed successfully.

### fireeye-hx-get-indicators
***
Get a list of indicators.


#### Base Command

`fireeye-hx-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Optional | 
| searchTerm | The searchTerm can be any name, category, signature, source, or condition value. | Optional | 
| shareMode | Determines who can see the indicator. You must belong to the correct authorization group . Possible values are: any, restricted, unrestricted, visible. | Optional | 
| sort | Sorts the results by the specified field in ascending  order. Possible values are: category, activeSince, createdBy, alerted. | Optional | 
| createdBy | Person who created the indicator. | Optional | 
| alerted | Whether the indicator resulted in alerts. Possible values are: yes, no. | Optional | 
| limit | Limit the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | Unknown | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | Unknown | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | Unknown | Indicator description. | 
| FireEyeHX.Indicators.category.name | Unknown | Catagory name. | 
| FireEyeHX.Indicators.created_by | Unknown | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.active_since | Unknown | Date indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | List of families of operating systems. | 
| FireEyeHX.Indicators.uri_name | String | URI formatted name of the indicator. | 
| FireEyeHX.Indicators.category.uri_name | String | URI name of the category. | 

#### Command example
```!fireeye-hx-get-indicators limit=2```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": [
            {
                "_id": "37a97ac2-35e9-40ad-a108-6802d5d82890",
                "_revision": "20220223091809012244597537",
                "active_since": "2022-02-23T09:18:09.012Z",
                "category": {
                    "_id": 2,
                    "name": "Custom",
                    "share_mode": "unrestricted",
                    "uri_name": "Custom",
                    "url": "/hx/api/v3/indicator_categories/custom"
                },
                "create_actor": {
                    "_id": 1001,
                    "username": "test-admin"
                },
                "create_text": null,
                "created_by": "test-admin",
                "description": null,
                "display_name": null,
                "meta": null,
                "name": "37a97ac2-35e9-40ad-a108-6802d5d82890",
                "platforms": [
                    "win",
                    "osx",
                    "linux"
                ],
                "signature": null,
                "stats": {
                    "active_conditions": 0,
                    "alerted_agents": 0,
                    "source_alerts": 0
                },
                "update_actor": {
                    "_id": 1001,
                    "username": "test-admin"
                },
                "uri_name": "37a97ac2-35e9-40ad-a108-6802d5d82890",
                "url": "/hx/api/v3/indicators/custom/37a97ac2_35e9_40ad_a108_6802d5d82890"
            },
            {
                "_id": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
                "_revision": "20220223075746635023596874",
                "active_since": "2022-02-23T07:57:46.635Z",
                "category": {
                    "_id": 2,
                    "name": "Custom",
                    "share_mode": "unrestricted",
                    "uri_name": "Custom",
                    "url": "/hx/api/v3/indicator_categories/custom"
                },
                "create_actor": {
                    "_id": 1001,
                    "username": "test-admin"
                },
                "create_text": null,
                "created_by": "test-admin",
                "description": null,
                "display_name": null,
                "meta": null,
                "name": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
                "platforms": [
                    "win",
                    "osx",
                    "linux"
                ],
                "signature": null,
                "stats": {
                    "active_conditions": 0,
                    "alerted_agents": 0,
                    "source_alerts": 0
                },
                "update_actor": {
                    "_id": 1001,
                    "username": "test-admin"
                },
                "uri_name": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
                "url": "/hx/api/v3/indicators/custom/5d5cea45_2856_4338_8de8_7ef2b16f9511"
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye HX Get Indicator- None
>|OS|Name|Created By|Active Since|Category|Signature|Active Condition|Hosts With Alerts|Source Alerts|
>|---|---|---|---|---|---|---|---|---|
>| win, osx, linux | 37a97ac2-35e9-40ad-a108-6802d5d82890 | test-admin | 2022-02-23T09:18:09.012Z | Custom |  | 0 | 0 | 0 |
>| win, osx, linux | 5d5cea45-2856-4338-8de8-7ef2b16f9511 | test-admin | 2022-02-23T07:57:46.635Z | Custom |  | 0 | 0 | 0 |


### fireeye-hx-get-indicator
***
Get a specific indicator details.


#### Base Command

`fireeye-hx-get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Indicator category. Please use the `uri_category` value. | Required | 
| name | Indicator name. Please use the `uri_name` value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | Unknown | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | Unknown | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | Unknown | Indicator description. | 
| FireEyeHX.Indicators.category.name | Unknown | Catagory name. | 
| FireEyeHX.Indicators.created_by | Unknown | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.active_since | Unknown | Date indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | List of families of operating systems. | 
| FireEyeHX.Conditions._id | Unknown | FireEye unique condition ID. | 
| FireEyeHX.Conditions.event_type | Unknown | Event type. | 
| FireEyeHX.Conditions.enabled | Unknown | Indicates whether the condition is enabled. | 

#### Command example
```!fireeye-hx-get-indicator category=Custom name=5d5cea45-2856-4338-8de8-7ef2b16f9511```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": {
            "_id": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
            "_revision": "20220223075746635023596874",
            "active_since": "2022-02-23T07:57:46.635Z",
            "category": {
                "_id": 2,
                "name": "Custom",
                "share_mode": "unrestricted",
                "uri_name": "Custom",
                "url": "/hx/api/v3/indicator_categories/custom"
            },
            "create_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "create_text": null,
            "created_by": "test-admin",
            "description": null,
            "display_name": null,
            "meta": null,
            "name": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
            "platforms": [
                "win",
                "osx",
                "linux"
            ],
            "signature": null,
            "stats": {
                "active_conditions": 0,
                "alerted_agents": 0,
                "source_alerts": 0
            },
            "update_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "uri_name": "5d5cea45-2856-4338-8de8-7ef2b16f9511",
            "url": "/hx/api/v3/indicators/custom/5d5cea45_2856_4338_8de8_7ef2b16f9511"
        }
    }
}
```

#### Human Readable Output

>### Indicator '5d5cea45-2856-4338-8de8-7ef2b16f9511' Alerts on
>**No entries.**


### fireeye-hx-append-conditions
***
Add conditions to an indicator. Conditions can be MD5, hash values, domain names and IP addresses.


#### Base Command

`fireeye-hx-append-conditions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. Please use the `uri_category` value. | Required | 
| name | The name of the indicator. Please use the `uri_name` value. | Required | 
| condition | A list of conditions to add. The list can include a list of IPv4 addresses, MD5 files, and domain names. For example: example.netexample.orgexample.lol. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-append-conditions category=Custom name=5d5cea45-2856-4338-8de8-7ef2b16f9511 condition=exsmple.com```
#### Context Example
```json
{
    "FireEyeHX": {
        "Conditions": {
            "details": [],
            "message": "OK",
            "route": "/hx/api/v3/indicators/category/indicator/conditions"
        }
    }
}
```

#### Human Readable Output

>### The conditions were added successfully
>|Category|Conditions|Name|
>|---|---|---|
>| Custom | exsmple.com | 5d5cea45-2856-4338-8de8-7ef2b16f9511 |


### fireeye-hx-search-delete
***
Delete the search, by ID.


#### Base Command

`fireeye-hx-search-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | The search ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-search-delete searchId=142```
#### Human Readable Output

>Results
>Search Id 142: Deleted successfully

### fireeye-hx-delete-file-acquisition
***
Delete the file acquisition, by ID.


#### Base Command

`fireeye-hx-delete-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition ID. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-approve-containment
***
Approve pending containment requests made by other components or users, The permissions necessary are api_admin role.


#### Base Command

`fireeye-hx-approve-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The Agent ID - this argument is required. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-assign-host-set-policy
***
Insert a new host set policy on your Endpoint Security server.


#### Base Command

`fireeye-hx-assign-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetId | The Host Set ID - this argument is required. | Required | 
| policyId | The Policy ID - this argument is required. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-assign-host-set-policy hostSetId=1005 policyId=YYYYY-5471-4ae1-918d-YYYYY```
#### Human Readable Output

>This hostset may already be included in this policy

### fireeye-hx-get-data-acquisition
***
Gather artifacts from the system disk and memory for the given acquisition id. (The data is fetched as mans file)


#### Base Command

`fireeye-hx-get-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition unique ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | string | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | string | File md5. | 
| FireEyeHX.Acquisitions.Data.host._id | string | Agent ID | 
| FireEyeHX.Acquisitions.Data.finish_time | string | Time when the acquisition finished | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | date | FIreEye HX instance | 

#### Command example
```!fireeye-hx-get-data-acquisition acquisitionId=102```
#### Context Example
```json
{
    "File": {
        "EntryID": "9ZoPJQJX9vtCa9NueiEpuj@cb52b293-6977-4d1b-8326-216bf1b32052",
        "Extension": "mans",
        "Info": "mans",
        "MD5": "fedf0fbaf4811afd9602c22b29ebed4a",
        "Name": "102_agent_YYYns3oui1fpzgYYY_data.mans",
        "SHA1": "c83819759775fe7cb1fcfaf41a8d452f69caefc7",
        "SHA256": "e92aaabe1e6dab564f421e3785dc46bacfe096b154acd042386e9f606a9e0b7e",
        "SHA512": "9b4be59a5fb8dcb1832ef5eb6a4c587ac7da117b660f451b0b0414e0cf01d9a6208f605703f982486185be538e3869e821b0d8546bbbb264ac5268302a11fbd4",
        "SSDeep": "393216:eijalomh9coY88Wy3cHnMcfrYECADR0E19dk:ea0jXY88dMHnv8uDL19dk",
        "Size": 15678868,
        "Type": "Zip archive data, at least v2.0 to extract"
    },
    "FireEyeHX": {
        "Acquisitions": {
            "Data": {
                "_id": 102,
                "_revision": "20220223084821573006597283",
                "comment": null,
                "download": "/hx/api/v3/acqs/live/102.mans",
                "error_message": "The triage completed with issues.",
                "external_id": null,
                "finish_time": "2022-02-23T08:48:21.572Z",
                "host": {
                    "_id": "YYYns3oui1fpzgYYY",
                    "hostname": "XXX",
                    "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
                },
                "instance": "FireEyeHX v2_instance_1",
                "md5": null,
                "name": "osxDefaultScript",
                "request_actor": {
                    "_id": 1001,
                    "username": "test-admin"
                },
                "request_time": "2022-02-23T08:42:46.000Z",
                "script": {
                    "_id": "7387b70dcf9c54334b2302daf6840ee10167a7e8",
                    "download": "/hx/api/v3/scripts/7387b70dcf9c54334b2302daf6840ee10167a7e8.json",
                    "url": "/hx/api/v3/scripts/7387b70dcf9c54334b2302daf6840ee10167a7e8"
                },
                "state": "COMPLETE",
                "url": "/hx/api/v3/acqs/live/102",
                "zip_file_size": "15678868",
                "zip_passphrase": null
            }
        }
    }
}
```

#### Human Readable Output

>The triage completed with issues.
>acquisition ID: 102

### fireeye-hx-data-acquisition
***
Start a data acquisition process to gather artifacts from the system disk and memory. (The data is fetched as mans file)


#### Base Command

`fireeye-hx-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 
| acquisition_id | This argument is deprecated. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Data.finish_time | Unknown | Time when the acquisition was finished. | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | Agent ID | 

#### Command example
```!fireeye-hx-data-acquisition hostName=XXX defaultSystemScript=osx```
#### Human Readable Output

>Acquisition request was successful
>Acquisition ID: 104

### fireeye-hx-get-alerts
***
Get a list of alerts, use the different arguments to filter the results returned.


#### Base Command

`fireeye-hx-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hasShareMode | Identifies which alerts result from indicators with the specified share mode. Possible values are: any, restricted, unrestricted. | Optional | 
| resolution | Sorts the results by the specified field. Possible values are: active_threat, alert, block, partial_block. | Optional | 
| agentId | Filter by the agent ID. | Optional | 
| conditionId | Filter by condition ID. | Optional | 
| eventAt | Filter event occurred time. ISO-8601 timestamp.. | Optional | 
| alertId | Filter by alert ID. | Optional | 
| matchedAt | Filter by match detection time. ISO-8601 timestamp. | Optional | 
| minId | Filter that returns only records with an AlertId field value great than the minId value. | Optional | 
| reportedAt | Filter by reported time. ISO-8601 timestamp. | Optional | 
| IOCsource | Source of alert- indicator of compromise. Possible values are: yes. | Optional | 
| EXDsource | Source of alert - exploit detection. Possible values are: yes. | Optional | 
| MALsource | Source of alert - malware alert. Possible values are: yes. | Optional | 
| limit | Limit the results returned. | Optional | 
| sort | Sorts the results by the specified field in ascending order. Possible values are: agentId, conditionId, eventAt, alertId, matchedAt, id, reportedAt. | Optional | 
| sortOrder | The sort order for the results. Possible values are: ascending, descending. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Unknown | FireEye alert ID. | 
| FireEyeHX.Alerts.agent._id | Unknown | FireEye agent ID. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | Host containment state. | 
| FireEyeHX.Alerts.condition._id | Unknown | The condition unique ID. | 
| FireEyeHX.Alerts.event_at | Unknown | Time when the event occoured. | 
| FireEyeHX.Alerts.matched_at | Unknown | Time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | Unknown | Time when the event was reported. | 
| FireEyeHX.Alerts.source | Unknown | Source of alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | Source alert ID. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | Appliance ID | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | Source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | Indicator ID. | 
| FireEyeHX.Alerts.resolution | Unknown | Alert resulotion. | 
| FireEyeHX.Alerts.event_type | Unknown | Event type. | 

#### Command example
```!fireeye-hx-get-alerts limit=2 sort=alertId```
#### Context Example
```json
{
    "File": [
        {
            "Extension": "exe",
            "Name": "feyeqatest.exe",
            "Path": "C:\\Users\\User\\Desktop\\feyeqatest.exe",
            "md5": "95b16477988ff5097e57a08332cfdb3a"
        },
        {
            "Extension": "exe",
            "Name": "feyeqatest.exe",
            "Path": "C:\\Users\\User\\Desktop\\\u37cb\\feyeqatest.exe",
            "md5": null
        }
    ],
    "FireEyeHX": {
        "Alerts": [
            {
                "_id": 7,
                "agent": {
                    "_id": "YYYns3oui1fpzgYYY",
                    "containment_state": "normal",
                    "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
                },
                "appliance": {
                    "_id": "86285DC29A17"
                },
                "condition": {
                    "_id": "07p68ZtTsFCDx6Vv7s6FDg==",
                    "url": "/hx/api/v3/conditions/07p68ZtTsFCDx6Vv7s6FDg=="
                },
                "decorator_statuses": [],
                "decorators": [],
                "event_at": "2022-01-24T10:36:33.171Z",
                "event_id": 59105127,
                "event_type": "fileWriteEvent",
                "event_values": {
                    "fileWriteEvent/closed": 1,
                    "fileWriteEvent/drive": "C",
                    "fileWriteEvent/eventReason": "Unknown",
                    "fileWriteEvent/fileExtension": "exe",
                    "fileWriteEvent/fileName": "feyeqatest.exe",
                    "fileWriteEvent/filePath": "Users\\User\\Desktop",
                    "fileWriteEvent/fullPath": "C:\\Users\\User\\Desktop\\feyeqatest.exe",
                    "fileWriteEvent/md5": "95b16477988ff5097e57a08332cfdb3a",
                    "fileWriteEvent/numBytesSeenWritten": 0,
                    "fileWriteEvent/openDuration": 0,
                    "fileWriteEvent/openTime": "2022-01-24T10:36:33.171Z",
                    "fileWriteEvent/parentPid": 5560,
                    "fileWriteEvent/parentProcessPath": "C:\\Windows\\System32\\userinit.exe",
                    "fileWriteEvent/pid": 5604,
                    "fileWriteEvent/process": "explorer.exe",
                    "fileWriteEvent/processPath": "C:\\Windows",
                    "fileWriteEvent/size": 70,
                    "fileWriteEvent/timestamp": "2022-01-24T10:36:33.171Z",
                    "fileWriteEvent/username": "XXX\\User",
                    "fileWriteEvent/writes": 0
                },
                "indicator": {
                    "_id": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                    "category": "mandiant_unrestricted",
                    "display_name": "FIREEYE END2END TEST",
                    "name": "FIREEYE END2END TEST",
                    "signature": null,
                    "uri_name": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                    "url": "/hx/api/v3/indicators/mandiant_unrestricted/2b4753b0_9972_477e_ba16_1a7c29058cee"
                },
                "is_false_positive": false,
                "matched_at": "2022-01-24T10:37:33.000Z",
                "matched_source_alerts": [],
                "md5values": [
                    "95b16477988ff5097e57a08332cfdb3a"
                ],
                "multiple_match": null,
                "reported_at": "2022-01-24T10:37:51.306Z",
                "resolution": "ALERT",
                "source": "IOC",
                "subtype": null,
                "url": "/hx/api/v3/alerts/7"
            },
            {
                "_id": 8,
                "agent": {
                    "_id": "YYYns3oui1fpzgYYY",
                    "containment_state": "normal",
                    "url": "/hx/api/v3/hosts/YYYns3oui1fpzgYYY"
                },
                "appliance": {
                    "_id": "86285DC29A17"
                },
                "condition": {
                    "_id": "07p68ZtTsFCDx6Vv7s6FDg==",
                    "url": "/hx/api/v3/conditions/07p68ZtTsFCDx6Vv7s6FDg=="
                },
                "decorator_statuses": [],
                "decorators": [],
                "event_at": "2022-01-25T10:25:19.665Z",
                "event_id": 59302205,
                "event_type": "fileWriteEvent",
                "event_values": {
                    "fileWriteEvent/closed": 1,
                    "fileWriteEvent/drive": "C",
                    "fileWriteEvent/eventReason": "Unknown",
                    "fileWriteEvent/fileExtension": "exe",
                    "fileWriteEvent/fileName": "feyeqatest.exe",
                    "fileWriteEvent/filePath": "Users\\User\\Desktop\\\u37cb",
                    "fileWriteEvent/fullPath": "C:\\Users\\User\\Desktop\\\u37cb\\feyeqatest.exe",
                    "fileWriteEvent/numBytesSeenWritten": 0,
                    "fileWriteEvent/openDuration": 0,
                    "fileWriteEvent/openTime": "2022-01-25T10:25:19.665Z",
                    "fileWriteEvent/parentPid": 5560,
                    "fileWriteEvent/parentProcessPath": "C:\\Windows\\System32\\userinit.exe",
                    "fileWriteEvent/pid": 5604,
                    "fileWriteEvent/process": "explorer.exe",
                    "fileWriteEvent/processPath": "C:\\Windows",
                    "fileWriteEvent/size": 70,
                    "fileWriteEvent/timestamp": "2022-01-25T10:25:19.665Z",
                    "fileWriteEvent/username": "XXX\\User",
                    "fileWriteEvent/writes": 0
                },
                "indicator": {
                    "_id": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                    "category": "mandiant_unrestricted",
                    "display_name": "FIREEYE END2END TEST",
                    "name": "FIREEYE END2END TEST",
                    "signature": null,
                    "uri_name": "2b4753b0-9972-477e-ba16-1a7c29058cee",
                    "url": "/hx/api/v3/indicators/mandiant_unrestricted/2b4753b0_9972_477e_ba16_1a7c29058cee"
                },
                "is_false_positive": false,
                "matched_at": "2022-01-25T10:25:34.000Z",
                "matched_source_alerts": [],
                "md5values": [],
                "multiple_match": null,
                "reported_at": "2022-01-25T10:25:44.011Z",
                "resolution": "ALERT",
                "source": "IOC",
                "subtype": null,
                "url": "/hx/api/v3/alerts/8"
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye HX Get Alerts
>|Alert ID|Reported|Event Type|Agent ID|
>|---|---|---|---|
>| 7 | 2022-01-24T10:37:51.306Z | fileWriteEvent | YYYns3oui1fpzgYYY |
>| 8 | 2022-01-25T10:25:44.011Z | fileWriteEvent | YYYns3oui1fpzgYYY |


### fireeye-hx-file-acquisition
***
Aquire a specific file as a password protected zip file. The password for unlocking the zip file is 'unzip-me'.


#### Base Command

`fireeye-hx-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisition_id | acquisition ID, This argument is deprecated. | Optional | 
| fileName | The file name. | Required | 
| filePath | The file path. | Required | 
| acquireUsing | Whether to aqcuire the file using the API or RAW. By default, raw file will be acquired. Use API option when file is encrypted. Possible values are: API, RAW. | Optional | 
| agentId | The agent ID associated with the host that holds the file. If the hostName is not specified, the agentId must be specified. | Optional | 
| hostName | The host that holds the file. If the agentId is not specified, hostName must be specified. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Files._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Files.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Files.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Files.req_filename | Unknown | The file name. | 
| FireEyeHX.Acquisitions.Files.req_path | Unknown | The file path. | 
| FireEyeHX.Acquisitions.Files.host._id | Unknown | FireEye HX agent ID. | 

### fireeye-hx-create-indicator
***
Create new indicator


#### Base Command

`fireeye-hx-create-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators.active_since | date | Date indicator became active. | 
| FireEyeHX.Indicators.meta | string | Meta data for new indicator | 
| FireEyeHX.Indicators.display_name | string | The indicator display name | 
| FireEyeHX.Indicators.name | string | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.created_by | string | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.url | string | The data URL | 
| FireEyeHX.Indicators.create_text | Unknown | The indicator create text | 
| FireEyeHX.Indicators.platforms | string | List of families of operating systems. | 
| FireEyeHX.Indicators.create_actor._id | number | The ID of the actor | 
| FireEyeHX.Indicators.create_actor.username | string | Actor user name | 
| FireEyeHX.Indicators.signature | string | Signature of indicator  | 
| FireEyeHX.Indicators._revision | string | Indicator revision | 
| FireEyeHX.Indicators._id | string | FireEye unique indicator ID. | 
| FireEyeHX.Indicator.description | string | Indicator description | 
| FireEyeHX.Indicators.category._id | number | Category ID | 
| FireEyeHX.Indicators.category.name | string | Category name | 
| FireEyeHX.Indicators.category.share_mode | string | Category share mode | 
| FireEyeHX.Indicators.category.uri_name | string | Category uri name | 
| FireEyeHX.Indicators.category.url | string | Category URL | 
| FireEyeHX.Indicators.uri_name | string | The indicator uri name | 
| FireEyeHX.Indicators.stats.active_conditions | number | Indicator active conditions | 
| FireEyeHX.Indicators.stats.alerted_agents | number | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.source_alerts | number | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.update_actor._id | number | Update actor ID | 
| FireEyeHX.Indicators.update_actor.username | string | Update actor name | 

#### Command example
```!fireeye-hx-create-indicator category=Custom```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": {
            "_id": "37a97ac2-35e9-40ad-a108-6802d5d82890",
            "_revision": "20220223091809012244597537",
            "active_since": "2022-02-23T09:18:09.012Z",
            "category": {
                "_id": 2,
                "name": "Custom",
                "share_mode": "unrestricted",
                "uri_name": "Custom",
                "url": "/hx/api/v3/indicator_categories/custom"
            },
            "create_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "create_text": null,
            "created_by": "test-admin",
            "description": null,
            "display_name": null,
            "meta": null,
            "name": "37a97ac2-35e9-40ad-a108-6802d5d82890",
            "platforms": [
                "win",
                "osx",
                "linux"
            ],
            "signature": null,
            "stats": {
                "active_conditions": 0,
                "alerted_agents": 0,
                "source_alerts": 0
            },
            "update_actor": {
                "_id": 1001,
                "username": "test-admin"
            },
            "uri_name": "37a97ac2-35e9-40ad-a108-6802d5d82890",
            "url": "/hx/api/v3/indicators/custom/37a97ac2_35e9_40ad_a108_6802d5d82890"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX New Indicator created successfully
>|ID|
>|---|
>| 37a97ac2-35e9-40ad-a108-6802d5d82890 |


### fireeye-hx-delete-host-set-policy
***
Delete a Host Set Policy.


#### Base Command

`fireeye-hx-delete-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetId | The Host Set Id. | Required | 
| policyId | The Policy Id. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-delete-host-set-policy hostSetId=1005 policyId=YYYYY-5471-4ae1-918d-YYYYY```
#### Human Readable Output

>Success

### fireeye-hx-delete-data-acquisition
***
Delete data acquisition.


#### Base Command

`fireeye-hx-delete-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-delete-data-acquisition acquisitionId=102```
#### Human Readable Output

>data acquisition 102 deleted successfully
