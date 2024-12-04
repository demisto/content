FireEye Endpoint Security is an integrated solution that detects what others miss and protects endpoint against known and unknown threats. This  integration provides access to information about endpoints, acquisitions, alerts, indicators, and containment. Customers can extract critical data and effectively operate security operations automated playbook


Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-fireeye-endpoint-security-(hx)-v2).

## Configure FireEye Endpoint Security (HX) v2 in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-hx-get-host-information
***
Returns information on a host associated with an agent.


#### Base Command

`fireeye-hx-get-host-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The agent ID. If the agent ID is not specified, the hostName must be specified. | Optional | 
| hostName | The host name. If the hostName is not specified, the agent ID must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | String | The ID of the FireEye HX Agent. | 
| FireEyeHX.Hosts.agent_version | String | The version of the agent. | 
| FireEyeHX.Hosts.excluded_from_containment | Boolean | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Boolean | Whether there is containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Boolean | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | String | The containment state of the host. Possible values normal,contain,contain_fail,containing,contained,uncontain,uncontaining,wtfc,wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Number | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Number | The total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Number | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Number | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | String | The name of the host. | 
| FireEyeHX.Hosts.domain | String | The name of the domain. | 
| FireEyeHX.Hosts.timezone | String | The time zone of the host. | 
| FireEyeHX.Hosts.primary_ip_address | String | The IP address of the host. | 
| FireEyeHX.Hosts.last_poll_timestamp | String | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | String | The timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | String | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | The time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | String | The operating system of the host. | 
| FireEyeHX.Hosts.os.bitness | String | The bitness of the operating system. | 
| FireEyeHX.Hosts.os.platform | Unknown | The list of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | String | The MAC address of the host. | 

#### Command example
```!fireeye-hx-get-host-information hostName=XXX```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": {
            "_id": "YYYXXXYYY",
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
            "last_poll_ip": "xx.xx.xx.xx",
            "last_poll_timestamp": "2022-02-23T09:08:31.000Z",
            "os": {
                "bitness": "64-bit",
                "kernel_version": null,
                "patch_level": null,
                "platform": "win",
                "product_name": "Windows 10 Pro"
            },
            "primary_ip_address": "xx.xx.xx.xx",
            "primary_mac": "xx-xx-xx-xx-xx-xx",
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
                "url": "/hx/api/v3/hosts/YYYXXXYYY/sysinfo"
            },
            "timezone": "Pacific Standard Time",
            "url": "/hx/api/v3/hosts/YYYXXXYYY"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Get Host Information
>|Host Name|Host IP|Agent ID|Agent Version|OS|Last Poll|Containment State|Domain|Last Alert|
>|---|---|---|---|---|---|---|---|---|
>| XXX | xx.xx.xx.xx | YYYXXXYYY | 31.28.17 | win | 2022-02-23T09:08:31.000Z | normal | WORKGROUP | _id: 365<br/>url: /hx/api/v3/alerts/365 |


### fireeye-hx-get-all-hosts-information
***
Returns information on all hosts.


#### Base Command

`fireeye-hx-get-all-hosts-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response. Default is 0. | Optional | 
| limit | Limits the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | String | The FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | String | The version of the agent. | 
| FireEyeHX.Hosts.excluded_from_containment | Boolean | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Boolean | Whether there is containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Boolean | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | String | The containment state of the host. Possible values are normal, contain, contain_fail, containing, contained, uncontain, uncontaining, wtfc, wtfu. | 
| FireEyeHX.Hosts.stats.alerting_conditions | Number | The number of conditions that have been alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Number | The total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Number | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Number | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | String | The name of the host. | 
| FireEyeHX.Hosts.domain | String | The name of the domain. | 
| FireEyeHX.Hosts.timezone | String | The time zone of the host. | 
| FireEyeHX.Hosts.primary_ip_address | String | The IP address of the host. | 
| FireEyeHX.Hosts.last_poll_timestamp | String | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | String | The timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | String | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | The time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | String | The operating system of the host. | 
| FireEyeHX.Hosts.os.bitness | String | The bitness of the operating system. | 
| FireEyeHX.Hosts.os.platform | String | The list of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | String | The host MAC address. | 

#### Command example
```!fireeye-hx-get-all-hosts-information limit=1```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": {
            "Agent ID": "YYYXXXYYY",
            "Agent Version": "31.28.17",
            "Containment State": "normal",
            "Domain": "WORKGROUP",
            "Host IP": "xx.xx.xx.xx",
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
>| XXX | xx.xx.xx.xx | YYYXXXYYY | 31.28.17 | win | 2022-02-23T09:08:31.000Z | normal | WORKGROUP | _id: 365<br/>url: /hx/api/v3/alerts/365 |


### fireeye-hx-host-containment
***
Applies containment for a specific host, so that it no longer has access to other systems. If the user does not have the necessary permissions, the command will not approve the request. The permission required to approve the request is api_admin role.


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
| FireEyeHX.Hosts._id | String | The ID of the FireEye HX Agent. | 
| FireEyeHX.Hosts.agent_version | String | The version of the agent. | 
| FireEyeHX.Hosts.excluded_from_containment | Boolean | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Boolean | Whether there is containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Boolean | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | String | The containment state of the host. Possible values are normal, contain, contain_fail, containing, contained, uncontain, uncontaining, wtfc, wtfu. | 
| FireEyeHX.Hosts.stats.alerting_conditions | Number | The number of conditions that have been alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Number | The total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Number | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Number | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | String | The name of the host. | 
| FireEyeHX.Hosts.domain | String | The name of the domain. | 
| FireEyeHX.Hosts.timezone | String | The time zone of the host. | 
| FireEyeHX.Hosts.primary_ip_address | String | The IP address of the host. | 
| FireEyeHX.Hosts.last_poll_timestamp | String | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | String | The timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | String | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | String | The time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | String | The operating system of the host. | 
| FireEyeHX.Hosts.os.bitness | String | The bitness of the operating system. | 
| FireEyeHX.Hosts.os.platform | String | The list of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | String | The host MAC address. | 

#### Command example
```!fireeye-hx-host-containment hostName=XXX```
#### Context Example
```json
{
    "Endpoint": {
        "Domain": "WORKGROUP",
        "Hostname": "XXX",
        "ID": "YYYXXXYYY",
        "IPAddress": "xx.xx.xx.xx",
        "MACAddress": "xx-xx-xx-xx-xx-xx",
        "OS": "win",
        "OSVersion": "Windows 10 Pro"
    },
    "FireEyeHX": {
        "Hosts": {
            "_id": "YYYXXXYYY",
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
            "last_poll_ip": "xx.xx.xx.xx",
            "last_poll_timestamp": "2022-02-23T09:08:31.000Z",
            "os": {
                "bitness": "64-bit",
                "kernel_version": null,
                "patch_level": null,
                "platform": "win",
                "product_name": "Windows 10 Pro"
            },
            "primary_ip_address": "xx.xx.xx.xx",
            "primary_mac": "xx-xx-xx-xx-xx-xx",
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
                "url": "/hx/api/v3/hosts/YYYXXXYYY/sysinfo"
            },
            "timezone": "Pacific Standard Time",
            "url": "/hx/api/v3/hosts/YYYXXXYYY"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Domain|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|
>|---|---|---|---|---|---|---|
>| WORKGROUP | XXX | YYYXXXYYY | xx.xx.xx.xx | xx-xx-xx-xx-xx-xx | win | Windows 10 Pro |


### fireeye-hx-cancel-containment
***
Releases a specific host from containment.


#### Base Command

`fireeye-hx-cancel-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostName | The host name to be contained. If the hostName is not specified, the agentId must be specified. | Optional | 
| agentId | The agent ID running on the host to be contained. If the agentId is not specified, the hostName must be specified. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-cancel-containment hostName=XXX```
#### Human Readable Output

>Success

### fireeye-hx-initiate-data-acquisition
***
Initiates a data acquisition process to collect artifacts from the system disk and memory.


#### Base Command

`fireeye-hx-initiate-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | The acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Select the host system to use the default system script. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the hostName is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the hostName must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The unique ID of the acquisition. | 
| FireEyeHX.Acquisitions.Data.state | string | The state of the acquisition. | 
| FireEyeHX.Acquisitions.Data.md5 | string | The MD5 of the file. | 
| FireEyeHX.Acquisitions.Data.host._id | string | The ID of the agent. | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | The name of the host. | 
| FireEyeHX.Acquisitions.Data.instance | string | The FireEye HX instance. | 
| FireEyeHX.Acquisitions.Data.finish_time | date | The time when the acquisition finished. | 

### fireeye-hx-get-host-set-information
***
Returns a list of all host sets known to your HX Series appliance.


#### Base Command

`fireeye-hx-get-host-set-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetID | The ID of a specific host set to return. | Optional | 
| offset | Specifies which record to start with in the response. The offset value must be an unsigned 32-bit integer. Default is 0. | Optional | 
| limit | Specifies how many records are returned. The limit value must be an unsigned 32-bit integer. Default is 50. | Optional | 
| search | Searches the names of all host sets connected to the specified HX appliance. | Optional | 
| sort | Sorts the results by the specified field in ascending or descending order. The default sorts in ascending order, by name. Sortable fields are _id (host set ID) and name (host set name). | Optional | 
| name | Specifies the name of the host set for which to search. | Optional | 
| type | Specifies the type of host set for which to search. Possible values are: venn, static. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | number | The ID of the host set. | 
| FireEyeHX.HostSets._revision | string | The number of the host set revision. | 
| FireEyeHX.HostSets.name | string | The name of the host set. | 
| FireEyeHX.HostSets.type | string | The type of the host set \(static/dynamic/hidden\). | 
| FireEyeHX.HostSets.url | string | The FireEye URL of the host set. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-get-host-set-information hostSetID=1001```
#### Context Example
```json
{
    "FireEyeHX": {
        "HostSets": {
            "_id": 1001,
            "_revision": "20210308150955358783164361",
            "name": "Test",
            "type": "venn",
            "url": "/hx/api/v3/host_sets/1001",
            "deleted": false
        }
    }
}
```

#### Human Readable Output

>### FireEye HX Get Host Sets Information
>|Name|ID|Type|
>|---|---|---|
>| Test | 1001 | venn |


### fireeye-hx-list-policy
***
Returns a list of all policies.


#### Base Command

`fireeye-hx-list-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response. Default is 0. | Optional | 
| limit | Limits the number of results. | Optional | 
| policyName | The name of the policy. | Optional | 
| policyId | The unique policy ID. | Optional | 
| enabled | Whether the policy is enabled ("true") or disabled ("false"). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Policy._id | String | The ID of the unique policy. | 
| FireEyeHX.Policy.name | String | The name of the policy. | 
| FireEyeHX.Policy.description | String | The description of the policy. | 
| FireEyeHX.Policy.policy_type_id | String | The ID of the unique policy type. | 
| FireEyeHX.Policy.priority | Number | The priority order of the policy. | 
| FireEyeHX.Policy.enabled | Boolean | Whether the policy is enabled \("true"\) or disabled \("false"\). | 
| FireEyeHX.Policy.default | Boolean | Whether it is the default policy \(true\). There can only be one policy marked as default. | 
| FireEyeHX.Policy.migrated | Boolean | Whether it is a migrated policy \(true\). | 
| FireEyeHX.Policy.created_by | String | The user who created the policy. | 
| FireEyeHX.Policy.created_at | String | The time the policy was first created. | 
| FireEyeHX.Policy.updated_at | String | The time the policy was last updated. | 
| FireEyeHX.Policy.categories | Unknown | The collection of categories that the policy is associated. | 
| FireEyeHX.Policy.display_created_at | String | The time since the display was first created. | 
| FireEyeHX.Policy.display_updated_at | String | The time since the display was last updated. | 

#### Command example
```!fireeye-hx-list-policy limit=2 policyName=Test```
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
                    "name": "Test",
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
Returns a list of all policies for all host sets.


#### Base Command

`fireeye-hx-list-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response. Default is 0. | Optional | 
| limit | Limits the number of results. | Optional | 
| hostSetId | The host set ID. | Optional | 
| policyId | The unique policy ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets.Policy.policy_id | String | The ID of the unique policy. | 
| FireEyeHX.HostSets.Policy.persist_id | Number | The ID of the host set. | 

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
                    "policy_id": "YYYXXXYYY"
                },
                {
                    "persist_id": 1002,
                    "policy_id": "YYYXXXYYY"
                },
                {
                    "persist_id": 1005,
                    "policy_id": "YYYXXXYYY"
                },
                {
                    "persist_id": 1005,
                    "policy_id": "YYYXXXYYY"
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
>| YYYXXXYYY | 1001 |
>| YYYXXXYYY | 1002 |
>| YYYXXXYYY | 1005 |
>| YYYXXXYYY | 1005 |


### fireeye-hx-list-containment
***
Fetches all containment states across known hosts.


#### Base Command

`fireeye-hx-list-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response. Default is 0. | Optional | 
| limit | Limits the number of results. | Optional | 
| state_update_time | Must be from type of -&gt; String: date-time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | String | The FireEye HX Agent ID. | 
| FireEyeHX.Hosts.last_sysinfo | String | The Last Sysinfo date. | 
| FireEyeHX.Hosts.requested_by_actor | String | The action requested by actor. | 
| FireEyeHX.Hosts.requested_on | String | When the containment was requested. | 
| FireEyeHX.Hosts.contained_by_actor | String | The action contained by actor. | 
| FireEyeHX.Hosts.contained_on | String | When the host was contained. | 
| FireEyeHX.Hosts.queued | Boolean | Determines whether the hosts are queued for containment. | 
| FireEyeHX.Hosts.excluded | Boolean | Whether the hosts are excluded. | 
| FireEyeHX.Hosts.missing_software | Boolean | Whether there is missing software. | 
| FireEyeHX.Hosts.reported_clone | Boolean | Whether there is a reported clone. | 
| FireEyeHX.Hosts.state | String | The state of the hosts. | 
| FireEyeHX.Hosts.state_update_time | String | The state update time of the hosts. | 
| FireEyeHX.Hosts.url | String | The URL of the hosts. | 

#### Command example
```!fireeye-hx-list-containment limit=2```
#### Context Example
```json
{
    "FireEyeHX": {
        "Hosts": [
            {
                "_id": "YYYXXXYYY",
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
                "url": "/hx/api/v3/hosts/YYYXXXYYY"
            },
            {
                "_id": "YYYXXXYYY",
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
                "url": "/hx/api/v3/hosts/YYYXXXYYY"
            }
        ]
    }
}
```

#### Human Readable Output

>### List Containment
>|Id|State|Request Origin|Request Date|Containment Origin|Containment Date|Last System information date|
>|---|---|---|---|---|---|---|
>| YYYXXXYYY | normal |  |  |  |  | 2022-02-23T07:28:33.969Z |
>| YYYXXXYYY | normal |  |  |  |  | 2022-02-23T08:23:25.592Z |


### fireeye-hx-search-list
***
Fetches all enterprise searches.


#### Base Command

`fireeye-hx-search-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response. Default is 0. | Optional | 
| limit | Specifies how many records are returned. Default is 50. | Optional | 
| state | Filter by search state. Select either STOPPED or RUNNING. Possible values are: RUNNING, STOPPED. | Optional | 
| sort | Sorts the results by the specified field. Default is sort by _id. Possible values are: _id, state, host_set._id, update_time, create_time, update_actor._id, update_actor.username, create_actor._id, create_actor.username. | Optional | 
| hostSetId | Filters searches by host set ID - &lt;Integer&gt;. | Optional | 
| searchId | Returns a single enterprise search record. If you enter this argument there is no need for other arguments. | Optional | 
| actorUsername | Filters searches by username that created searches - &lt;String&gt;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Number | The ID of the unique search. | 
| FireEyeHX.Search.state | String | The state of the search, whether it stopped or ran. | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search. | 
| FireEyeHX.Search.update_time | String | The time the search was last updated. | 
| FireEyeHX.Search.create_time | String | The time the search was created. | 
| FireEyeHX.Search.scripts.platform | Unknown | The platform for which this script is used. | 
| FireEyeHX.Search.update_actor | Unknown | The actor who last updated the search. | 
| FireEyeHX.Search.create_actor | Unknown | The actor who created the search. | 
| FireEyeHX.Search.error | Unknown | Collection of errors per agents for the search. | 
| FireEyeHX.Search._revision | String | The ETag that can be used for concurrency checking. | 
| FireEyeHX.Search.input_type | String | The input method that was used to start the search. | 
| FireEyeHX.Search.url | String | The URI to retrieve data for this record. | 
| FireEyeHX.Search.host_set | Unknown | The Host Set information. | 
| FireEyeHX.Search.stats | Unknown | The stats information. | 
| FireEyeHX.Search.stats.hosts | Number | The number of hosts running this operation. | 
| FireEyeHX.Search.stats.skipped_hosts | Number | The number of hosts that were skipped. | 
| FireEyeHX.Search.stats.search_state | Unknown | The number of search in different states. | 
| FireEyeHX.Search.stats.search_issues | Unknown | The issues encountered for searches. | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown | The terms for the operation. | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown | The exhaustive terms for the operation. | 
| FireEyeHX.Search.stats.settings.search_type | String | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | String | Whether a search is exhaustive. | 
| FireEyeHX.Search.stats.settings.mode | String | Whether a search is a HOST type or GRID type. | 
| FireEyeHX.Search.stats.settings.displayname | String | The name of the search. | 

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
                "username": "test"
            },
            "create_time": "2022-02-23T09:18:11.214Z",
            "error": null,
            "host_set": null,
            "input_type": "api",
            "scripts": [
                {
                    "_id": "YYYXXXYYY",
                    "download": "/hx/api/v3/scripts/YYYXXXYYY.json",
                    "platform": "win",
                    "url": "/hx/api/v3/scripts/YYYXXXYYY"
                },
                {
                    "_id": "YYYXXXYYY",
                    "download": "/hx/api/v3/scripts/YYYXXXYYY.json",
                    "platform": "osx",
                    "url": "/hx/api/v3/scripts/YYYXXXYYY"
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
                            "value": "xx.xx.xx.xx"
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
                "username": "test"
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
>| 143 | RUNNING |  | _id: 1001<br/>username: test | 2022-02-23T09:18:11.214Z | _id: 1001<br/>username: test | 2022-02-23T09:18:11.214Z |


### fireeye-hx-search-stop
***
Stops a specific running search.


#### Base Command

`fireeye-hx-search-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | Unique search ID - Required. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Number | The ID of the unique search. | 
| FireEyeHX.Search.state | String | The state of the search, whether it stopped or ran. | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search. | 
| FireEyeHX.Search.update_time | String | The time the search was last updated. | 
| FireEyeHX.Search.create_time | String | The time the search was created. | 
| FireEyeHX.Search.scripts.platform | Unknown | The platform for which this script is used. | 
| FireEyeHX.Search.update_actor | Unknown | The actor who last updated the search. | 
| FireEyeHX.Search.create_actor | Unknown | The actor who created the search. | 
| FireEyeHX.Search.error | Unknown | The collection of errors per agents for the search. | 
| FireEyeHX.Search._revision | Unknown | ETag that can be used for concurrency checking. | 
| FireEyeHX.Search.input_type | String | The input method that was used to start the search. | 
| FireEyeHX.Search.url | String | The URI to retrieve data for this record. | 
| FireEyeHX.Search.host_set | Unknown | The Host Set information. | 
| FireEyeHX.Search.stats | Unknown | The stats information. | 
| FireEyeHX.Search.stats.hosts | Number | The number of hosts running this operation. | 
| FireEyeHX.Search.stats.skipped_hosts | Number | The number of hosts that were skipped. | 
| FireEyeHX.Search.stats.search_state | Unknown | The number of search in different states. | 
| FireEyeHX.Search.stats.search_issues | Unknown | The issues encountered for searches. | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown | The terms for the operation. | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown | The exhaustive terms for the operation | 
| FireEyeHX.Search.stats.settings.search_type | String | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | String | Whether a search is exhaustive. | 
| FireEyeHX.Search.stats.settings.mode | String | Whether a search is a HOST type or GRID type. | 
| FireEyeHX.Search.stats.settings.displayname | String | The name of the search. | 

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
                "username": "test"
            },
            "create_time": "2022-02-23T09:05:54.645Z",
            "error": null,
            "host_set": null,
            "input_type": "api",
            "scripts": [
                {
                    "_id": "YYYXXXYYY",
                    "download": "/hx/api/v3/scripts/YYYXXXYYY.json",
                    "platform": "win",
                    "url": "/hx/api/v3/scripts/YYYXXXYYY"
                },
                {
                    "_id": "YYYXXXYYY",
                    "download": "/hx/api/v3/scripts/YYYXXXYYY.json",
                    "platform": "osx",
                    "url": "/hx/api/v3/scripts/YYYXXXYYY"
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
                            "value": "xx.xx.xx.xx"
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
                "username": "test"
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
Fetches the results for a specific enterprise search.


#### Base Command

`fireeye-hx-search-result-get`
#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- |--------------|
| searchId          | The Unique search ID. | Required     | 
| limit             | Limit the number of results to return per search. | Optional     | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.host._id | String | The ID of the unique agent. | 
| FireEyeHX.Search.host.url | String | The URI to retrieve data for this record. | 
| FireEyeHX.Search.host.hostname | String | The name of the host. | 
| FireEyeHX.Search.results._id | Number | The unique ID. | 
| FireEyeHX.Search.results.type | String | The type of the search result data. | 
| FireEyeHX.Search.results.data | Unknown | The object containing data relating to the search result for the host. | 

#### Command example
```!fireeye-hx-search-result-get searchId=141```
#### Context Example
```json
{
    "FireEyeHX": {
        "Search": {
            "host": {
                "_id": "YYYXXXYYY",
                "hostname": "XXX",
                "url": "/hx/api/v3/hosts/YYYXXXYYY"
            },
            "results": [
                {
                    "data": {
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "64924",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "64925",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "64926",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "56687",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "58763",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "58766",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "59099",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "55107",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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
                        "IP Address": "xx.xx.xx.xx",
                        "Local IP Address": "xx.xx.xx.xx",
                        "Local Port": "55107",
                        "Port": "443",
                        "Process ID": "8696",
                        "Process Name": "chrome.exe",
                        "Remote IP Address": "xx.xx.xx.xx",
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

>### Host Id YYYXXXYYY
>Host Name XXX
>|Item Type|Summary|
>|---|---|
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 64924,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 64925,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 64926,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-20T09:41:51.470Z,<br/>**Timestamp - Accessed:** 2022-01-20T09:41:51.470Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 56687,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-01-31T06:56:37.591Z,<br/>**Timestamp - Accessed:** 2022-01-31T06:56:37.591Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 58763,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T07:51:38.928Z,<br/>**Timestamp - Accessed:** 2022-02-01T07:51:38.928Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 58766,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T07:53:03.630Z,<br/>**Timestamp - Accessed:** 2022-02-01T07:53:03.630Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 59099,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-01T12:04:14.969Z,<br/>**Timestamp - Accessed:** 2022-02-01T12:04:14.969Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 55107,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-07T10:51:46.951Z,<br/>**Timestamp - Accessed:** 2022-02-07T10:51:46.951Z |
>| IPv4 Network Event | **Process Name:** chrome.exe,<br/>**Process ID:** 8696,<br/>**Username:** XXX\User,<br/>**Local IP Address:** xx.xx.xx.xx,<br/>**Remote IP Address:** xx.xx.xx.xx,<br/>**IP Address:** xx.xx.xx.xx,<br/>**Port:** 443,<br/>**Local Port:** 55107,<br/>**Remote Port:** 443,<br/>**Timestamp - Event:** 2022-02-07T10:53:17.233Z,<br/>**Timestamp - Accessed:** 2022-02-07T10:53:17.233Z |


### fireeye-hx-search
***
Searches endpoints to check all hosts or a subset of hosts for a specific file or indicator.


#### Base Command

`fireeye-hx-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | searchId. | Optional | 
| agentsIds | The IDs of the gents to be searched. | Optional | 
| hostsNames | The names of hosts to be searched. | Optional | 
| hostSet | The ID of host set to be searched. | Optional | 
| hostSetName | The name of host set to be searched. | Optional | 
| limit | Limits the results count (once the limit is reached, the search is stopped). | Optional | 
| exhaustive | Whether a search is exhaustive or quick. Possible values are: yes, no. Default is yes. | Optional | 
| ipAddress | A valid IPv4 address for which to search. | Optional | 
| ipAddressOperator | Which operator to apply to the given IP address. Possible values are: equals, not equals. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result, when ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 60. | Optional | 
| fileMD5Hash | A 32-character MD5 hash value for which to search. | Optional | 
| fileMD5HashOperator | Which operator to apply to the given MD5 hash. Possible values are: equals, not equals. | Optional | 
| fileFullPath | The full path of file to search. | Optional | 
| fileFullPathOperator | Which operator to apply to the given file path. Possible values are: equals, not equals, contains, not contains. | Optional | 
| dnsHostname | The DNS value for which to search. | Optional | 
| dnsHostnameOperator | Which operator to apply to the given DNS. Possible values are: equals, not equals, contains, not contains. | Optional | 
| stopSearch | The method in which the search should be stopped after finding &lt;limit&gt; number of results. Possible values are: stopAndDelete, stop. | Optional | 
| fieldSearchName | Searchable fields - If using this argument, the 'fieldSearchOperator' and 'fieldSearchValue' arguments are required. Possible values are: Application Name, Browser Name, Browser Version, Cookie Flags, Cookie Name, Cookie Value, Driver Device Name, Driver Module Name, Executable Exported Dll Name, Executable Exported Function Name, Executable Imported Function Name, Executable Imported Module Name, Executable Injected, Executable PE Type, Executable Resource Name, File Attributes, File Certificate Issuer, File Certificate Subject, File Download Mime Type, File Download Referrer, File Download Type, File Name, File SHA1 Hash, File SHA256 Hash, File Signature Exists, File Signature Verified, File Stream Name, File Text Written, Group Name, HTTP Header, Host Set, Hostname, Local IP Address, Local Port, Parent Process Name, Parent Process Path, Port, Port Protocol, Port State, Process Arguments, Process Name, Quarantine Event Sender Address, Quarantine Event Sender Name, Registry Key Full Path, Registry Key Value Name, Registry Key Value Text, Remote IP Address, Remote Port, Service DLL, Service Mode, Service Name, Service Status, Service Type, Size in bytes, Syslog Event ID, Syslog Event Message, Syslog Facility. | Optional | 
| fieldSearchOperator | Which operator to apply to the given search field. Possible values are: equals, not equals, contains, not contains, less than, greater than. | Optional | 
| fieldSearchValue | One or more values that match the selected search type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.results.data.Timestamp - Modified | string | The time when the entry was last modified. | 
| FireEyeHX.Search.results.data.File Text Written | string | The file text content. | 
| FireEyeHX.Search.results.data.File Name | string | The name of the file. | 
| FireEyeHX.Search.results.data.File Full Path | string | The full path of the file. | 
| FireEyeHX.Search.results.data.File Bytes Written | string | The number of bytes written to the file. | 
| FireEyeHX.Search.results.data.Size in bytes | string | The size of the file in bytes. | 
| FireEyeHX.Search.results.data.Browser Version | string | The version of the browser. | 
| FireEyeHX.Search.results.data.Browser Name | string | The name of the browser. | 
| FireEyeHX.Search.results.data.Cookie Name | string | The name of the cookie. | 
| FireEyeHX.Search.results.data.DNS Hostname | string | The name of the DNS host. | 
| FireEyeHX.Search.results.data.URL | string | The event URL. | 
| FireEyeHX.Search.results.data.Username | string | The event username. | 
| FireEyeHX.Search.results.data.File MD5 Hash | string | The MD5 hash of the file. | 
| FireEyeHX.Search.host._id | string | The ID of the host. | 
| FireEyeHX.Search.host.hostname | string | The name of host. | 
| FireEyeHX.Search.host.url | string | The Inner FireEye host URL. | 
| FireEyeHX.Search.results.data | string | The ID of the performed search. | 
| FireEyeHX.Search.results.data.Timestamp - Accessed | string | The last accessed time. | 
| FireEyeHX.Search.results.data.Port | number | The Port. | 
| FireEyeHX.Search.results.data.Process ID | string | The ID of the process. | 
| FireEyeHX.Search.results.data.Local IP Address | string | The local IP Address. | 
| FireEyeHX.Search.results.data.Local IP Address | string | The local IP Address. | 
| FireEyeHX.Search.results.data.Local Port | number | The local Port. | 
| FireEyeHX.Search.results.data.Username | string | The username. | 
| FireEyeHX.Search.results.data.Remote Port | number | The remote port. | 
| FireEyeHX.Search.results.data.IP Address | string | The IP address. | 
| FireEyeHX.Search.results.data.Process Name | string | The process name. | 
| FireEyeHX.Search.results.data.Timestamp - Event | string | The timestamp of the event. | 
| FireEyeHX.Search.results.type | string | The type of the event. | 
| FireEyeHX.Search.results.id | string | The ID of the result. | 

#### Command example
```!fireeye-hx-search hostsNames=XXX ipAddress=xx.xx.xx.xx ipAddressOperator=equals polling=false```
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
| FireEyeHX.Alerts._id | Number | The ID of the FireEye alert. | 
| FireEyeHX.Alerts.agent._id | Unknown | The ID of the FireEye agent. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | The containment state of the agent. | 
| FireEyeHX.Alerts.condition._id | String | The unique ID of the condition. | 
| FireEyeHX.Alerts.event_at | String | The time when the event occurred. | 
| FireEyeHX.Alerts.matched_at | String | The time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | String | The time when the event was reported. | 
| FireEyeHX.Alerts.source | String | The source of the alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | The ID of the source alert. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | The ID of the appliance. | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | The source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | The ID of the indicator. | 
| FireEyeHX.Alerts.resolution | String | The alert resolution. | 
| FireEyeHX.Alerts.event_type | String | The type of the event. | 

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
                "_id": "YYYXXXYYY",
                "containment_state": "normal",
                "url": "/hx/api/v3/hosts/YYYXXXYYY"
            },
            "appliance": {
                "_id": "YYYXXXYYY"
            },
            "condition": {
                "_id": "YYYXXXYYY",
                "url": "/hx/api/v3/conditions/YYYXXXYYY"
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
Suppresses an alert by ID.


#### Base Command

`fireeye-hx-suppress-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert ID. The alert ID is listed in the output of 'get-alerts'. command. | Required | 


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
| category | The category of the indicator. | Optional | 
| searchTerm | The searchTerm can be any name, category, signature, source, or condition value. | Optional | 
| shareMode | Determines who can see the indicator. They must belong to the correct authorization group. Possible values are: any, restricted, unrestricted, visible. | Optional | 
| sort | Sorts the results by the specified field in ascending order. Possible values are: category, activeSince, createdBy, alerted. | Optional | 
| createdBy | The person who created the indicator. | Optional | 
| alerted | Whether the indicator resulted in alerts. Possible values are: yes, no. | Optional | 
| limit | Limits the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | String | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | String | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | String | The description of the indicator. | 
| FireEyeHX.Indicators.category.name | String | The Category name. | 
| FireEyeHX.Indicators.created_by | String | The "Created By" field as displayed in UI. | 
| FireEyeHX.Indicators.active_since | String | The date the indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | The total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | The total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | The list of operating systems. | 
| FireEyeHX.Indicators.uri_name | String | The URI formatted name of the indicator. | 
| FireEyeHX.Indicators.category.uri_name | String | The URI name of the category. | 

#### Command example
```!fireeye-hx-get-indicators limit=2```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": [
            {
                "_id": "YYYXXXYYY",
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
                    "username": "test"
                },
                "create_text": null,
                "created_by": "test",
                "description": null,
                "display_name": null,
                "meta": null,
                "name": "YYYXXXYYY",
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
                    "username": "test"
                },
                "uri_name": "YYYXXXYYY",
                "url": "/hx/api/v3/indicators/custom/37a97ac2_35e9_40ad_a108_6802d5d82890"
            },
            {
                "_id": "YYYXXXYYY",
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
                    "username": "test"
                },
                "create_text": null,
                "created_by": "test",
                "description": null,
                "display_name": null,
                "meta": null,
                "name": "YYYXXXYYY",
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
                    "username": "test"
                },
                "uri_name": "YYYXXXYYY",
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
>| win, osx, linux | YYYXXXYYY | test | 2022-02-23T09:18:09.012Z | Custom |  | 0 | 0 | 0 |
>| win, osx, linux | YYYXXXYYY | test | 2022-02-23T07:57:46.635Z | Custom |  | 0 | 0 | 0 |


### fireeye-hx-get-indicator
***
Get details of a specific indicator.


#### Base Command

`fireeye-hx-get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The category of the indicator. Use the `uri_category` value. | Required | 
| name | The name of the indicator. Use the `uri_name` value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | String | The FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | String | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | String | The description of the indicator. | 
| FireEyeHX.Indicators.category.name | String | The name of the category. | 
| FireEyeHX.Indicators.created_by | String | The "Created By" field as displayed in UI. | 
| FireEyeHX.Indicators.active_since | String | The date the indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | The total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | The total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | The list of operating systems. | 
| FireEyeHX.Conditions._id | Unknown | The ID of the FireEye unique condition. | 
| FireEyeHX.Conditions.event_type | Unknown | The type of the event. | 
| FireEyeHX.Conditions.enabled | Unknown | Indicates whether the condition is enabled. | 

#### Command example
```!fireeye-hx-get-indicator category=Custom name=YYYXXXYYY```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": {
            "_id": "YYYXXXYYY",
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
                "username": "test"
            },
            "create_text": null,
            "created_by": "test",
            "description": null,
            "display_name": null,
            "meta": null,
            "name": "YYYXXXYYY",
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
                "username": "test"
            },
            "uri_name": "YYYXXXYYY",
            "url": "/hx/api/v3/indicators/custom/5d5cea45_2856_4338_8de8_7ef2b16f9511"
        }
    }
}
```

#### Human Readable Output

>### Indicator 'YYYXXXYYY' Alerts on
>**No entries.**


### fireeye-hx-append-conditions
***
Add conditions to an indicator. Conditions can be MD5, hash values, domain names and IP addresses.


#### Base Command

`fireeye-hx-append-conditions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. Use the `uri_category` value. | Required | 
| name | The name of the indicator. Use the `uri_name` value. | Required | 
| condition | A list of conditions to add. The list can include a list of IPv4 addresses, MD5 files, and domain names. For example, example.netexample.orgexample.lol. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-append-conditions category=Custom name=YYYXXXYYY condition=exsmple.com```
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
>| Custom | exsmple.com | YYYXXXYYY |


### fireeye-hx-search-delete
***
Deletes the search by ID.


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
Deletes the file acquisition by ID.


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
Approves pending containment requests made by other components or users. The required permission is api_admin role.


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
Inserts a new host set policy on your Endpoint Security server.


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
```!fireeye-hx-assign-host-set-policy hostSetId=1005 policyId=YYYXXXYYY```
#### Human Readable Output

>This hostset may already be included in this policy

### fireeye-hx-get-data-acquisition
***
Collects artifacts from the system disk and memory for the given acquisition ID (the data is fetched as a MANS file).


#### Base Command

`fireeye-hx-get-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition unique ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The unique ID of the acquisition. | 
| FireEyeHX.Acquisitions.Data.state | string | The state of the acquisition. | 
| FireEyeHX.Acquisitions.Data.md5 | string | The MD5 of the file. | 
| FireEyeHX.Acquisitions.Data.host._id | string | The ID of the agent. | 
| FireEyeHX.Acquisitions.Data.finish_time | string | The time when the acquisition finished. | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | The hostname. | 
| FireEyeHX.Acquisitions.Data.instance | date | The FireEye HX instance. | 

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
        "Name": "102_agent_YYYXXXYYY_data.mans",
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
                    "_id": "YYYXXXYYY",
                    "hostname": "XXX",
                    "url": "/hx/api/v3/hosts/YYYXXXYYY"
                },
                "instance": "FireEyeHX v2_instance_1",
                "md5": null,
                "name": "osxDefaultScript",
                "request_actor": {
                    "_id": 1001,
                    "username": "test"
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
Start a data acquisition process to gather artifacts from the system disk and memory (the data is fetched as mans file).


#### Base Command

`fireeye-hx-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | The acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Select the host system, which uses the default script. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 
| acquisition_id | This argument is deprecated. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | Number | The unique ID of the acquisition. | 
| FireEyeHX.Acquisitions.Data.state | String | The state of the acquisition. | 
| FireEyeHX.Acquisitions.Data.md5 | String | The MD5 of the file. | 
| FireEyeHX.Acquisitions.Data.finish_time | String | The time when the acquisition finished. | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | The ID of the agent. | 

#### Command example
```!fireeye-hx-data-acquisition hostName=XXX defaultSystemScript=osx```
#### Human Readable Output

>Acquisition request was successful
>Acquisition ID: 104

### fireeye-hx-get-alerts
***
Returns a list of alerts. Use the different arguments to filter the results returned.


#### Base Command

`fireeye-hx-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hasShareMode | Identifies which alerts result from indicators with the specified share mode. Possible values are: any, restricted, unrestricted. | Optional | 
| resolution | Sorts the results by the specified field. Possible values are: active_threat, alert, block, partial_block. | Optional | 
| agentId | Filter by the agent ID. | Optional | 
| conditionId | Filter by condition ID. | Optional | 
| eventAt | Filter by the event occurred time. ISO-8601 timestamp. | Optional | 
| alertId | Filter by the alert ID. | Optional | 
| matchedAt | Filter by the match detection time. ISO-8601 timestamp. | Optional | 
| minId | Filter by returning only records with an AlertId field value greater than the minId value. | Optional | 
| reportedAt | Filter by the reported time. ISO-8601 timestamp. | Optional | 
| IOCsource | The source of the alert-indicator of compromise. Possible values are: yes. | Optional | 
| EXDsource | The source of the alert - exploit detection. Possible values are: yes. | Optional | 
| MALsource | The Source of the malware alert. Possible values are: yes. | Optional | 
| limit | Limit the results returned. | Optional | 
| sort | Sorts the results by the specified field in ascending order. Possible values are: agentId, conditionId, eventAt, alertId, matchedAt, id, reportedAt. | Optional | 
| sortOrder | The sort order for the results. Possible values are: ascending, descending. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Number | The ID of the FireEye alert. | 
| FireEyeHX.Alerts.agent._id | Unknown | The ID of the FireEye agent. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | The state of the agent containment. | 
| FireEyeHX.Alerts.condition._id | String | The unique ID of the alert. | 
| FireEyeHX.Alerts.event_at | String | The time when the event occurred. | 
| FireEyeHX.Alerts.matched_at | String | The time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | String | The time when the event was reported. | 
| FireEyeHX.Alerts.source | String | The source of the alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | The ID of the source alert. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | The ID of the appliance. | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | The source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | The ID of the indicator. | 
| FireEyeHX.Alerts.resolution | String | The alert resolution. | 
| FireEyeHX.Alerts.event_type | String | The type of the event. | 

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
                    "_id": "YYYXXXYYY",
                    "containment_state": "normal",
                    "url": "/hx/api/v3/hosts/YYYXXXYYY"
                },
                "appliance": {
                    "_id": "86285DC29A17"
                },
                "condition": {
                    "_id": "YYYXXXYYY",
                    "url": "/hx/api/v3/conditions/YYYXXXYYY"
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
                    "_id": "YYYXXXYYY",
                    "containment_state": "normal",
                    "url": "/hx/api/v3/hosts/YYYXXXYYY"
                },
                "appliance": {
                    "_id": "86285DC29A17"
                },
                "condition": {
                    "_id": "YYYXXXYYY",
                    "url": "/hx/api/v3/conditions/YYYXXXYYY"
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
>| 7 | 2022-01-24T10:37:51.306Z | fileWriteEvent | YYYXXXYYY |
>| 8 | 2022-01-25T10:25:44.011Z | fileWriteEvent | YYYXXXYYY |


### fireeye-hx-file-acquisition
***
Acquires a specific file as a password protected zip file. The password for unlocking the zip file is 'unzip-me'.


#### Base Command

`fireeye-hx-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisition_id | The acquisition ID. This argument is deprecated. | Optional | 
| fileName | The file name. | Required | 
| filePath | The file path. | Required | 
| acquireUsing | Whether to acquire the file using the API or RAW. By default, the RAW file will be acquired. Use the API option when file is encrypted. Possible values are: API, RAW. | Optional | 
| agentId | The agent ID associated with the host that holds the file. If the host name is not specified, the agentId must be specified. | Optional | 
| hostName | The host that holds the file. If the agentId is not specified, hostName must be specified. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Files._id | Number | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Files.state | String | The acquisition state. | 
| FireEyeHX.Acquisitions.Files.md5 | String | The MD5 of the file. | 
| FireEyeHX.Acquisitions.Files.req_filename | String | The name of the file. | 
| FireEyeHX.Acquisitions.Files.req_path | String | The path of the file. | 
| FireEyeHX.Acquisitions.Files.host._id | String | The ID of the FireEye HX agent. | 

### fireeye-hx-create-indicator
***
Create a new indicator.


#### Base Command

`fireeye-hx-create-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- |----------|
| category | The indicator category. | Required |
| display_name | Display name for the indicator. | Optional |
| description | Description for the indicator. | Optional |
| platforms | The platform for the indicator. If not selected, the indicator will be created for all platforms. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators.active_since | date | The date the indicator became active. | 
| FireEyeHX.Indicators.meta | string | The meta data for new indicator. | 
| FireEyeHX.Indicators.display_name | string | The display name of the indicator. | 
| FireEyeHX.Indicators.name | string | The indicator name, as displayed in the UI. | 
| FireEyeHX.Indicators.created_by | string | The "Created By" field, as displayed in UI | 
| FireEyeHX.Indicators.url | string | The data URL. | 
| FireEyeHX.Indicators.create_text | Unknown | The indicator created text. | 
| FireEyeHX.Indicators.platforms | string | The list of operating systems. | 
| FireEyeHX.Indicators.create_actor._id | number | The ID of the actor. | 
| FireEyeHX.Indicators.create_actor.username | string | The user name of the actor. | 
| FireEyeHX.Indicators.signature | string | The signature of the indicator. | 
| FireEyeHX.Indicators._revision | string | The indicator revision. | 
| FireEyeHX.Indicators._id | string | The ID of the FireEye unique indicator. | 
| FireEyeHX.Indicator.description | string | The description of the indicator. | 
| FireEyeHX.Indicators.category._id | number | The ID of the category. | 
| FireEyeHX.Indicators.category.name | string | The name of the category. | 
| FireEyeHX.Indicators.category.share_mode | string | The share mode of the category. | 
| FireEyeHX.Indicators.category.uri_name | string | The URI name of the category. | 
| FireEyeHX.Indicators.category.url | string | The URL of the category. | 
| FireEyeHX.Indicators.uri_name | string | The URI name of the indicator. | 
| FireEyeHX.Indicators.stats.active_conditions | number | The active conditions of the indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | number | The total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.source_alerts | number | The total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.update_actor._id | number | The ID of the updated actor. | 
| FireEyeHX.Indicators.update_actor.username | string | The updated name of the actor. | 

#### Command example
```!fireeye-hx-create-indicator category=Custom```
#### Context Example
```json
{
    "FireEyeHX": {
        "Indicators": {
            "_id": "YYYXXXYYY",
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
                "username": "test"
            },
            "create_text": null,
            "created_by": "test",
            "description": null,
            "display_name": null,
            "meta": null,
            "name": "YYYXXXYYY",
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
                "username": "test"
            },
            "uri_name": "YYYXXXYYY",
            "url": "/hx/api/v3/indicators/custom/37a97ac2_35e9_40ad_a108_6802d5d82890"
        }
    }
}
```

#### Human Readable Output

>### FireEye HX New Indicator created successfully
>|ID|
>|---|
>| YYYXXXYYY |


### fireeye-hx-delete-host-set-policy
***
Deletes a Host Set policy.


#### Base Command

`fireeye-hx-delete-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetId | The host set ID. | Required | 
| policyId | The policy ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-delete-host-set-policy hostSetId=1005 policyId=YYYXXXYYY```
#### Human Readable Output
>Success


### fireeye-hx-delete-data-acquisition
***
Deletes data acquisition.


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

### fireeye-hx-delete-indicator-condition
***
Delete an indicator condition.


#### Base Command

`fireeye-hx-delete-indicator-condition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Required | 
| indicator_name | The name of the indicator. Use the `uri_name` value. | Required | 
| type | The condition type. Possible values are: presence, execution. | Required | 
| condition_id | The condition ID, which is part of the response when you request a list of all conditions known to the HX Series appliance. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-delete-indicator-condition category=Custom condition_id=myFIAYoWKoWqaaYQ7CxHVA== indicator_name=7f49e4c6-14d5-4b06-8d17-843fd17f79de type=execution```
#### Human Readable Output

>Successfully deleted condition myFIAYoWKoWqaaYQ7CxHVA== (execution) of indicator 7f49e4c6-14d5-4b06-8d17-843fd17f79de (Custom)


### fireeye-hx-list-indicator-category
***
Lists the indicator categories.


#### Base Command

`fireeye-hx-list-indicator-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Performs a search of indicator categories. Searchable values are based on the name, display_name, retention_policy, ui_edit_policy, ui_signature_enabled, ui_source_alerts_enabled. | Optional | 
| name | Filter for indicator categories with the specified name. | Optional | 
| display_name | Filter for indicator categories with given display name. | Optional | 
| retention_policy | The retention policy. Possible values are: manual, auto, intel. | Optional | 
| ui_edit_policy | The UI edit policy. Possible values are: full, edit_delete, delete, read_only. | Optional | 
| ui_signature_enabled | Whether to enable the UI signature. Possible values are: true, false. | Optional | 
| ui_source_alerts_enabled | Whether to enable UI source alerts. Possible values are: true, false. | Optional | 
| share_mode | Share mode. Possible values are: restricted, unrestricted, silent, visible, any. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| offset | Result offset. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.IndicatorCategory.uri_name | number | The policy ID of the indicator category. | 
| FireEyeHX.IndicatorCategory.name | string | The name of the indicator category. | 
| FireEyeHX.IndicatorCategory._revision | number | The revision of the indicator category. | 
| FireEyeHX.IndicatorCategory.display_name | string | The display name of the indicator category. | 
| FireEyeHX.IndicatorCategory.retention_policy | string | The retention policy of the indicator category. | 
| FireEyeHX.IndicatorCategory.ui_edit_policy | string | The UI edit policy of the indicator category. | 
| FireEyeHX.IndicatorCategory.ui_signature_enabled | boolean | Whether the UI signature is enabled. | 
| FireEyeHX.IndicatorCategory.ui_source_alerts_enabled | boolean | Whether the UI source alerts is enabled. | 
| FireEyeHX.IndicatorCategory.share_mode | string | The share mode of the indicator category. | 

#### Command example
```!fireeye-hx-list-indicator-category search=fireEye```
#### Context Example
```json
{
    "FireEyeHX": {
        "IndicatorCategory": [
            {
                "_id": 4,
                "_revision": "20200423145028596495100030",
                "display_name": null,
                "name": "FireEye",
                "retention_policy": "auto",
                "share_mode": "unrestricted",
                "ui_edit_policy": "delete",
                "ui_signature_enabled": true,
                "ui_source_alerts_enabled": true,
                "uri_name": "FireEye",
                "url": "/hx/api/v3/indicator_categories/fireeye"
            },
            {
                "_id": 8,
                "_revision": "20200423145028596495100038",
                "display_name": "FireEye Restricted",
                "name": "FireEye Restricted",
                "retention_policy": "auto",
                "share_mode": "restricted",
                "ui_edit_policy": "delete",
                "ui_signature_enabled": true,
                "ui_source_alerts_enabled": true,
                "uri_name": "fireeye_restricted",
                "url": "/hx/api/v3/indicator_categories/fireeye_restricted"
            },
            {
                "_id": 5,
                "_revision": "20200423145028596495100032",
                "display_name": null,
                "name": "FireEye-CMS",
                "retention_policy": "auto",
                "share_mode": "unrestricted",
                "ui_edit_policy": "delete",
                "ui_signature_enabled": true,
                "ui_source_alerts_enabled": true,
                "uri_name": "FireEye-CMS",
                "url": "/hx/api/v3/indicator_categories/fireeye_cms"
            }
        ]
    }
}
```

#### Human Readable Output

>### 3 Indicator categories found
>|Name|Policy ID|
>|---|---|
>| FireEye | 4 |
>| FireEye Restricted | 8 |
>| FireEye-CMS | 5 |


### fireeye-hx-delete-indicator
***
Delete an indicator.


#### Base Command

`fireeye-hx-delete-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The category name. | Required | 
| indicator_name | The name of the indicator. Use the `uri_name` value. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fireeye-hx-delete-indicator category=Custom indicator_name=7f49e4c6-14d5-4b06-8d17-843fd17f79de```
#### Human Readable Output

>Successfully deleted indicator 7f49e4c6-14d5-4b06-8d17-843fd17f79de from the Custom category

### fireeye-hx-create-host-set-static
***
Creates static host set.


#### Base Command

`fireeye-hx-create-host-set-static`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_set_name | The host set name. | Required | 
| hosts_ids | The hosts IDs to add to the host set. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | String | The host set ID. | 
| FireEyeHX.HostSets.url | String | URI to retrieve data for this record. | 
| FireEyeHX.HostSets.name | String | The host set name. | 
| FireEyeHX.HostSets._revision | String | Timestamp of last update. Used for preventing updates with obsolete data. If _revision in the request body does not match _revision in the database, the update will fail. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-create-host-set-static host_set_name=demisto_test hosts_ids=Hqb2ns3oui1fpzg0BxI1Ch```
#### Human Readable Output

>Static Host Set demisto_test with id 1001 was created successfully.
### fireeye-hx-update-host-set-static
***
Updates a static host set.


#### Base Command

`fireeye-hx-update-host-set-static`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_set_id | The host set ID. | Required | 
| host_set_name | The host set name. | Required | 
| add_host_ids | The host sets IDs to add. | Optional | 
| remove_host_ids | The host set IDs to remove. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | String | The host set ID. | 
| FireEyeHX.HostSets.url | String | URI to retrieve data for this record. | 
| FireEyeHX.HostSets.name | String | The host set name. | 
| FireEyeHX.HostSets._revision | String | Timestamp of last update. Used for preventing updates with obsolete data. If _revision in the request body does not match _revision in the database, the update will fail. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-update-host-set-static host_set_name=demisto_test host_set_id=1036 add_host_ids=GfLI00Q4zpidezw9I11rV6 remove_host_ids=Hqb2ns3oui1fpzg0BxI1Ch```
#### Human Readable Output

>Static Host Set demisto_test was updated successfully.
### fireeye-hx-create-host-set-dynamic
***
Creates dynamic host set.


#### Base Command

`fireeye-hx-create-host-set-dynamic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_set_name | The host set name. | Required | 
| query | Free text query. Cannot be used with the other query arguments. | Optional | 
| query_key | The query key. Must be provided with the query_value and query_operator. Possible values are: domain, product_name, patch_level, timezone, os_bitness, cloud_provider, app_version, hostname, server_time, gmt_offset_seconds, primary-ip_address, normalized_app_version, litmus_script_id, app_config_hash, platform. | Optional | 
| query_value | The query value. Must be provided with the query_key and query_operator. | Optional | 
| query_operator | The query operator. Must be provided with the query_key and query_value. Possible values are: eq, gt, lt, lte, gte, exists, cidr. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | String | The host set ID. | 
| FireEyeHX.HostSets.url | String | URI to retrieve data for this record. | 
| FireEyeHX.HostSets.name | String | The host set name. | 
| FireEyeHX.HostSets._revision | String | Timestamp of last update. Used for preventing updates with obsolete data. If _revision in the request body does not match _revision in the database, the update will fail. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-create-host-set-dynamic host_set_name=demisto_test query_key=Bitlevel query_operator=eq query_value=64-bit```
```!fireeye-hx-update-host-set-dynamic host_set_name=MoreTestyay query=`{"key": "AgentVersion","value": "31.28.17","operator": "gte"}` ```
#### Human Readable Output

>Dynamic Host Set demisto_test with id 1068 was created successfully.
### fireeye-hx-update-host-set-dynamic
***
Updates dynamic host set.


#### Base Command

`fireeye-hx-update-host-set-dynamic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_set_name | The host set name. | Required | 
| host_set_id | The host set ID. | Required | 
| query | Free text query. Cannot be used with the other query arguments. | Optional | 
| query_key | The query key. Must be provided with the query_value and query_operator. Possible values are: domain, product_name, patch_level, timezone, os_bitness, cloud_provider, app_version, hostname, server_time, gmt_offset_seconds, primary-ip_address, normalized_app_version, litmus_script_id, app_config_hash, platform. | Optional | 
| query_value | The query value. Must be provided with the query_key and query_operator. | Optional | 
| query_operator | The query operator. Must be provided with the query_value and query_key. Possible values are: eq, gt, lt, lte, gte, exists, cidr. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | String | The host set ID. | 
| FireEyeHX.HostSets.url | String | URI to retrieve data for this record. | 
| FireEyeHX.HostSets.name | String | The host set name. | 
| FireEyeHX.HostSets._revision | String | Timestamp of last update. Used for preventing updates with obsolete data. If _revision in the request body does not match _revision in the database, the update will fail. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-update-host-set-dynamic host_set_name=demisto_test query_key=Bitlevel query_operator=eq query_value=64-bit host_set_id=1061```
```!fireeye-hx-update-host-set-dynamic host_set_name=MoreTestyay query=`{"key": "AgentVersion","value": "31.28.17","operator": "gte"}` host_set_id=1061```
#### Human Readable Output

>Dynamic Host Set Demisto_test was updated successfully.
### fireeye-hx-delete-host-set
***
Deletes a host set.


#### Base Command

`fireeye-hx-delete-host-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_set_id | The host set ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | String | The host set ID. | 
| FireEyeHX.HostSets.deleted | Boolean | Was the host set deleted. | 

#### Command example
```!fireeye-hx-delete-host-set host_set_id=1001```
#### Human Readable Output

>Host set 1001 was deleted successfully.