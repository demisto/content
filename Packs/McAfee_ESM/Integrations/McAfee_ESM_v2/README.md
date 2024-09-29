
Run queries and receive alarms from Intel Security ESM.
This integration was integrated and tested with version 11.3 of McAfee ESM v2.
Previous versions have been declared [EOL](https://kc.mcafee.com/corporate/index?page=content&id=KB94822) by the vendor.

## Configure McAfee ESM v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Base URL \(e.g. https://example.com\) | True |
| credentials | Username | True |
| version | Version: \(one of 10.0, 10.1, 10.2, 10.3, 11.1, 11.3\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetchType | Fetch Types: cases, alarms, both \(relevant only for fetch incident mode\) | False |
| startingFetchID | Start fetch after ID: \(relevant only for fetch incident mode\) | False |
| fetchLimitCases | Fetch cases limit | False |
| fetchTime | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| fetchLimitAlarms | Fetch alarms limit | False |
| timezone | McAfee ESM Timezone in hours \(e.g if ESM timezone is \+0300 =&gt; then insert 3\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Required Permissions
| Component | Permission |
| --- | --- |
| Alarms | Alarm Management *and* View Data |
| Cases | Incident Management Administrator *and* Incident Management User |
| Watchlists | Watchlists |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### esm-fetch-fields
***
Gets all fields that can be used in query filters, including type information for each field


#### Base Command

`esm-fetch-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!esm-fetch-fields```


#### Human Readable Output

>### Fields
>|name|types|
>|---|---|
>| AppID | STRING |
>| CommandID | STRING |
>| DomainID | STRING |
>| HostID | STRING |
>| ObjectID | STRING |
>| UserIDDst | STRING |
>| UserIDSrc | STRING |
>| URL | SSTRING |
>| Database_Name | STRING |
>| Message_Text | SSTRING |
>| Response_Time | UINT32 |
>| Application_Protocol | STRING |
>| Object_Type | STRING |
>| Filename | SSTRING |
>| From | SSTRING |
>| To | SSTRING |
>| Cc | SSTRING |
>| Bcc | SSTRING |
>| Subject | SSTRING |
>| Method | STRING |
>| User_Agent | SSTRING |
>| Cookie | SSTRING |
>| Referer | SSTRING |
>| File_Operation | STRING |
>| File_Operation_Succeeded | STRING |
>| Destination_Filename | SSTRING |
>| User_Nickname | STRING |
>| Contact_Name | STRING |
>| Contact_Nickname | STRING |
>| Client_Version | SSTRING |
>| Job_Name | SSTRING |
>| Language | SSTRING |
>| SWF_URL | SSTRING |
>| TC_URL | SSTRING |
>| RTMP_Application | SSTRING |
>| Version | SSTRING |
>| Local_User_Name | SSTRING |
>| NAT_Details | UINT16,IPV4 |
>| Network_Layer | SIGID |
>| Transport_Layer | SIGID |
>| Session_Layer | SIGID |
>| Application_Layer | SIGID |
>| HTTP_Layer | SIGID |
>| HTTP_Req_URL | SSTRING |
>| HTTP_Req_Cookie | SSTRING |
>| HTTP_Req_Referer | SSTRING |
>| HTTP_Req_Host | SSTRING |
>| HTTP_Req_Method | SSTRING |
>| HTTP_User_Agent | SSTRING |
>| DNS_Name | SSTRING |
>| DNS_Type | STRING |
>| DNS_Class | STRING |
>| Query_Response | STRING |
>| Authoritative_Answer | STRING |
>| SNMP_Operation | STRING |
>| SNMP_Item_Type | STRING |
>| SNMP_Version | STRING |
>| SNMP_Error_Code | STRING |
>| NTP_Client_Mode | STRING |
>| NTP_Server_Mode | STRING |
>| NTP_Request | STRING |
>| NTP_Opcode | STRING |
>| SNMP_Item | SSTRING |
>| Interface | STRING |
>| Direction | STRING |
>| Sensor_Name | STRING |
>| Sensor_UUID | SSTRING |
>| Sensor_Type | STRING |
>| Signature_Name | SSTRING |
>| Threat_Name | SSTRING |
>| Destination_Hostname | SSTRING |
>| Category | SSTRING |
>| Process_Name | SSTRING |
>| Grid_Master_IP | IP |
>| Response_Code | STRING |
>| Device_Port | UINT64 |
>| Device_IP | IP |
>| PID | UINT64 |
>| Target_Context | SSTRING |
>| Source_Context | SSTRING |
>| Target_Class | SSTRING |
>| Policy_Name | SSTRING |
>| Destination_Zone | SSTRING |
>| Source_Zone | SSTRING |
>| Queue_ID | STRLIT |
>| Delivery_ID | SSTRING |
>| Recipient_ID | SSTRING |
>| Spam_Score | FLOAT |
>| Mail_ID | SSTRING |
>| To_Address | SSTRING |
>| From_Address | SSTRING |
>| Message_ID | SSTRING |
>| Request_Type | SSTRING |
>| SQL_Statement | SSTRING |
>| External_EventID | UINT64 |
>| Event_Class | SSTRING |
>| Description | SSTRING |
>| File_Hash | GUID |
>| Mainframe_Job_Name | SSTRING |
>| External_SubEventID | UINT64 |
>| Destination_UserID | SSTRING |
>| Source_UserID | SSTRING |
>| Volume_ID | SSTRING |
>| Step_Name | SSTRING |
>| Step_Count | SSTRING |
>| LPAR_DB2_Subsystem | SSTRING |
>| Logical_Unit_Name | SSTRING |
>| Job_Type | SSTRING |
>| FTP_Command | SSTRING |
>| File_Type | SSTRING |
>| DB2_Plan_Name | SSTRING |
>| Catalog_Name | SSTRING |
>| Access_Resource | SSTRING |
>| Table_Name | SSTRING |
>| External_DB2_Server | SSTRING |
>| External_Application | SSTRING |
>| Creator_Name | SSTRING |
>| Return_Code | STRING |
>| Database_ID | SSTRING |
>| Incoming_ID | SSTRING |
>| Handle_ID | UINT64 |
>| Destination_Network | SSTRING |
>| Source_Network | SSTRING |
>| Malware_Insp_Result | SSTRING |
>| Malware_Insp_Action | SSTRING |
>| External_Hostname | SSTRING |
>| Privileged_User | SSTRING |
>| Facility | SSTRING |
>| Area | SSTRING |
>| Instance_GUID | GUID |
>| Logon_Type | SSTRING |
>| Operating_System | SSTRING |
>| File_Path | SSTRING |
>| Agent_GUID | GUID |
>| Reputation | UINT64 |
>| URL_Category | SSTRING |
>| Session_Status | SSTRING |
>| Destination_Logon_ID | SSTRING |
>| Source_Logon_ID | SSTRING |
>| UUID | GUID |
>| External_SessionID | SSTRING |
>| Management_Server | SSTRING |
>| Detection_Method | SSTRING |
>| Target_Process_Name | SSTRING |
>| Analyzer_DAT_Version | FLOAT |
>| Forwarding_Status | SSTRING |
>| Reason | SSTRING |
>| Threat_Handled | SSTRING |
>| Threat_Category | SSTRING |
>| Device_Action | SSTRING |
>| Database_GUID | GUID |
>| SQL_Command | SSTRING |
>| Destination_Directory | SSTRING |
>| Directory | SSTRING |
>| Mailbox | SSTRING |
>| Handheld_ID | UINT64 |
>| Policy_ID | UINT64 |
>| Server_ID | UINT64 |
>| Registry_Value | SSTRING |
>| Registry_Key | SSTRING |
>| Caller_Process | SSTRING |
>| DAT_Version | FLOAT |
>| Interface_Dest | SSTRING |
>| Datacenter_Name | SSTRING |
>| Datacenter_ID | SSTRING |
>| Virtual_Machine_ID | SSTRING |
>| Virtual_Machine_Name | SSTRING |
>| PCAP_Name | SSTRING |
>| Search_Query | SSTRING |
>| Service_Name | SSTRING |
>| External_Device_Name | SSTRING |
>| External_Device_ID | SSTRING |
>| External_Device_Type | SSTRING |
>| Organizational_Unit | SSTRING |
>| Privileges | SSTRING |
>| Reputation_Name | SSTRING |
>| Vulnerability_References | SSTRING |
>| Web_Domain | SSTRING |
>| Sub_Status | SSTRING |
>| Status | SSTRING |
>| Access_Privileges | SSTRING |
>| Rule_Name | SSTRING |
>| App_Layer_Protocol | SSTRING |
>| Group_Name | SSTRING |
>| Authentication_Type | SSTRING |
>| New_Value | SSTRING |
>| Old_Value | SSTRING |
>| Security_ID | SSTRING |
>| SHA1 | SSTRING |
>| Reputation_Score | FLOAT |
>| Parent_File_Hash | GUID |
>| File_ID | SSTRING |
>| Engine_List | SSTRING |
>| Device_URL | SSTRING |
>| Attacker_IP | IPV4 |
>| Victim_IP | IPV4 |
>| Incident_ID | INT64 |
>| Attribute_Type | SSTRING |
>| Access_Mask | SSTRING |
>| Object_GUID | GUID |
>| VPN_Feature_Name | SSTRING |
>| Reputation_Server_IP | IP |
>| DNS_Server_IP | IP |
>| Hash_Type | SSTRING |
>| Hash | SSTRING |
>| Subcategory | SSTRING |
>| Wireless_SSID | SSTRING |
>| Share_Name | SSTRING |
>| CnC_Host | SSTRING |
>| Device_Confidence | UINT64 |
>| SHA256 | SSTRING |
>| AppID | STRING |
>| CommandID | STRING |
>| DSIDSigID | SIGID |
>| Action | UINT8 |
>| ASNGeoDst | UINT64 |
>| DSID | UINT64 |
>| ZoneDst | UINT16 |
>| SigID | SIGID |
>| GUIDSrc | GUID |
>| NDDevIDSrc | UINT16 |
>| ID | UINT64 |
>| Protocol | UINT8 |
>| NormID | UINT32 |
>| ZoneSrc | UINT16 |
>| FirstTime | UINT32 |
>| SrcPort | UINT16 |
>| AvgSeverity | FLOAT |
>| DstPort | UINT16 |
>| SrcIP | IP |
>| GUIDDst | GUID |
>| DstIP | IP |
>| NDDevIDDst | UINT16 |
>| SrcMac | MAC_ADDRESS |
>| SessionID | UINT64 |
>| ASNGeoSrc | UINT64 |
>| DstMac | MAC_ADDRESS |
>| LastTime | UINT32 |


### esm-search
***
Perform a query against Mcafee ESM SIEM


#### Base Command

`esm-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeRange | The time period for the search. Can be LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, or CURRENT_WEEK. | Optional |
| filters | Filter on the query results, should be a JSON string, of the format EsmFilter (read more on that here - https://&lt;esm-ip&gt;:&lt;esm-port&gt;/rs/esm/help/types/EsmFilter) | Required |
| queryType | Type of query to run. Can be "EVENT", "FLOW", or "ASSETS". Default is "EVENT". | Optional |
| timeOut | Maximum time to wait before timeout (in minutes). Default is 30. | Optional |
| customStart | If the timeRange argument is set to CUSTOM, the start time for the time range. For example: 2017-06-01T12:48:16.734Z | Optional |
| customEnd | If the timeRange argument is set to CUSTOM, the end time for the time range. For example: 2017-06-01T12:48:16.734Z | Optional |
| fields | The fields that will be selected when this query is executed. | Optional |
| limit | Query results can be limited to a maximum row count. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-search timeRange="CURRENT_YEAR" filters="[{\"type\":\"EsmFieldFilter\",\"field\":{\"name\":\"SrcIP\"},\"operator\":\"IN\"}]" limit="3"```

#### Context Example
```
{
    "McAfeeESM": {
        "results": [
            {
                "ActionName": "success",
                "AlertDstIP": "192.168.1.111",
                "AlertDstPort": "0",
                "AlertIPSIDAlertID": "144115188075855872|779674",
                "AlertLastTime": "2020-01-01T05:48:20Z",
                "AlertProtocol": "n/a",
                "AlertSrcIP": "22.22.22.22",
                "AlertSrcPort": "0"
            },
            {
                "ActionName": "success",
                "AlertDstIP": "192.168.1.111",
                "AlertDstPort": "0",
                "AlertIPSIDAlertID": "144115188075855872|779675",
                "AlertLastTime": "2020-01-01T05:48:22Z",
                "AlertProtocol": "n/a",
                "AlertSrcIP": "22.22.22.22",
                "AlertSrcPort": "0"
            },
            {
                "ActionName": "success",
                "AlertDstIP": "192.168.1.111",
                "AlertDstPort": "0",
                "AlertIPSIDAlertID": "144115188075855872|779676",
                "AlertLastTime": "2020-01-01T10:51:57Z",
                "AlertProtocol": "n/a",
                "AlertSrcIP": "33.33.33.33",
                "AlertSrcPort": "0"
            }
        ]
    }
}
```

#### Human Readable Output

>Search results
>|Alert.IPSIDAlertID|Alert.SrcIP|Alert.SrcPort|Alert.DstIP|Alert.DstPort|Alert.Protocol|Alert.LastTime|Action.Name|
>|--|--|--|--|--|--|--|--|
>| 144115188075855872\|779674|22.22.22.22|0|192.168.1.111|0|n/a|2020-01-01T05:48:20Z|success |
>| 144115188075855872\|779675|22.22.22.22|0|192.168.1.111|0|n/a|2020-01-01T05:48:22Z|success |
>| 144115188075855872\|779676|33.33.33.33|0|192.168.1.111|0|n/a|2020-01-01T10:51:57Z|success |

### esm-fetch-alarms
***
Retrieves a list of triggered alarms.


#### Base Command

`esm-fetch-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeRange | The time period for the search. Can be LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, or CURRENT_WEEK. | Optional |
| customStart | If the timeRange argument is set to CUSTOM, the start time for the time range. For example: 2017-06-01T12:48:16.734Z | Optional |
| customEnd | If the timeRange argument is set to CUSTOM, the end time for the time range. For example: 2017-06-01T12:48:16.734Z | Optional |
| assignedUser | User assigned to handle the triggered alarm. Use the 'ME' option to use the instance user, or use [format EsmUser](https://&lt;esm-ip&gt;:&lt;esm-port&gt;/rs/esm/help/types/EsmUser).  | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Alarm.ID | number | Alarm ID. |
| McAfeeESM.Alarm.summary | string | Alarm summary. |
| McAfeeESM.Alarm.assignee | string | Alarm assignee. |
| McAfeeESM.Alarm.severity | number | Alarm severity. |
| McAfeeESM.Alarm.triggeredDate | date | Alarm triggered date. |
| McAfeeESM.Alarm.acknowledgedDate | date | Alarm acknowledged date. |
| McAfeeESM.Alarm.acknowledgedUsername | string | Alarm acknowledged username. |
| McAfeeESM.Alarm.alarmName | string | Alarm name. |
| McAfeeESM.Alarm.conditionType | number | Alarm condition type. |


#### Command Example
```!esm-fetch-alarms timeRange=CURRENT_MONTH```

#### Context Example
```
{
    "McAfeeESM": {
        "Alarm": [
            {
                "ID": 42710,
                "acknowledgedDate": "",
                "acknowledgedUsername": "",
                "alarmName": "Alarm Test",
                "assignee": "ANALYST",
                "conditionType": 22,
                "severity": 50,
                "summary": "Event rate exceeded 10 by 17",
                "triggeredDate": "2020-06-24T13:05:43Z"
            },
            {
                "ID": 42709,
                "acknowledgedDate": "",
                "acknowledgedUsername": "",
                "alarmName": "Alarm Test",
                "assignee": "ANALYST",
                "conditionType": 22,
                "severity": 50,
                "summary": "Event rate exceeded 10 by 1",
                "triggeredDate": "2020-06-24T12:53:12Z"
            },
            {
                "ID": 42708,
                "acknowledgedDate": "",
                "acknowledgedUsername": "",
                "alarmName": "Alarm Test",
                "assignee": "ANALYST",
                "conditionType": 22,
                "severity": 50,
                "summary": "Event rate exceeded 10 by 2",
                "triggeredDate": "2020-06-24T11:32:08Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alarms
>|id|acknowledgedDate|acknowledgedUsername|alarmName|assignee|conditionType|severity|summary|triggeredDate|
>|---|---|---|---|---|---|---|---|---|
>| 42710 |  |  | Alarm Test | ANALYST | 22 | 50 | Event rate exceeded 10 by 17 | 2020-06-24T13:05:43Z |
>| 42709 |  |  | Alarm Test | ANALYST | 22 | 50 | Event rate exceeded 10 by 1 | 2020-06-24T12:53:12Z |
>| 42708 |  |  | Alarm Test | ANALYST | 22 | 50 | Event rate exceeded 10 by 2 | 2020-06-24T11:32:08Z |


### esm-get-case-list
***
Gets a list of cases from McAfee ESM.


#### Base Command

`esm-get-case-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters for cases that were opened before this date. In the format "&lt;number&gt;&lt;timeunit&gt;", for example: 1 day,30 minutes,2 weeks,6 months,1 year | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | Case ID. |
| McAfeeESM.Case.Summary | string | The summary of the case. |
| McAfeeESM.Case.Status | string | The status of the case. |
| McAfeeESM.Case.OpenTime | date | The date and time when the case was opened. |
| McAfeeESM.Case.Severity | number | The severity of the case. |


#### Command Example
```!esm-get-case-list since="1 month"```

#### Context Example
```
{
    "McAfeeESM": {
        "Case": [
            {
                "ID": 33262,
                "OpenTime": "2020-06-23T06:38:03Z",
                "Severity": 50,
                "Status": "Open",
                "Summary": "Signature ID 'Failed User Logon' (306-31) match found"
            },
            {
                "ID": 33261,
                "OpenTime": "2020-06-22T12:04:09Z",
                "Severity": 50,
                "Status": "Open",
                "Summary": "Signature ID 'Failed User Logon' (306-31) match found"
            },
            {
                "ID": 33264,
                "OpenTime": "2020-06-23T12:13:08Z",
                "Severity": 50,
                "Status": "Open",
                "Summary": "Signature ID 'Failed User Logon' (306-31) match found"
            }
        ]
    }
}
```

#### Human Readable Output

>### cases since 1 month
>|ID|OpenTime|Severity|Status|Summary|
>|---|---|---|---|---|
>| 33262 | 2020-06-23T06:38:03Z | 50 | Open | Signature ID 'Failed User Logon' (306-31) match found |
>| 33261 | 2020-06-22T12:04:09Z | 50 | Open | Signature ID 'Failed User Logon' (306-31) match found |
>| 33264 | 2020-06-23T12:13:08Z | 50 | Open | Signature ID 'Failed User Logon' (306-31) match found |

### esm-add-case
***
Adds a case to the system.


#### Base Command

`esm-add-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| summary | The name of the case. | Required |
| status | The status of the case. Run the esm-get-case-statuses command to view all statuses. | Optional |
| assignee | User assigned to the case. | Optional |
| severity | The severity of the case (1 - 100). | Optional |
| organization | The organization assigned to the case. Run the esm-get-organization-list command to view all organizations. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. |
| McAfeeESM.Case.Summary | string | The summary of the case. |
| McAfeeESM.Case.Status | string | The status of the case. |
| McAfeeESM.Case.OpenTime | date | The open time of the case. |
| McAfeeESM.Case.Severity | number | The severity of the case. |
| McAfeeESM.Case.Assignee | string | The assignee of the case. |
| McAfeeESM.Case.Organization | string | The organization of the case. |
| McAfeeESM.Case.EventList | Unknown | List of the case's events. |
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. |


#### Command Example
```!esm-add-case summary="McAfee ESM v2 add case"```

#### Context Example
```
{
    "McAfeeESM": {
        "Case": {
            "Assignee": "ANALYST",
            "ID": 33272,
            "OpenTime": "2020-06-24T13:10:01Z",
            "Organization": "None",
            "Severity": 1,
            "Status": "Open",
            "Summary": "McAfee ESM v2 add case"
        }
    }
}
```

#### Human Readable Output

>### Case
>|Assignee|ID|OpenTime|Organization|Severity|Status|Summary|
>|---|---|---|---|---|---|---|
>| ANALYST | 33272 | 2020-06-24T13:10:01Z | None | 1 | Open | McAfee ESM v2 add case |


### esm-edit-case
***
Edit the details of an existing case.


#### Base Command

`esm-edit-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the case. | Required |
| summary | The name of the case. | Optional |
| severity | The new severity of the case (1 - 100). | Optional |
| assignee | User assigned to the case. | Optional |
| status | The new status of the case. Run the esm-get-case-statuses command to view all statuses. | Optional |
| organization | The organization assigned to the case. Run the esm-get-organization-list command to view all organizations. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. |
| McAfeeESM.Case.Summary | string | The summary of the case. |
| McAfeeESM.Case.Status | string | The status of the case. |
| McAfeeESM.Case.OpenTime | date | The open time of the case. |
| McAfeeESM.Case.Severity | number | The severity of the case. |
| McAfeeESM.Case.Assignee | string | The assignee of the case. |
| McAfeeESM.Case.Organization | string | The organization of the case. |
| McAfeeESM.Case.EventList | Unknown | List of the case's events. |
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. |


#### Command Example
```!esm-edit-case id="33266" summary="McAfee ESM v2 edit case"```

#### Context Example
```
{
    "McAfeeESM": {
        "Case": {
            "Assignee": "ANALYST",
            "ID": 33266,
            "OpenTime": "2020-06-24T10:54:21Z",
            "Organization": "None",
            "Severity": 1,
            "Status": "Open",
            "Summary": "McAfee ESM v2 edit case"
        }
    }
}
```

#### Human Readable Output

>### Case
>|Assignee|ID|OpenTime|Organization|Severity|Status|Summary|
>|---|---|---|---|---|---|---|
>| ANALYST | 33266 | 2020-06-24T10:54:21Z | None | 1 | Open | McAfee ESM v2 edit case |


### esm-get-case-statuses
***
Gets a list of valid case statuses from the system.


#### Base Command

`esm-get-case-statuses`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!esm-get-case-statuses```

#### Human Readable Output

>### case statuses
>|id|name|default|showInCasePane|
>|---|---|---|---|
>| 2 | Closed | false | false |
>| 11830 | McAfee_ESM_v2_add_case | false | false |
>| 1 | Open | true | true |
>| 11725 | Research_1563355610148 | false | true |
>| 11825 | TestMcAfee_ESM_v2 | false | false |
>| 11758 | bbbb | false | false |
>| 11776 | test | false | true |
>| 11777 | test1 | false | false |
>| 11268 | test2 | false | true |
>| 11267 | test3 | false | true |
>| 11890 | test_delete_case | false | false |
>| 11889 | test_edit_case | false | false |


### esm-edit-case-status
***
Edits the status of a case.


#### Base Command

`esm-edit-case-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| original_name | The name of the case status to edit. | Required |
| new_name | The new name for the case status. | Required |
| show_in_case_pane | Whether the status will display in the case pane. Can be "True" or "False". Default is "True". | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-edit-case-status original_name=test_edit_case new_name=edited_case```

#### Human Readable Output
>Edited case status with ID: 11889


### esm-get-case-detail
***
Gets the details of an existing case.


#### Base Command

`esm-get-case-detail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the case. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. |
| McAfeeESM.Case.Summary | string | The summary of the case. |
| McAfeeESM.Case.Status | string | The status of the case. |
| McAfeeESM.Case.OpenTime | date | The open time of the case. |
| McAfeeESM.Case.Severity | number | The severity of the case. |
| McAfeeESM.Case.Assignee | string | The assignee of the case. |
| McAfeeESM.Case.Organization | string | The organization of the case. |
| McAfeeESM.Case.EventList | Unknown | List of the case's events. |
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. |


#### Command Example
```!esm-get-case-detail id="33264"```

#### Context Example
```
{
    "McAfeeESM": {
        "Case": {
            "Assignee": "ANALYST",
            "ID": 33264,
            "OpenTime": "2020-06-23T12:13:08Z",
            "Organization": "None",
            "Severity": 50,
            "Status": "Open",
            "Summary": "Signature ID 'Failed User Logon' (306-31) match found"
        }
    }
}
```

#### Human Readable Output

>### Case
>|Assignee|ID|OpenTime|Organization|Severity|Status|Summary|
>|---|---|---|---|---|---|---|
>| ANALYST | 33264 | 2020-06-23T12:13:08Z | None | 50 | Open | Signature ID 'Failed User Logon' (306-31) match found |


### esm-get-case-event-list
***
Gets case event details.


#### Base Command

`esm-get-case-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma-separated list of event IDs. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.CaseEvent.ID | string | The ID of the event. |
| McAfeeESM.CaseEvent.LastTime | date | The time the event was last updated. |
| McAfeeESM.CaseEvent.Message | string | The message of the event. |


#### Command Example
```!esm-get-case-event-list ids="42687"```

### esm-add-case-status
***
Adds a status to the specified case.


#### Base Command

`esm-add-case-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the case status. | Required |
| show_in_case_pane | Whether the status will display in the case pane. Can be "True" or "False". Default is "True". | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-add-case-status name=test_add_case```

#### Human Readable Output

>Added case status : test_add_case

### esm-delete-case-status
***
Deletes the status of a case.


#### Base Command

`esm-delete-case-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the case status to delete. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-delete-case-status name=test_delete_case```

#### Human Readable Output

>Deleted case status with ID: 11890

### esm-get-organization-list
***
Gets a case organization.

#### Base Command

`esm-get-organization-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Organization.ID | number | Organization ID. |
| McAfeeESM.Organization.Name | string | Organization name. |


#### Command Example
```!esm-get-organization-list```

#### Context Example
```
{
    "McAfeeESM": {
        "Organization": [
            {
                "ID": 2,
                "Name": "ABC"
            },
            {
                "ID": 1,
                "Name": "Org"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organizations
>|id|name|
>|---|---|
>| 2 | ABC |
>| 1 | Org |


### esm-get-user-list
***
Gets a list of all users.


#### Base Command

`esm-get-user-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.User.ID | number | The ID of the user. |
| McAfeeESM.User.Name | string | The ESM user name. |
| McAfeeESM.User.Email | string | The email address of the user. |
| McAfeeESM.User.SMS | string | The SMS details of the user. |
| McAfeeESM.User.IsMaster | boolean | Whether the user is a master user. |
| McAfeeESM.User.IsAdmin | boolean | Whether the user is an admin. |


#### Command Example
```!esm-get-user-list```

#### Context Example
```
{
    "McAfeeESM": {
        "User": [
            {
                "Email": "",
                "Groups": "[]",
                "ID": 6,
                "IsAdmin": false,
                "IsMaster": false,
                "Name": "abcd",
                "SMS": ""
            },
            {
                "Email": "",
                "Groups": "[1, 2]",
                "ID": 7,
                "IsAdmin": true,
                "IsMaster": true,
                "Name": "gavrieltest",
                "SMS": ""
            },
            {
                "Email": "",
                "Groups": "[2]",
                "ID": 1,
                "IsAdmin": false,
                "IsMaster": true,
                "Name": "ANALYST",
                "SMS": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### User list
>|ID|Name|Email|Groups|IsMaster|IsAdmin|SMS|
>|---|---|---|---|---|---|---|
>| 6 | abcd |  | [] | false | false |  |
>| 7 | gavrieltest |  | [1, 2] | true | true |  |
>| 1 | ANALYST |  | [2] | true | false |  |


### esm-acknowledge-alarms
***
Marks triggered alarms as acknowledged.


#### Base Command

`esm-acknowledge-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to be marked as acknowledged. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-acknowledge-alarms alarmIds="42710"```


#### Human Readable Output

>Alarms has been Acknowledged.

### esm-unacknowledge-alarms
***
Marks triggered alarms as unacknowledged.


#### Base Command

`esm-unacknowledge-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to be marked as unacknowledged. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-unacknowledge-alarms alarmIds="42687"```

#### Human Readable Output

>Alarms has been Unacknowledged.

### esm-delete-alarms
***
Deletes triggered alarms.


#### Base Command

`esm-delete-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to delete. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!esm-delete-alarms alarmIds="42709"```

#### Human Readable Output

>Alarms has been Deleted.

### esm-get-alarm-event-details
***
Gets the details for the triggered alarm.


#### Base Command

`esm-get-alarm-event-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | The event for which to get the details. Run the esm-list-alarm-events command to get the ID. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.AlarmEvent.ID | string | Event ID. |
| McAfeeESM.AlarmEvent.SubType | string | Event type. |
| McAfeeESM.AlarmEvent.Severity | number | Event severity. |
| McAfeeESM.AlarmEvent.Message | string | Event message. |
| McAfeeESM.AlarmEvent.LastTime | date | Event time. |
| McAfeeESM.AlarmEvent.SrcIP | string | Source IP of the event. |
| McAfeeESM.AlarmEvent.DstIP | string | Destination IP of the event. |
| McAfeeESM.AlarmEvent.Cases | Unknown | A list of cases related to the event. |
| McAfeeESM.AlarmEvent.Cases.ID | string | Case ID. |
| McAfeeESM.AlarmEvent.Cases.OpenTime | date | Case creation time. |
| McAfeeESM.AlarmEvent.Cases.Severity | number | Case severity. |
| McAfeeESM.AlarmEvent.Cases.Status | string | Case status. |
| McAfeeESM.AlarmEvent.Cases.Summary | string | Case summary. |
| McAfeeESM.AlarmEvent.DstMac | string | Destination MAC address of the event. |
| McAfeeESM.AlarmEvent.SrcMac | string | Source MAC address of the event. |
| McAfeeESM.AlarmEvent.DstPort | string | Destination port of the event. |
| McAfeeESM.AlarmEvent.SrcPort | string | Source port of the event. |
| McAfeeESM.AlarmEvent.FirstTime | date | The first time for the event. |
| McAfeeESM.AlarmEvent.NormalizedDescription | string | Normalized description of the event. |


#### Command Example
```!esm-get-alarm-event-details eventId=144115188075855872|802641```

#### Context Example
```
{
    "McAfeeESM": {
        "AlarmEvent": {
            "Case": [
                {
                    "ID": 33260,
                    "OpenTime": "2020-06-22T06:16:24Z",
                    "Severity": 50,
                    "Status": "Open",
                    "Summary": "Signature ID 'Failed User Logon' (306-31) match found"
                }
            ],
            "DstIP": "192.168.1.111",
            "DstMac": "00:00:00:00:00:00",
            "DstPort": "0",
            "FirstTime": "2020-06-22T06:16:05Z",
            "ID": 802641,
            "LastTime": "2020-06-22T06:16:05Z",
            "Message": "Failed User Logon",
            "NormalizedDescription": "The Login category indicates events related to logging in to hosts or services.  Belongs to Authentication: The authentication category indicates events relating to system access.",
            "Severity": 25,
            "SrcIP": "44.44.44.44",
            "SrcMac": "00:00:00:00:00:00",
            "SrcPort": "0",
            "SubType": "failure"
        }
    }
}
```

#### Human Readable Output

>### Alarm events
>|Case|DstIP|DstMac|DstPort|FirstTime|ID|LastTime|Message|NormalizedDescription|Severity|SrcIP|SrcMac|SrcPort|SubType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'ID': 33260, 'OpenTime': '2020-06-22T06:16:24Z', 'Severity': 50, 'Status': 'Open', 'Summary': "Signature ID 'Failed User Logon' (306-31) match found"} | 192.168.1.111 | 00:00:00:00:00:00 | 0 | 2020-06-22T06:16:05Z | 802641 | 2020-06-22T06:16:05Z | Failed User Logon | The Login category indicates events related to logging in to hosts or services.  Belongs to Authentication: The authentication category indicates events relating to system access. | 25 | 44.44.44.44 | 00:00:00:00:00:00 | 0 | failure |


### esm-list-alarm-events
***
Gets a list of events related to the alarm.


#### Base Command

`esm-list-alarm-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmId | The alarm for which to get the details. Run the esm-fetch-alarms command to get the ID. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.AlarmEvent.ID | string | Event ID. |
| McAfeeESM.AlarmEvent.SubType | string | Event type. |
| McAfeeESM.AlarmEvent.Severity | number | Event severity. |
| McAfeeESM.AlarmEvent.Message | string | Event message. |
| McAfeeESM.AlarmEvent.LastTime | date | Event time. |
| McAfeeESM.AlarmEvent.SrcIP | string | Source IP of the event. |
| McAfeeESM.AlarmEvent.DstIP | string | Destination IP of the event. |
| McAfeeESM.AlarmEvent.Cases | Unknown | A list of cases related to the event. |
| McAfeeESM.AlarmEvent.Cases.ID | string | Case ID. |
| McAfeeESM.AlarmEvent.Cases.OpenTime | date | Case creation time. |
| McAfeeESM.AlarmEvent.Cases.Severity | number | Case severity. |
| McAfeeESM.AlarmEvent.Cases.Status | string | Case status. |
| McAfeeESM.AlarmEvent.Cases.Summary | string | Case summary. |


#### Command Example
```!esm-list-alarm-events alarmId=42687```

#### Context Example
```
{
    "McAfeeESM": {
        "AlarmEvent": {
            "DstIP": "192.168.1.111",
            "DstMac": null,
            "DstPort": null,
            "FirstTime": null,
            "ID": "144115188075855872|802641",
            "LastTime": "2020-06-22T06:16:05Z",
            "Message": "Failed User Logon",
            "NormalizedDescription": null,
            "Severity": 25,
            "SrcIP": "11.11.11.11",
            "SrcMac": null,
            "SrcPort": null,
            "SubType": "failure"
        }
    }
}
```

#### Human Readable Output

>### Alarm events
>|DstIP|DstMac|DstPort|FirstTime|ID|LastTime|Message|NormalizedDescription|Severity|SrcIP|SrcMac|SrcPort|SubType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 192.168.1.111 |  |  |  | 144115188075855872\|802641 | 2020-06-22T06:16:05Z | Failed User Logon |  | 25 | 11.11.11.11 |  |  | failure |

### esm-create-watchlist
***
Create a new watchlist.


#### Base Command

`esm-create-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The new watchlist name. | Required |
| type | The type of the new watchlist. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.name | string | The watchlist name |
| McAfeeESM.Watchlist.id | number | The watchlist id |
| McAfeeESM.Watchlist.type | string | The watchlist type |

#### Command Example
```!esm-create-watchlist name=test_watchlist type=IPAddress```

#### Context Example
```
{
	"McAfeeESM": {
		"Watchlist": {
			"id": 54,
			"name": "test_watchlist",
			"type": "IPAddress"
		}
	}
}
```

#### Human Readable Output

>Watchlist test_watchlist created.

### esm-delete-watchlist
***
Delete a watchlist.


#### Base Command

`esm-delete-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | the watch list ids to delete. | Optional |
| names | the watch list names to delete. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example
```!esm-delete-watchlist names=test_watchlist```

#### Human Readable Output

>Watchlists removed

### esm-watchlist-add-entry
***
Create a new watchlist entry.


#### Base Command

`esm-watchlist-add-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional |
| watchlist_id | The watchlist id. | Optional |
| values | The values you want to add to watchlist. (CSV format) | Required |

#### Context Output

There is no context output for this command.

#### Command Example
```!esm-watchlist-add-entry watchlist_name=test_watchlist values=1.1.1.1,2.2.2.2```

#### Human Readable Output

>Watchlist successfully updated.

### esm-watchlist-delete-entry
***
Delete watchlist entry.


#### Base Command

`esm-watchlist-delete-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional |
| watchlist_id | The watchlist id. | Optional |
| values | The values you want to remove from watchlist.  (CSV format) | Required |

#### Context Output

There is no context output for this command.

#### Command Example
```!esm-watchlist-delete-entry watchlist_name=test_watchlist values=1.1.1.1,2.2.2.2```


#### Human Readable Output

>Watchlist successfully updated.

### esm-watchlist-list-entries
***
Get watchlist entries.


#### Base Command

`esm-watchlist-list-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional |
| watchlist_id | The watchlist id. | Optional |
| limit | max count of values. | Required |
| offset | values offset. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.data | Unknown | The watchlist data |
| McAfeeESM.Watchlist.name | string | The watchlist name |

#### Command Example
```!esm-watchlist-list-entries watchlist_name=test_watchlist```

#### Context Example
```
{
	"McAfeeESM": {
		"Watchlist": {
			"data": [
				"1.1.1.1",
				"2.2.2.2"
			],
            "name": "test_watchlist"
		}
	}
}
```

#### Human Readable Output

>### results from test_watchlist watchlist
>|data|
>|---|
>| 1.1.1.1,<br/>2.2.2.2,<br/> |


### esm-get-watchlists
***
Returns a list of watchlists' names and IDs.


#### Base Command

`esm-get-watchlists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hidden | Whether to include hidden watchlists. Can be true or false. Possible values are: true, false. Default is true. | Required | 
| dynamic | Whether to include dynamic watchlists. Can be true or false. Possible values are: true, false. Default is true. | Required | 
| write_only | Whether to include write only watchlists. Can be true or false. Possible values are: true, false. Default is false. | Required | 
| indexed_only | Whether to include indexed only watchlists. Can be true or false. Possible values are: true, false. Default is false. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.name | string | The name of the watchlist. | 
| McAfeeESM.Watchlist.id | number | The ID of the watchlist. | 
| McAfeeESM.Watchlist.type | string | The type of the watchlist. | 