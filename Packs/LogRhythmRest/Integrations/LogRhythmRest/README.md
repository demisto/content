LogRhythm security intelligence.
This integration was integrated and tested with version 7.4.6 of LogRhythmRest
## Configure LogRhythmRest in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Hostname, IP address, or server URL | True |
| API Token | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Search API cluster ID | False |
| Entity ID | False |
| Fetch incidents | False |
| Incidents Fetch Interval | False |
| Incident type | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lr-execute-query
***
Executes a query for logs that match the query parameters.


#### Base Command

`lr-execute-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | The value by which to filter log messages. | Required | 
| page-size | Number of logs to return. Default is 100. | Optional | 
| time-frame | The time range from which to return log messages. If time_frame is "Custom", specify the start and end time for the time range. Possible values: "Today", "Last2Days", "LastWeek", "LastMonth", and "Custom". Possible values are: Today, Last2Days, LastWeek, LastMonth, Custom. Default is Custom. | Optional | 
| start-date | Start date for the data query, for example: "2018-04-20". Only use this argument if the time-frame argument is "Custom". | Optional | 
| end-date | End date for the data query, for example: "2018-04-20". Only use this argument if the time-frame argument is "Custom". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Log.Channel | string | Channel of the log. | 
| Logrhythm.Log.Computer | string | Computer for the log | 
| Logrhythm.Log.EventData | string | Event data of the log. | 
| Logrhythm.Log.EventID | string | Event ID of the log. | 
| Logrhythm.Log.Keywords | string | Keywords of the log. | 
| Logrhythm.Log.Level | string | Log level. | 
| Logrhythm.Log.Opcode | string | Opcode of the log. | 
| Logrhythm.Log.Task | string | Task of the log. | 


#### Command Example
```!lr-execute-query keyword=Failure time-frame=Custom start-date=2019-05-15 end-date=2019-05-16 page-size=2```


#### Context Example
```json
{
    "Logrhythm.Log": [
        {
            "EventID": "4625", 
            "Task": "Logon", 
            "Level": "Information", 
            "Computer": "WIN-1234.lab", 
            "Opcode": "Info", 
            "Keywords": "Audit Failure", 
            "EventData": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tGPWARD\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", 
            "Channel": "Security"
        }, 
        {
            "EventID": "4625", 
            "Task": "Logon", 
            "Level": "Information", 
            "Computer": "WIN-1234.lab", 
            "Opcode": "Info", 
            "Keywords": "Audit Failure", 
            "EventData": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tTMARTIN\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", 
            "Channel": "Security"
        }
    ]
}
```

#### Human Readable Output

>### Hosts for primary
>|Level|Computer|Channel|Keywords|EventData|
>|---|---|---|---|---|
>| Information | WIN-1234.lab | Security | Audit Failure | An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tGPWARD\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested. |
>| Information | WIN-1234.lab | Security | Audit Failure | An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tTMARTIN\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested. |


### lr-get-hosts-by-entity
***
Retrieves a list of hosts for a given entity, or an empty list if none is found.


#### Base Command

`lr-get-hosts-by-entity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity-name | The entity name. | Required | 
| count | Number of hosts to return. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | String | The entity ID. | 
| Logrhythm.Host.EntityName | String | The entity name. | 
| Logrhythm.Host.OS | String | The host operating system. | 
| Logrhythm.Host.ThreatLevel | String | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | String | Whether to use the event log credentials. | 
| Logrhythm.Host.Name | String | The name of the host. | 
| Logrhythm.Host.DateUpdated | String | The last update date of the host. | 
| Logrhythm.Host.HostZone | String | The host zone. | 
| Logrhythm.Host.RiskLevel | String | The risk level. | 
| Logrhythm.Host.Location | String | The host location. | 
| Logrhythm.Host.Status | String | The host status. | 
| Logrhythm.Host.ID | String | The unique ID of the host object. | 
| Logrhythm.Host.OSType | String | The type of the host operating system. | 


#### Command Example
```!lr-get-hosts-by-entity entity-name=primary count=2```

#### Context Example
```json
{
    "Logrhythm": {
        "Host": [
            {
                "DateUpdated": "2019-04-24T09:58:32.003Z",
                "EntityId": 1,
                "EntityName": "Primary Site",
                "HostZone": "Internal",
                "ID": -1000002,
                "Location": "NA",
                "Name": "AI Engine Server",
                "OS": "Unknown",
                "OSType": "Other",
                "RiskLevel": "None",
                "Status": "Active",
                "ThreatLevel": "None",
                "UseEventlogCredentials": false
            },
            {
                "DateUpdated": "2021-05-18T15:06:54.62Z",
                "EntityId": 1,
                "EntityName": "Primary Site",
                "HostZone": "Internal",
                "ID": 1,
                "Location": "NA",
                "Name": "WIN-JSBOL5ERCQA",
                "OS": "Windows",
                "OSType": "Other",
                "RiskLevel": "Medium-Medium",
                "Status": "Active",
                "ThreatLevel": "None",
                "UseEventlogCredentials": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Hosts for primary
>|ID|Name|EntityId|EntityName|OS|Status|Location|RiskLevel|ThreatLevel|ThreatLevelComments|DateUpdated|HostZone|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| -1000002 | AI Engine Server | 1 | Primary Site | Unknown | Active | NA | None | None |  | 2019-04-24T09:58:32.003Z | Internal |
>| 1 | WIN-JSBOL5ERCQA | 1 | Primary Site | Windows | Active | NA | Medium-Medium | None |  | 2021-05-18T15:06:54.62Z | Internal |


### lr-add-host
***
Add a new host to an entity.


#### Base Command

`lr-add-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity-id | The entity ID. | Required | 
| entity-name | The entity name. | Required | 
| name | The LogRhythm host name. | Required | 
| short-description | A short description of the host. Default is None. | Optional | 
| long-description | A long description of the host. Default is None. | Optional | 
| risk-level | The host risk level. Possible values: "None", "Low-Low", "Low-Medium", "Low-High", "Medium-Low", "Medium-Medium", "Medium-High", "High-Low", "High-Medium", and "High-High". Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. Default is None. | Required | 
| threat-level | The host threat level. Possible values: "None", "Low-Low", "Low-Medium", "Low-High", "Medium-Low", "Medium-Medium", "Medium-High", "High-Low", "High-Medium", and "High-High". Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. Default is None. | Optional | 
| threat-level-comments | Comments for the host threat level. Default is None. | Optional | 
| host-status | The host status. Possible values: "New", "Retired", and "Active". Possible values are: New, Retired, Active. | Required | 
| host-zone | The host zone. Possible values: "Unknown", "Internal", "DMZ", and "External". Possible values are: Unknown, Internal, DMZ, External. | Required | 
| os | The host operating system. | Required | 
| use-eventlog-credentials | Whether to use the event log credentials. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| os-type | The host operating system type. Possible values are: Unknown, Other, WindowsNT4, Windows2000Professional, Windows2000Server, Windows2003Standard, Windows2003Enterprise, Windows95, WindowsXP, WindowsVista, Linux, Solaris, AIX, HPUX, Windows. Default is Unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | string | The entity ID for the host. | 
| Logrhythm.Host.EntityName | string | The entity name for the host. | 
| Logrhythm.Host.OS | string | The host operating system. | 
| Logrhythm.Host.ThreatLevel | string | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | string | Whether to use the event log credentials. | 
| Logrhythm.Host.Name | string | The name of the host. | 
| Logrhythm.Host.DateUpdated | string | The last update date of the host. | 
| Logrhythm.Host.HostZone | string | The host zone. | 
| Logrhythm.Host.RiskLevel | string | The risk level of the host. | 
| Logrhythm.Host.Location | string | The host location. | 
| Logrhythm.Host.Status | string | The host status. | 
| Logrhythm.Host.ID | string | The unique ID of the host object. | 
| Logrhythm.Host.OSType | string | The type of the host operating system. | 


#### Command Example
```!lr-add-host entity-id=1 entity-name=`Primary Site` host-status=New host-zone=Internal name=host11 os=Windows risk-level="High-Medium" use-eventlog-credentials=false```

#### Context Example
```json
{
    "Logrhythm": {
        "Host": {
            "DateUpdated": "2021-06-22T05:22:09.74Z",
            "EntityId": 1,
            "EntityName": "Primary Site",
            "HostZone": "Internal",
            "ID": 51,
            "Location": "NA",
            "Name": "host11",
            "OS": "Windows",
            "OSType": "Unknown",
            "RiskLevel": "High-Medium",
            "Status": "New",
            "ThreatLevel": "None",
            "ThreatLevelComments": "None",
            "UseEventlogCredentials": true
        }
    }
}
```

#### Human Readable Output

>host11 added successfully to Primary Site

### lr-update-host-status
***
Updates an host status.


#### Base Command

`lr-update-host-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host-id | The unique ID of the host. | Required | 
| status | The enumeration status of the host. Possible values: "Retired" and "Active". Possible values are: Retired, Active. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | string | The entity ID of the host. | 
| Logrhythm.Host.EntityName | string | The entity name of the host. | 
| Logrhythm.Host.OS | string | The host operating system. | 
| Logrhythm.Host.ThreatLevel | string | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | string | Whether to use the event log credentials. | 
| Logrhythm.Host.Name | string | The name of the host. | 
| Logrhythm.Host.DateUpdated | string | The last update date of the host. | 
| Logrhythm.Host.HostZone | string | The host zone. | 
| Logrhythm.Host.RiskLevel | string | The risk level of the host. | 
| Logrhythm.Host.Location | string | The host location. | 
| Logrhythm.Host.Status | string | The host status. | 
| Logrhythm.Host.ID | string | The unique ID of the host object. | 
| Logrhythm.Host.OSType | string | The type of the host operating system. | 


#### Command Example
```!lr-update-host-status host-id=8 status=Retired```

#### Context Example
```json
{
    "Logrhythm": {
        "Host": {
            "DateUpdated": "2021-06-22T05:22:11.163Z",
            "EntityId": 1,
            "EntityName": "Primary Site",
            "HostZone": "Internal",
            "ID": 8,
            "Location": "NA",
            "Name": "test-host7",
            "OS": "Linux",
            "OSType": "Other",
            "RiskLevel": "Low-Medium",
            "Status": "Retired",
            "ThreatLevel": "Low-High",
            "UseEventlogCredentials": false
        }
    }
}
```

#### Human Readable Output

>Status updated to Retired

### lr-get-persons
***
Retrieves a list of LogRhythm persons.


#### Base Command

`lr-get-persons`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| person-id | The LogRhythm person ID. | Optional | 
| count | Number of persons to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Person.DateUpdated | String | Date that the person was updated. | 
| Logrhythm.Person.FirstName | String | First name of the LogRhythm person. | 
| Logrhythm.Person.LastName | String | Last name of the LogRhythm person. | 
| Logrhythm.Person.HostStatus | string | Host status of the LogRhythm person. | 
| Logrhythm.Person.ID | String | Logrhythm person ID. | 
| Logrhythm.Person.IsAPIPerson | Boolean | Whether the API is a person. | 
| Logrhythm.Person.UserID | String | User ID of the LogRhythm person. | 
| Logrhythm.Person.UserLogin | String | User login of the LogRhythm person. | 


#### Command Example
```!lr-get-persons person-id=7```

#### Context Example
```json
{
    "Logrhythm": {
        "Person": {
            "DateUpdated": "0001-01-01T00:00:00Z",
            "FirstName": "logrhythm",
            "HostStatus": "Retired",
            "ID": 7,
            "IsAPIPerson": false,
            "LastName": "logrhythm",
            "UserID": 5,
            "UserLogin": "lrapi2"
        }
    }
}
```

#### Human Readable Output

>### Persons information
>|ID|HostStatus|IsAPIPerson|FirstName|LastName|UserID|UserLogin|DateUpdated|
>|---|---|---|---|---|---|---|---|
>| 7 | Retired | false | logrhythm | logrhythm | 5 | lrapi2 | 0001-01-01T00:00:00Z |


### lr-get-networks
***
Retrieves a list of networks.


#### Base Command

`lr-get-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network-id | The LogRhythm network ID. | Optional | 
| count | Number of networks to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Network.BIP | String | Beginning IP address of the network. | 
| Logrhythm.Network.ThreatLevel | String | Threat level of the network. | 
| Logrhythm.Network.Name | String | Network name. | 
| Logrhythm.Network.EIP | String | End IP address of the network. | 
| Logrhythm.Network.DateUpdated | String | Date network was updated. | 
| Logrhythm.Network.EntityName | String | Entity name of the network. | 
| Logrhythm.Network.HostZone | String | Host zone of the network. | 
| Logrhythm.Network.RiskLevel | String | Risk level of the network. | 
| Logrhythm.Network.Location | String | Network location. | 
| Logrhythm.Network.HostStatus | String | Host status of the network. | 
| Logrhythm.Network.ID | String | Network ID. | 
| Logrhythm.Network.EntityId | String | Entity ID of the network. | 


#### Command Example
```!lr-get-networks network-id=1```

#### Context Example
```json
{
    "Logrhythm": {
        "Network": {
            "BeganIP": "1.1.1.1",
            "DateUpdated": "2019-02-20T10:57:13.983Z",
            "EndIP": "2.2.2.2",
            "EntityId": -100,
            "EntityName": "Global Entity",
            "HostStatus": "Active",
            "HostZone": "External",
            "ID": 1,
            "Location": "NA",
            "Name": "test",
            "RiskLevel": "None",
            "ThreatLevel": "None"
        }
    }
}
```

#### Human Readable Output

>### Networks information
>|ID|BeganIP|EndIP|HostStatus|Name|RiskLevel|EntityId|EntityName|Location|ThreatLevel|DateUpdated|HostZone|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 1.1.1.1 | 2.2.2.2 | Active | test | None | -100 | Global Entity | NA | None | 2019-02-20T10:57:13.983Z | External |


### lr-get-hosts
***
Returns a list of hosts.


#### Base Command

`lr-get-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host-id | The LogRhythm host ID. | Optional | 
| count | Number of hosts to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | String | The entity ID. | 
| Logrhythm.Host.EntityName | String | The entity name. | 
| Logrhythm.Host.OS | String | The host operating system. | 
| Logrhythm.Host.ThreatLevel | String | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | String | Whether to use the event log credentials. | 
| Logrhythm.Host.Name | String | The name of the host. | 
| Logrhythm.Host.DateUpdated | String | Date that the host was last updated. | 
| Logrhythm.Host.HostZone | String | The host zone. | 
| Logrhythm.Host.RiskLevel | String | The risk level of the host. | 
| Logrhythm.Host.Location | String | The host location. | 
| Logrhythm.Host.Status | String | The host status. | 
| Logrhythm.Host.ID | String | The unique ID of the host object. | 
| Logrhythm.Host.OSType | String | Host operating system type. | 


#### Command Example
```!lr-get-hosts host-id=1```

#### Context Example
```json
{
    "Logrhythm": {
        "Host": {
            "DateUpdated": "2021-05-18T15:06:54.62Z",
            "EntityId": 1,
            "EntityName": "Primary Site",
            "HostZone": "Internal",
            "ID": 1,
            "Location": "NA",
            "Name": "WIN-JSBOL5ERCQA",
            "OS": "Windows",
            "OSType": "Other",
            "RiskLevel": "Medium-Medium",
            "Status": "Active",
            "ThreatLevel": "None",
            "UseEventlogCredentials": false
        }
    }
}
```

#### Human Readable Output

>### Hosts information:
>|ID|Name|EntityId|EntityName|OS|Status|Location|RiskLevel|ThreatLevel|ThreatLevelComments|DateUpdated|HostZone|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | WIN-JSBOL5ERCQA | 1 | Primary Site | Windows | Active | NA | Medium-Medium | None |  | 2021-05-18T15:06:54.62Z | Internal |


### lr-get-alarm-data
***
Returns data for an alarm.


#### Base Command

`lr-get-alarm-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm-id | The alarm ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Alarm.Status | String | The alarm status. | 
| Logrhythm.Alarm.EventID | String | The alarm event ID. | 
| Logrhythm.Alarm.LastDxTimeStamp | String | The timestamp when the drilldown returned new results from the Data Indexer. | 
| Logrhythm.Alarm.DateInserted | String | The alarm date inserted. | 
| Logrhythm.Alarm.AIERuleName | String | The alarm AI engine \(AIE\) rule. | 
| Logrhythm.Alarm.Priority | String | The alarm priority. | 
| Logrhythm.Alarm.AIERuleID | String | The alarm AI engine \(AIE\) rule ID. | 
| Logrhythm.Alarm.ID | String | The alarm ID. | 
| Logrhythm.Alarm.NotificationSent | Boolean | Whether an alarm notification was sent. | 
| Logrhythm.Alarm.AlarmGuid | String | The alarm GUID. | 
| Logrhythm.Alarm.RetryCount | String | The alarm retry count. | 
| Logrhythm.Alarm.NormalMessageDate | String | The alarm message date. | 
| Logrhythm.Alarm.WebConsoleIds | String | The alarm web console IDs. | 
| Logrhythm.Alarm.Summary.PIFType | String | Alarm Primary Inspection Field \(the original name for "Summary Field"\). | 
| Logrhythm.Alarm.Summary.DrillDownSummaryLogs | String | Drilldown summary logs. | 


#### Command Example
```!lr-get-alarm-data alarm-id=1824```

#### Context Example
```json
{
    "Logrhythm": {
        "Alarm": {
            "AIEMsgXml": {
                "_": {
                    "AIERuleID": "1000000003",
                    "DateEdited": "2019-06-20 11:54:42"
                },
                "_0": {
                    "FactCount": "1",
                    "Login": "administrator",
                    "NormalMsgDate": "2019-06-20 12:13:19",
                    "NormalMsgDateLower": "2019-06-20 12:13:19",
                    "NormalMsgDateUpper": "2019-06-20 12:13:20",
                    "RuleBlockType": "1"
                },
                "v": "1"
            },
            "AIERuleID": 1000000003,
            "AIERuleName": "Use Of Admin User",
            "AlarmGuid": "5a4d8d77-5ec6-4669-b455-fb0cdbeed7df",
            "DateInserted": "2019-06-20T12:13:28.363",
            "EventID": 337555,
            "ID": 1824,
            "LastDxTimeStamp": "0001-01-01T00:00:00",
            "NormalMessageDate": "2019-06-20T12:13:20.243",
            "NotificationSent": false,
            "Priority": 85,
            "RetryCount": 0,
            "Status": "Completed",
            "Summary": [
                {
                    "DrillDownSummaryLogs": "administrator",
                    "PIFType": "User (Origin)"
                }
            ],
            "WebConsoleIds": [
                "c272b5f5-1db6-461b-9e9c-78d171429494"
            ]
        }
    }
}
```

#### Human Readable Output

>### Alarm information for alarm id 1824
>|AIERuleID|AIERuleName|AlarmGuid|DateInserted|EventID|ID|LastDxTimeStamp|NormalMessageDate|NotificationSent|Priority|RetryCount|Status|WebConsoleIds|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1000000003 | Use Of Admin User | 5a4d8d77-5ec6-4669-b455-fb0cdbeed7df | 2019-06-20T12:13:28.363 | 337555 | 1824 | 0001-01-01T00:00:00 | 2019-06-20T12:13:20.243 | false | 85 | 0 | Completed | c272b5f5-1db6-461b-9e9c-78d171429494 |
>### Alarm summaries
>|PIFType|DrillDownSummaryLogs|
>|---|---|
>| User (Origin) | administrator |


### lr-get-alarm-events
***
Returns a list of events, by alarm ID.


#### Base Command

`lr-get-alarm-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm-id | The alarm ID. | Required | 
| count | Number of events to return. Default is 10. | Optional | 
| fields | A comma-separated list of fields (outputs) to return to the context. If empty, all fields are returned. Possible values are: . | Optional | 
| get-log-message | Whether to return the log message from the event. Possible values: "True" and "False". Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Alarm.Event | String | Alarm event information. | 
| Logrhythm.Alarm.ID | String | The alarm ID. | 


#### Command Example
```!lr-get-alarm-events alarm-id=1835```

#### Context Example
```json
{
    "Logrhythm": {
        "Alarm": {
            "Event": [
                {
                    "classificationId": 1040,
                    "classificationName": "Authentication Failure",
                    "classificationTypeName": "Audit",
                    "command": "3",
                    "commonEventId": 19812,
                    "commonEventName": "User Logon Failure : Bad Password",
                    "count": 1,
                    "direction": 0,
                    "directionName": "Unknown",
                    "entityId": 1,
                    "entityName": "Primary Site",
                    "impactedEntityId": 1,
                    "impactedEntityName": "Primary Site",
                    "impactedHost": "win-jsbol5ercqa.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.lab",
                    "impactedZoneName": "Unknown",
                    "keyField": "messageId",
                    "logDate": "2019-06-20 05:27:03",
                    "logSourceHost": "WIN-JSBOL5ERCQA",
                    "logSourceHostId": 1,
                    "logSourceHostName": "WIN-JSBOL5ERCQA",
                    "logSourceId": 1,
                    "logSourceName": "WIN-JSBOL5ERCQA MS Security Log",
                    "logSourceType": 1000030,
                    "logSourceTypeName": "MS Windows Event Logging - Security",
                    "login": "administrator",
                    "messageId": "1e28712d-4af4-4e82-9403-a2ebfda82f2d",
                    "messageTypeEnum": 1,
                    "mpeRuleId": 1060400,
                    "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password",
                    "normalDate": "2019-06-20 12:27:03",
                    "normalDateMin": "2019-06-20 12:27:03",
                    "normalMsgDateMax": "2019-06-20 12:27:03",
                    "object": "NtLmSsp",
                    "objectName": "0xC000006A",
                    "originEntityId": 1,
                    "originEntityName": "Primary Site",
                    "originHostId": -1,
                    "originZone": 0,
                    "originZoneName": "Unknown",
                    "parentProcessId": "0x0",
                    "priority": 3,
                    "protocolId": -1,
                    "reason": "Unknown user name or bad password",
                    "rootEntityId": 1,
                    "rootEntityName": "Primary Site",
                    "ruleBlockNumber": 1,
                    "sequenceNumber": 211157,
                    "session": "0x0",
                    "severity": "Information",
                    "status": "0xC000006D",
                    "subject": "Unknown user name or bad password",
                    "vendorInfo": "An account failed to log on",
                    "vendorMessageId": "4625"
                },
                {
                    "classificationId": 1040,
                    "classificationName": "Authentication Failure",
                    "classificationTypeName": "Audit",
                    "command": "3",
                    "commonEventId": 19812,
                    "commonEventName": "User Logon Failure : Bad Password",
                    "count": 1,
                    "direction": 0,
                    "directionName": "Unknown",
                    "entityId": 1,
                    "entityName": "Primary Site",
                    "impactedEntityId": 1,
                    "impactedEntityName": "Primary Site",
                    "impactedHost": "win-jsbol5ercqa.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.lab",
                    "impactedZoneName": "Unknown",
                    "keyField": "messageId",
                    "logDate": "2019-06-20 05:27:03",
                    "logSourceHost": "WIN-JSBOL5ERCQA",
                    "logSourceHostId": 1,
                    "logSourceHostName": "WIN-JSBOL5ERCQA",
                    "logSourceId": 1,
                    "logSourceName": "WIN-JSBOL5ERCQA MS Security Log",
                    "logSourceType": 1000030,
                    "logSourceTypeName": "MS Windows Event Logging - Security",
                    "login": "administrator",
                    "messageId": "ec975fad-44fd-42cd-be8e-1573742c6d7a",
                    "messageTypeEnum": 1,
                    "mpeRuleId": 1060400,
                    "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password",
                    "normalDate": "2019-06-20 12:27:03",
                    "normalDateMin": "2019-06-20 12:27:03",
                    "normalMsgDateMax": "2019-06-20 12:27:03",
                    "object": "NtLmSsp",
                    "objectName": "0xC000006A",
                    "originEntityId": 1,
                    "originEntityName": "Primary Site",
                    "originHostId": -1,
                    "originZone": 0,
                    "originZoneName": "Unknown",
                    "parentProcessId": "0x0",
                    "priority": 3,
                    "protocolId": -1,
                    "reason": "Unknown user name or bad password",
                    "rootEntityId": 1,
                    "rootEntityName": "Primary Site",
                    "ruleBlockNumber": 1,
                    "sequenceNumber": 211156,
                    "session": "0x0",
                    "severity": "Information",
                    "status": "0xC000006D",
                    "subject": "Unknown user name or bad password",
                    "vendorInfo": "An account failed to log on",
                    "vendorMessageId": "4625"
                },
                {
                    "classificationId": 1040,
                    "classificationName": "Authentication Failure",
                    "classificationTypeName": "Audit",
                    "command": "3",
                    "commonEventId": 19812,
                    "commonEventName": "User Logon Failure : Bad Password",
                    "count": 1,
                    "direction": 0,
                    "directionName": "Unknown",
                    "entityId": 1,
                    "entityName": "Primary Site",
                    "impactedEntityId": 1,
                    "impactedEntityName": "Primary Site",
                    "impactedHost": "win-jsbol5ercqa.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.lab",
                    "impactedZoneName": "Unknown",
                    "keyField": "messageId",
                    "logDate": "2019-06-20 05:27:03",
                    "logSourceHost": "WIN-JSBOL5ERCQA",
                    "logSourceHostId": 1,
                    "logSourceHostName": "WIN-JSBOL5ERCQA",
                    "logSourceId": 1,
                    "logSourceName": "WIN-JSBOL5ERCQA MS Security Log",
                    "logSourceType": 1000030,
                    "logSourceTypeName": "MS Windows Event Logging - Security",
                    "login": "administrator",
                    "messageId": "21318d09-2b01-4b88-8b18-efc48c597e1f",
                    "messageTypeEnum": 1,
                    "mpeRuleId": 1060400,
                    "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password",
                    "normalDate": "2019-06-20 12:27:03",
                    "normalDateMin": "2019-06-20 12:27:03",
                    "normalMsgDateMax": "2019-06-20 12:27:03",
                    "object": "NtLmSsp",
                    "objectName": "0xC000006A",
                    "originEntityId": 1,
                    "originEntityName": "Primary Site",
                    "originHostId": -1,
                    "originZone": 0,
                    "originZoneName": "Unknown",
                    "parentProcessId": "0x0",
                    "priority": 3,
                    "protocolId": -1,
                    "reason": "Unknown user name or bad password",
                    "rootEntityId": 1,
                    "rootEntityName": "Primary Site",
                    "ruleBlockNumber": 1,
                    "sequenceNumber": 211155,
                    "session": "0x0",
                    "severity": "Information",
                    "status": "0xC000006D",
                    "subject": "Unknown user name or bad password",
                    "vendorInfo": "An account failed to log on",
                    "vendorMessageId": "4625"
                },
                {
                    "classificationId": 1040,
                    "classificationName": "Authentication Failure",
                    "classificationTypeName": "Audit",
                    "command": "3",
                    "commonEventId": 19812,
                    "commonEventName": "User Logon Failure : Bad Password",
                    "count": 1,
                    "direction": 0,
                    "directionName": "Unknown",
                    "entityId": 1,
                    "entityName": "Primary Site",
                    "impactedEntityId": 1,
                    "impactedEntityName": "Primary Site",
                    "impactedHost": "win-jsbol5ercqa.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.lab",
                    "impactedZoneName": "Unknown",
                    "keyField": "messageId",
                    "logDate": "2019-06-20 05:27:03",
                    "logSourceHost": "WIN-JSBOL5ERCQA",
                    "logSourceHostId": 1,
                    "logSourceHostName": "WIN-JSBOL5ERCQA",
                    "logSourceId": 1,
                    "logSourceName": "WIN-JSBOL5ERCQA MS Security Log",
                    "logSourceType": 1000030,
                    "logSourceTypeName": "MS Windows Event Logging - Security",
                    "login": "administrator",
                    "messageId": "20384578-60c1-4828-bdea-68cdc202d719",
                    "messageTypeEnum": 1,
                    "mpeRuleId": 1060400,
                    "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password",
                    "normalDate": "2019-06-20 12:27:03",
                    "normalDateMin": "2019-06-20 12:27:03",
                    "normalMsgDateMax": "2019-06-20 12:27:03",
                    "object": "NtLmSsp",
                    "objectName": "0xC000006A",
                    "originEntityId": 1,
                    "originEntityName": "Primary Site",
                    "originHostId": -1,
                    "originZone": 0,
                    "originZoneName": "Unknown",
                    "parentProcessId": "0x0",
                    "priority": 3,
                    "protocolId": -1,
                    "reason": "Unknown user name or bad password",
                    "rootEntityId": 1,
                    "rootEntityName": "Primary Site",
                    "ruleBlockNumber": 1,
                    "sequenceNumber": 211154,
                    "session": "0x0",
                    "severity": "Information",
                    "status": "0xC000006D",
                    "subject": "Unknown user name or bad password",
                    "vendorInfo": "An account failed to log on",
                    "vendorMessageId": "4625"
                },
                {
                    "classificationId": 1040,
                    "classificationName": "Authentication Failure",
                    "classificationTypeName": "Audit",
                    "command": "3",
                    "commonEventId": 19812,
                    "commonEventName": "User Logon Failure : Bad Password",
                    "count": 1,
                    "direction": 0,
                    "directionName": "Unknown",
                    "entityId": 1,
                    "entityName": "Primary Site",
                    "impactedEntityId": 1,
                    "impactedEntityName": "Primary Site",
                    "impactedHost": "win-jsbol5ercqa.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.lab",
                    "impactedZoneName": "Unknown",
                    "keyField": "messageId",
                    "logDate": "2019-06-20 05:27:03",
                    "logSourceHost": "WIN-JSBOL5ERCQA",
                    "logSourceHostId": 1,
                    "logSourceHostName": "WIN-JSBOL5ERCQA",
                    "logSourceId": 1,
                    "logSourceName": "WIN-JSBOL5ERCQA MS Security Log",
                    "logSourceType": 1000030,
                    "logSourceTypeName": "MS Windows Event Logging - Security",
                    "login": "administrator",
                    "messageId": "dd2c2251-ede1-4559-916b-0422ea8c0f9e",
                    "messageTypeEnum": 1,
                    "mpeRuleId": 1060400,
                    "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password",
                    "normalDate": "2019-06-20 12:27:03",
                    "normalDateMin": "2019-06-20 12:27:03",
                    "normalMsgDateMax": "2019-06-20 12:27:03",
                    "object": "NtLmSsp",
                    "objectName": "0xC000006A",
                    "originEntityId": 1,
                    "originEntityName": "Primary Site",
                    "originHostId": -1,
                    "originZone": 0,
                    "originZoneName": "Unknown",
                    "parentProcessId": "0x0",
                    "priority": 3,
                    "protocolId": -1,
                    "reason": "Unknown user name or bad password",
                    "rootEntityId": 1,
                    "rootEntityName": "Primary Site",
                    "ruleBlockNumber": 1,
                    "sequenceNumber": 211153,
                    "session": "0x0",
                    "severity": "Information",
                    "status": "0xC000006D",
                    "subject": "Unknown user name or bad password",
                    "vendorInfo": "An account failed to log on",
                    "vendorMessageId": "4625"
                }
            ],
            "ID": 1835
        }
    }
}
```

#### Human Readable Output

>### Events information for alarm 1835
>|classificationId|classificationName|classificationTypeName|command|commonEventId|commonEventName|count|direction|directionName|entityId|entityName|impactedEntityId|impactedEntityName|impactedHost|impactedHostName|impactedName|impactedZoneName|keyField|logDate|logSourceHost|logSourceHostId|logSourceHostName|logSourceId|logSourceName|logSourceType|logSourceTypeName|login|messageId|messageTypeEnum|mpeRuleId|mpeRuleName|normalDate|normalDateMin|normalMsgDateMax|object|objectName|originEntityId|originEntityName|originHostId|originZone|originZoneName|parentProcessId|priority|protocolId|reason|rootEntityId|rootEntityName|ruleBlockNumber|sequenceNumber|session|severity|status|subject|vendorInfo|vendorMessageId|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.lab |  | win-jsbol5ercqa.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 1e28712d-4af4-4e82-9403-a2ebfda82f2d | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211157 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.lab |  | win-jsbol5ercqa.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | ec975fad-44fd-42cd-be8e-1573742c6d7a | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211156 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.lab |  | win-jsbol5ercqa.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 21318d09-2b01-4b88-8b18-efc48c597e1f | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211155 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.lab |  | win-jsbol5ercqa.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 20384578-60c1-4828-bdea-68cdc202d719 | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211154 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.lab |  | win-jsbol5ercqa.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | dd2c2251-ede1-4559-916b-0422ea8c0f9e | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211153 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |

### lr-get-case-evidence
***
Execute evidence query for a specific case ID.


#### Base Command

`lr-get-case-evidence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Search.Evidence.status | String | Evidence status. | 
| Logrhythm.Search.Evidence.text | String | Evidence text. | 
| Logrhythm.Search.Evidence.number | Number | Evidence ID. | 
| Logrhythm.Search.Evidence.dateCreated | Date | Date the evidence was created. | 
| Logrhythm.Search.Evidence.pinned | Boolean | Whether evidence is pinned. | 
| Logrhythm.Search.Evidence.lastUpdatedBy.name | String | The name of the person who last updated the evidence. | 
| Logrhythm.Search.Evidence.createdBy.name | String | The name of the person who created the evidence. | 
| Logrhythm.Search.Evidence.dateUpdated | Date | The date the evidence was last updated. | 
| Logrhythm.Search.Evidence.type | String | Evidence type. | 


#### Command Example
```!lr-get-case-evidence case_id=12345```

#### Context Example
```json
{
    "Logrhythm": {
        "Evidence": {
            "alarm": {
                "alarmDate": "2019-04-15T00:02:52.847Z",
                "alarmId": 190,
                "alarmRuleId": 1098,
                "alarmRuleName": "LogRhythm Data Indexer Max Index Exceeded",
                "dateInserted": "2019-04-15T00:02:52.86Z",
                "entityId": 1,
                "entityName": "Primary Site",
                "riskBasedPriorityMax": 37
            },
            "createdBy": {
                "disabled": false,
                "name": "LogRhythm Administrator",
                "number": -100
            },
            "dateCreated": "2019-04-15T21:41:34.61Z",
            "datePinned": null,
            "dateUpdated": "2019-04-15T21:41:34.61Z",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LogRhythm Administrator",
                "number": -100
            },
            "number": 3,
            "pinned": false,
            "status": "completed",
            "statusMessage": null,
            "text": "",
            "type": "alarm"
        }
    }
}
```

#### Human Readable Output

>### Evidences for case FD05A0D9-6749-45F7-BB5D-596FBA68E731
>|Alarm|Createdby|Datecreated|Datepinned|Dateupdated|Lastupdatedby|Number|Pinned|Status|Statusmessage|Text|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| alarmDate: 2019-04-15T00:02:52.847Z<br/>dateInserted: 2019-04-15T00:02:52.86Z<br/>alarmRuleId: 1098<br/>entityName: Primary Site<br/>alarmId: 190<br/>riskBasedPriorityMax: 37<br/>entityId: 1<br/>alarmRuleName: LogRhythm Data Indexer Max Index Exceeded | disabled: false<br/>number: -100<br/>name: LogRhythm Administrator | 2019-04-15T21:41:34.61Z |  | 2019-04-15T21:41:34.61Z | disabled: false<br/>number: -100<br/>name: LogRhythm Administrator | 3 | false | completed |  |  | alarm |

### lr-execute-search-query
***
Execute search query to LogRhythm log database.


#### Base Command

`lr-execute-search-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| number_of_days | Number of days to search. | Required | 
| source_type | Log source type. Possible values are: API_-_AWS_CloudTrail, API_-_AWS_CloudWatch_Alarm, API_-_AWS_Config_Event, API_-_AWS_S3_Flat_File, API_-_AWS_S3_Server_Access_Event, API_-_BeyondTrust_Retina_Vulnerability_Management, API_-_Box_Event, API_-_Cisco_IDS/IPS, API_-_Cradlepoint_ECM, API_-_IP360_Vulnerability_Scanner, API_-_Metasploit_Penetration_Scanner, API_-_Nessus_Vulnerability_Scanner, API_-_NetApp_CIFS_Security_Audit_Event_Log, API_-_NeXpose_Vulnerability_Scanner, API_-_Office_365_Management_Activity, API_-_Office_365_Message_Tracking, API_-_Okta_Event, API_-_Qualys_Vulnerability_Scanner, API_-_Salesforce_EventLogFile, API_-_Sourcefire_eStreamer, API_-_Tenable_SecurityCenter, API_-_Tenable.io_Scanner, Flat_File_-_ActivIdentity_CMS, Flat_File_-_Airwatch_MDM, Flat_File_-_Alfresco, Flat_File_-_AllScripts, Flat_File_-_Apache_Access_Log, Flat_File_-_Apache_Error_Log, Flat_File_-_Apache_SSL_Access_Log, Flat_File_-_Apache_SSL_Error_Log, Flat_File_-_Apache_Tomcat_Access_Log, Flat_File_-_Apache_Tomcat_Console_Log, Flat_File_-_Avaya_Secure_Access_Link_Remote_Access_Log, Flat_File_-_Avaya_Voice_Mail_Log, Flat_File_-_Axway_SFTP, Flat_File_-_Beacon_Endpoint_Profiler, Flat_File_-_Bind_9, Flat_File_-_BlackBerry_Enterprise_Server, Flat_File_-_Blue_Coat_Proxy_BCREPORTERMAIN_Format, Flat_File_-_Blue_Coat_Proxy_CSV_Format, Flat_File_-_Blue_Coat_Proxy_SQUID-1_Format, Flat_File_-_Blue_Coat_Proxy_W3C_Format, Flat_File_-_Bro_IDS_Critical_Stack_Intel_Log, Flat_File_-_Broadcom_SiteMinder, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTDS, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTEL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTJL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTLL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTNV, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTOM, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTPW, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRV, Flat_File_-_CA_ControlMinder, Flat_File_-_Cerberus_FTP_Server, Flat_File_-_Cerner, Flat_File_-_Cisco_AMP_for_Endpoints, Flat_File_-_Cisco_Email_Security_Appliance, Flat_File_-_Cisco_LMS_(cwcli), Flat_File_-_Cisco_LMS_(Syslog), Flat_File_-_Cisco_NGFW, Flat_File_-_Cisco_Secure_ACS_CSV_File, Flat_File_-_Cisco_Security_Agent, Flat_File_-_Cisco_Umbrella_DNS, Flat_File_-_Cisco_Web_Security_aclog, Flat_File_-_Citrix_Access_Gateway_IIS_Format, Flat_File_-_Citrix_Access_Gateway_NCSA_Common_Format, Flat_File_-_Citrix_Access_Gateway_W3C_Format, Flat_File_-_Citrix_Presentation_Server, Flat_File_-_Citrix_Secure_Gateway, Flat_File_-_ClamAV_Anti-Virus, Flat_File_-_ColdFusion_Application_Log, Flat_File_-_ColdFusion_Exception_Log, Flat_File_-_ColdFusion_Mail_Log, Flat_File_-_ColdFusion_Mailsent_Log, Flat_File_-_ColdFusion_Server_Log, Flat_File_-_Cornerstone_Managed_File_Transfer, Flat_File_-_Coyote_Point_Equalizer, Flat_File_-_DB2_Audit_Log, Flat_File_-_DB2_via_BMC_Log_Master, Flat_File_-_Defender_Server, Flat_File_-_DocWorks, Flat_File_-_eClinicalWorks_Audit_Log, Flat_File_-_EMC_Isilon, Flat_File_-_Epicor_Coalition, Flat_File_-_FairWarning_Ready-For-Healthcare, Flat_File_-_FileZilla_System_Log, Flat_File_-_FireEye_Web_MPS, Flat_File_-_Forcepoint_Web_Security_CEF_Cloud_Format, Flat_File_-_Forescout_CounterACT, Flat_File_-_FoxT_BoKS_Server_Access_Control, Flat_File_-_FundsXpress, Flat_File_-_Gene6_FTP, Flat_File_-_GlobalSCAPE_EFT, Flat_File_-_Hadoop, Flat_File_-_HMC, Flat_File_-_HP-UX_Audit_Log, Flat_File_-_IBM_4690_POS, Flat_File_-_IBM_Informix_Application_Log, Flat_File_-_IBM_Informix_Audit_Log, Flat_File_-_IBM_Tivoli_Storage_Manager, Flat_File_-_IBM_WebSphere_App_Server_v7_Audit_Log, Flat_File_-_IBM_WebSphere_Cast_Iron_Cloud_Integration, Flat_File_-_IBM_ZOS_Batch_Decryption_Log, Flat_File_-_IBM_ZOS_CICS_Decryption_Log, Flat_File_-_IBM_ZOS_RACF_Access_Log, Flat_File_-_IBM_ZOS_RACF_SMF_Type_80, Flat_File_-_IPSwitch_WS_FTP, Flat_File_-_Irix_Audit_Logs, Flat_File_-_IT-CUBE_AgileSI, Flat_File_-_JBoss_Log_File, Flat_File_-_Juniper_Steel_Belted_Radius_Server, Flat_File_-_Kerio_Mail_Server, Flat_File_-_KERISYS_Doors_Event_Export_Format, Flat_File_-_Kippo_Honeypot, Flat_File_-_Linux_Audit_ASCII, Flat_File_-_Linux_Audit_Log, Flat_File_-_Linux_Host_Secure_Log, Flat_File_-_LOGbinder_EX, Flat_File_-_LogRhythm_Alarm_Reingest, Flat_File_-_LogRhythm_Data_Indexer_Monitor, Flat_File_-_LogRhythm_Oracle_Log, Flat_File_-_LogRhythm_System_Monitor, Flat_File_-_LogRhythm_System_Monitor_Log_File, Flat_File_-_LogRhythm_Trebek_Log, Flat_File_-_LogRhythm_Zeus_Log, Flat_File_-_Lotus_Domino_Client_Log, Flat_File_-_McAfee_Cloud_Proxy_do_not_use, Flat_File_-_McAfee_ePO_HIPS, Flat_File_-_McAfee_Foundstone, Flat_File_-_McAfee_Proxy_Cloud, Flat_File_-_McAfee_SaaS_Web_Protection, Flat_File_-_McAfee_Web_Gateway_Audit_Log, Flat_File_-_Merak, Flat_File_-_Meridian, Flat_File_-_Microsoft_ActiveSync_2010, Flat_File_-_Microsoft_CRM, Flat_File_-_Microsoft_DHCP_Server_Log, Flat_File_-_Microsoft_Forefront_TMG, Flat_File_-_Microsoft_Forefront_TMG_Web_Proxy, Flat_File_-_Microsoft_IIS_(IIS_Format)_File, Flat_File_-_Microsoft_IIS_7.x_W3C_Extended_Format, Flat_File_-_Microsoft_IIS_Error_Log_V6, Flat_File_-_Microsoft_IIS_FTP_IIS_Log_File_Format, Flat_File_-_Microsoft_IIS_FTP_W3C_Extended_Format, Flat_File_-_Microsoft_IIS_NCSA_Common_Format_File, Flat_File_-_Microsoft_IIS_SMTP_W3C_Format, Flat_File_-_Microsoft_IIS_URL_Scan_Log, Flat_File_-_Microsoft_IIS_W3C_File, Flat_File_-_Microsoft_ISA_Server_2004, Flat_File_-_Microsoft_ISA_Server_W3C_File, Flat_File_-_Microsoft_Netlogon, Flat_File_-_Microsoft_Port_Reporter_PR-PORTS_Log, Flat_File_-_Microsoft_Semantic_Logging, Flat_File_-_Microsoft_SQL_Server_2000_Error_Log, Flat_File_-_Microsoft_SQL_Server_2005_Error_Log, Flat_File_-_Microsoft_SQL_Server_2008_Error_Log, Flat_File_-_Microsoft_SQL_Server_2012_Error_Log, Flat_File_-_Microsoft_SQL_Server_2014_Error_Log, Flat_File_-_Microsoft_Windows_2003_DNS, Flat_File_-_Microsoft_Windows_2008_DNS, Flat_File_-_Microsoft_Windows_2012_DNS, Flat_File_-_Microsoft_Windows_Firewall, Flat_File_-_MicroStrategy, Flat_File_-_Mimecast_Audit, Flat_File_-_Mimecast_Email, Flat_File_-_Monetra, Flat_File_-_MongoDB, Flat_File_-_MS_Exchange_2003_Message_Tracking_Log, Flat_File_-_MS_Exchange_2007_Message_Tracking_Log, Flat_File_-_MS_Exchange_2010_Message_Tracking_Log, Flat_File_-_MS_Exchange_2013_Message_Tracking_Log, Flat_File_-_MS_Exchange_2016_Message_Tracking_Log, Flat_File_-_MS_Exchange_RPC_Client_Access, Flat_File_-_MS_IAS/RAS_Server_NPS_DB_Log_Format, Flat_File_-_MS_IAS/RAS_Server_Standard_Log_Format, Flat_File_-_MS_ISA_Server_2006_ISA_All_Fields, Flat_File_-_MS_ISA_Server_2006_W3C_All_Fields, Flat_File_-_MS_SQL_Server_Reporting_Services_2008, Flat_File_-_MySQL, Flat_File_-_MySQL_error.log, Flat_File_-_MySQL_mysql.log, Flat_File_-_MySQL_mysql-slow.log, Flat_File_-_Nessus_System_Log, Flat_File_-_NetApp_Cluster, Flat_File_-_Nginx_Log, Flat_File_-_Novell_Audit, Flat_File_-_Novell_GroupWise, Flat_File_-_Novell_LDAP, Flat_File_-_ObserveIT_Enterprise, Flat_File_-_Office_365_Message_Tracking, Flat_File_-_OpenDJ, Flat_File_-_OpenVMS, Flat_File_-_OpenVPN, Flat_File_-_Oracle_11g_Fine_Grained_Audit_Trail, Flat_File_-_Oracle_9i, Flat_File_-_Oracle_BRM_CM_Log, Flat_File_-_Oracle_BRM_DM_Log, Flat_File_-_Oracle_Listener_Audit_Trail, Flat_File_-_Oracle_SunOne_Directory_Server, Flat_File_-_Oracle_SunOne_Web_Server_Access_Log, Flat_File_-_Oracle_Virtual_Directory, Flat_File_-_Oracle_WebLogic_11g_Access_Log, Flat_File_-_Other, Flat_File_-_PeopleSoft, Flat_File_-_PhpMyAdmin_Honeypot, Flat_File_-_Postfix, Flat_File_-_PowerBroker_Servers, Flat_File_-_Princeton_Card_Secure, Flat_File_-_ProFTPD, Flat_File_-_PureMessage_For_Exchange_SMTP_Log, Flat_File_-_PureMessage_For_UNIX_Blocklist_Log, Flat_File_-_PureMessage_For_UNIX_Message_Log, Flat_File_-_RACF_(SMF), Flat_File_-_Radmin, Flat_File_-_Restic_Backup_Log, Flat_File_-_RL_Patient_Feedback, Flat_File_-_RSA_Adaptive_Authentication, Flat_File_-_RSA_Authentication_Manager_6.1, Flat_File_-_S2_Badge_Reader, Flat_File_-_Safenet, Flat_File_-_Sendmail_File, Flat_File_-_Sharepoint_ULS, Flat_File_-_ShoreTel_VOIP, Flat_File_-_Siemens_Radiology_Information_System, Flat_File_-_Snort_Fast_Alert_File, Flat_File_-_Solaris_-_Sulog, Flat_File_-_Solaris_Audit_Log, Flat_File_-_SpamAssassin, Flat_File_-_Squid_Proxy, Flat_File_-_Subversion, Flat_File_-_Sudo.Log, Flat_File_-_Swift_Alliance, Flat_File_-_Symantec_Antivirus_10.x_Corporate_Edtn, Flat_File_-_Symantec_Antivirus_12.x_Corporate_Edtn, Flat_File_-_Symitar_Episys_Console_Log, Flat_File_-_Symitar_Episys_Sysevent_Log, Flat_File_-_Tandem_EMSOUT_Log_File, Flat_File_-_Tandem_XYGATE, Flat_File_-_Tectia_SSH_Server, Flat_File_-_Trade_Innovations_CSCS, Flat_File_-_Trend_Micro_IMSS, Flat_File_-_Trend_Micro_Office_Scan, Flat_File_-_Tumbleweed_Mailgate_Server, Flat_File_-_Verint_Audit_Trail_File, Flat_File_-_VMWare_Virtual_Machine, Flat_File_-_Voltage_Securemail, Flat_File_-_Vormetric_Log_File, Flat_File_-_vsFTP_Daemon_Log, Flat_File_-_Vyatta_Firewall_Kernel_Log, Flat_File_-_WordPot_Honeypot, Flat_File_-_X-NetStat_Log, Flat_File_-_XPient_POS_CCA_Manager, Flat_File_-_XPIENT_POS_POSLOG, Flat_File_-_XPIENT_POS_Shell_Log, IPFIX_-_IP_Flow_Information_Export, J-Flow_-_Juniper_J-Flow_Version_5, J-Flow_-_Juniper_J-Flow_Version_9, LogRhythm_CloudAI, LogRhythm_Data_Loss_Defender, LogRhythm_Demo_File_-_Application_Server_Log, LogRhythm_Demo_File_-_Content_Inspection_Log, LogRhythm_Demo_File_-_Database_Audit_Log, LogRhythm_Demo_File_-_Ecom_Server_Log, LogRhythm_Demo_File_-_File_Server_Log, LogRhythm_Demo_File_-_Firewall_Log, LogRhythm_Demo_File_-_FTP_Log, LogRhythm_Demo_File_-_IDS_Alarms_Log, LogRhythm_Demo_File_-_Mail_Server_Log, LogRhythm_Demo_File_-_Netflow_Log, LogRhythm_Demo_File_-_Network_Device_Log, LogRhythm_Demo_File_-_Network_Server_Log, LogRhythm_Demo_File_-_VPN_Log, LogRhythm_Demo_File_-_Web_Access_Log, LogRhythm_File_Monitor_(AIX), LogRhythm_File_Monitor_(HP-UX), LogRhythm_File_Monitor_(Linux), LogRhythm_File_Monitor_(Solaris), LogRhythm_File_Monitor_(Windows), LogRhythm_Filter, LogRhythm_Network_Connection_Monitor_(AIX), LogRhythm_Network_Connection_Monitor_(HP-UX), LogRhythm_Network_Connection_Monitor_(Linux), LogRhythm_Network_Connection_Monitor_(Solaris), LogRhythm_Network_Connection_Monitor_(Windows), LogRhythm_Process_Monitor_(AIX), LogRhythm_Process_Monitor_(HP-UX), LogRhythm_Process_Monitor_(Linux), LogRhythm_Process_Monitor_(Solaris), LogRhythm_Process_Monitor_(Windows), LogRhythm_Registry_Integrity_Monitor, LogRhythm_SQL_Server_2000_C2_Audit_Log, LogRhythm_SQL_Server_2005_C2_Audit_Log, LogRhythm_SQL_Server_2008_C2_Audit_Log, LogRhythm_SQL_Server_2012+_C2_Audit_Log, LogRhythm_User_Activity_Monitor_(AIX), LogRhythm_User_Activity_Monitor_(HP-UX), LogRhythm_User_Activity_Monitor_(Linux), LogRhythm_User_Activity_Monitor_(Solaris), LogRhythm_User_Activity_Monitor_(Windows), MS_Event_Log_for_XP/2000/2003_-_Application, MS_Event_Log_for_XP/2000/2003_-_Application_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_BioPassword, MS_Event_Log_for_XP/2000/2003_-_DFS, MS_Event_Log_for_XP/2000/2003_-_Directory_Service, MS_Event_Log_for_XP/2000/2003_-_DNS, MS_Event_Log_for_XP/2000/2003_-_DotDefender, MS_Event_Log_for_XP/2000/2003_-_EMC_Celerra_NAS, MS_Event_Log_for_XP/2000/2003_-_File_Rep_Service, MS_Event_Log_for_XP/2000/2003_-_HA, MS_Event_Log_for_XP/2000/2003_-_Kaspersky, MS_Event_Log_for_XP/2000/2003_-_Micros_POS, MS_Event_Log_for_XP/2000/2003_-_PatchLink, MS_Event_Log_for_XP/2000/2003_-_SafeWord_2008, MS_Event_Log_for_XP/2000/2003_-_SCE, MS_Event_Log_for_XP/2000/2003_-_Security, MS_Event_Log_for_XP/2000/2003_-_Security_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_SMS_2003, MS_Event_Log_for_XP/2000/2003_-_System, MS_Event_Log_for_XP/2000/2003_-_System_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_Virtual_Server, MS_Windows_Event_Logging_-_ADFS_Admin, MS_Windows_Event_Logging_-_Application, MS_Windows_Event_Logging_-_AppLockerApp, MS_Windows_Event_Logging_-_Backup, MS_Windows_Event_Logging_-_Citrix_Delivery_Services, MS_Windows_Event_Logging_-_Citrix_XenApp, MS_Windows_Event_Logging_-_DFS, MS_Windows_Event_Logging_-_DHCP_Admin, MS_Windows_Event_Logging_-_DHCP_Operational, MS_Windows_Event_Logging_-_Diagnosis-PLA, MS_Windows_Event_Logging_-_Digital_Persona, MS_Windows_Event_Logging_-_Dir_Service, MS_Windows_Event_Logging_-_DNS, MS_Windows_Event_Logging_-_Dot_Defender, MS_Windows_Event_Logging_-_ESD_Data_Flow_Track, MS_Windows_Event_Logging_-_Exchange_Mailbox_DB_Failures, MS_Windows_Event_Logging_-_FailoverClustering/Operational, MS_Windows_Event_Logging_-_Firewall_With_Advanced_Security, MS_Windows_Event_Logging_-_Forefront_AV, MS_Windows_Event_Logging_-_Group_Policy_Operational, MS_Windows_Event_Logging_-_Hyper-V_Hvisor, MS_Windows_Event_Logging_-_Hyper-V_IMS, MS_Windows_Event_Logging_-_Hyper-V_Network, MS_Windows_Event_Logging_-_Hyper-V_SynthSt, MS_Windows_Event_Logging_-_Hyper-V_VMMS, MS_Windows_Event_Logging_-_Hyper-V_Worker, MS_Windows_Event_Logging_-_Kaspersky, MS_Windows_Event_Logging_-_Kernel_PnP_Configuration, MS_Windows_Event_Logging_-_Lync_Server, MS_Windows_Event_Logging_-_MSExchange_Management, MS_Windows_Event_Logging_-_Operations_Manager, MS_Windows_Event_Logging_-_PowerShell, MS_Windows_Event_Logging_-_Print_Services, MS_Windows_Event_Logging_-_Quest_ActiveRoles_EDM_Server, MS_Windows_Event_Logging_-_Replication, MS_Windows_Event_Logging_-_SafeWord_2008, MS_Windows_Event_Logging_-_Security, MS_Windows_Event_Logging_-_Setup, MS_Windows_Event_Logging_-_Sysmon, MS_Windows_Event_Logging_-_System, MS_Windows_Event_Logging_-_Task_Scheduler, MS_Windows_Event_Logging_-_TS_Gateway, MS_Windows_Event_Logging_-_TS_Licensing, MS_Windows_Event_Logging_-_TS_Local_Session_Manager, MS_Windows_Event_Logging_-_TS_Remote_Connection_Manager, MS_Windows_Event_Logging_-_TS_Session_Broker, MS_Windows_Event_Logging_-_TS_Session_Broker_Client, MS_Windows_Event_Logging_-_VisualSVN, MS_Windows_Event_Logging_:_Deutsch_-_Security, MS_Windows_Event_Logging_:_Espaniol_-_Application, MS_Windows_Event_Logging_:_Espaniol_-_Security, MS_Windows_Event_Logging_:_Espaniol_-_System, MS_Windows_Event_Logging_:_Francais_-_System, MS_Windows_Event_Logging_:_Francais_-_Security, MS_Windows_Event_Logging_XML_-_ADFS, MS_Windows_Event_Logging_XML_-_Application, MS_Windows_Event_Logging_XML_-_Forwarded_Events, MS_Windows_Event_Logging_XML_-_Generic, MS_Windows_Event_Logging_XML_-_Microsoft-Windows-NTLM/Operational, MS_Windows_Event_Logging_XML_-_Security, MS_Windows_Event_Logging_XML_-_Sysmon, MS_Windows_Event_Logging_XML_-_Sysmon_7.01, MS_Windows_Event_Logging_XML_-_Sysmon_8/9/10, MS_Windows_Event_Logging_XML_-_System, MS_Windows_Event_Logging_XML_-_Unisys_Stealth, MS_Windows_Event_Logging_XML_-_Windows_Defender, Netflow_-_Cisco_Netflow_Version_1, Netflow_-_Cisco_Netflow_Version_5, Netflow_-_Cisco_Netflow_Version_9, Netflow_-_Palo_Alto_Version_9, Netflow_-_SonicWALL_Version_5, Netflow_-_SonicWALL_Version_9, OPSEC_LEA_-_Checkpoint_Firewall, OPSEC_LEA_-_Checkpoint_Firewall_Audit_Log, OPSEC_LEA_-_Checkpoint_For_LR_7.4.1+, OPSEC_LEA_-_Checkpoint_Log_Server, sFlow_-_Version_5, SNMP_Trap_-_Audiolog, SNMP_Trap_-_Autoregistered, SNMP_Trap_-_Brocade_Switch, SNMP_Trap_-_Cisco_5508_Wireless_Controller, SNMP_Trap_-_Cisco_IP_SLA, SNMP_Trap_-_Cisco_Prime, SNMP_Trap_-_Cisco_Router-Switch, SNMP_Trap_-_CyberArk, SNMP_Trap_-_Dell_OpenManage, SNMP_Trap_-_HP_Network_Node_Manager, SNMP_Trap_-_IBM_TS3000_Series_Tape_Drive, SNMP_Trap_-_Riverbed_SteelCentral_NetShark, SNMP_Trap_-_RSA_Authentication_Manager, SNMP_Trap_-_Swift_Alliance, SNMP_Trap_-_Trend_Micro_Control_Manager, Syslog_-_3Com_Switch, Syslog_-_A10_Networks_AX1000_Load_Balancer, Syslog_-_A10_Networks_Web_Application_Firewall, Syslog_-_Accellion_Secure_File_Transfer_Application, Syslog_-_Active_Scout_IPS, Syslog_-_Adallom, Syslog_-_Adtran_Switch, Syslog_-_Aerohive_Access_Point, Syslog_-_Aerohive_Firewall, Syslog_-_AIMIA_Tomcat, Syslog_-_AirDefense_Enterprise, Syslog_-_Airmagnet_Wireless_IDS, Syslog_-_AirTight_IDS/IPS, Syslog_-_AirWatch_MDM, Syslog_-_Airwave_Management_System_Log, Syslog_-_AIX_Host, Syslog_-_Alcatel-Lucent_Switch, Syslog_-_Alcatel-Lucent_Wireless_Controller, Syslog_-_AlertLogic, Syslog_-_AMX_AV_Controller, Syslog_-_Apache_Access_Log, Syslog_-_Apache_Error_Log, Syslog_-_Apache_Tomcat_Request_Parameters, Syslog_-_Apache_Tomcat_Service_Clients_Log, Syslog_-_APC_ATS, Syslog_-_APC_NetBotz_Environmental_Monitoring, Syslog_-_APC_PDU, Syslog_-_APC_UPS, Syslog_-_Apcon_Network_Monitor, Syslog_-_Apex_One, Syslog_-_Arbor_Networks_Peakflow, Syslog_-_Arbor_Networks_Spectrum, Syslog_-_Arbor_Pravail_APS, Syslog_-_Arista_Switch, Syslog_-_Array_TMX_Load_Balancer, Syslog_-_Arris_CMTS, Syslog_-_Aruba_Clear_Pass, Syslog_-_Aruba_Mobility_Controller, Syslog_-_Aruba_Wireless_Access_Point, Syslog_-_AS/400_via_Powertech_Interact, Syslog_-_Asus_WRT_Router, Syslog_-_Avatier_Identity_Management_Suite_(AIMS), Syslog_-_Avaya_Communications_Manager, Syslog_-_Avaya_Ethernet_Routing_Switch, Syslog_-_Avaya_G450_Media_Gateway, Syslog_-_Avaya_Router, Syslog_-_Aventail_SSL/VPN, Syslog_-_Avocent_Cyclades_Terminal_Server, Syslog_-_Azul_Java_Appliance, Syslog_-_Barracuda_Load_Balancer, Syslog_-_Barracuda_Mail_Archiver, Syslog_-_Barracuda_NG_Firewall, Syslog_-_Barracuda_NG_Firewall_6.x, Syslog_-_Barracuda_Spam_Firewall, Syslog_-_Barracuda_Web_Application_Firewall, Syslog_-_Barracuda_Webfilter, Syslog_-_BeyondTrust_BeyondInsight_LEEF, Syslog_-_Bind_DNS, Syslog_-_Bit9_Parity_Suite, Syslog_-_Bit9_Security_Platform_CEF, Syslog_-_Bit9+Carbon_Black_(Deprecated), Syslog_-_BitDefender, Syslog_-_Black_Diamond_Switch, Syslog_-_Blue_Coat_CAS, Syslog_-_Blue_Coat_Forward_Proxy, Syslog_-_Blue_Coat_PacketShaper, Syslog_-_Blue_Coat_ProxyAV_ISA_W3C_Format, Syslog_-_Blue_Coat_ProxyAV_MS_Proxy_2.0_Format, Syslog_-_Blue_Coat_ProxySG, Syslog_-_Blue_Socket_Wireless_Controller, Syslog_-_Bluecat_Adonis, Syslog_-_BlueCedar, Syslog_-_BluVector, Syslog_-_Bomgar, Syslog_-_Bradford_Networks_NAC, Syslog_-_Bradford_Remediation_&amp;_Registration_Svr, Syslog_-_Bro_IDS, Syslog_-_Brocade_Switch, Syslog_-_Bromium_vSentry_CEF, Syslog_-_BSD_Host, Syslog_-_CA_Privileged_Access_Manager, Syslog_-_Cb_Defense_CEF, Syslog_-_Cb_Protection_CEF, Syslog_-_Cb_Response_LEEF, Syslog_-_Cell_Relay, Syslog_-_Certes_Networks_CEP, Syslog_-_Check_Point_Log_Exporter, Syslog_-_Checkpoint_Site-to-Site_VPN, Syslog_-_Cisco_ACS, Syslog_-_Cisco_Aironet_WAP, Syslog_-_Cisco_APIC, Syslog_-_Cisco_Application_Control_Engine, Syslog_-_Cisco_ASA, Syslog_-_Cisco_Clean_Access_(CCA)_Appliance, Syslog_-_Cisco_CSS_Load_Balancer, Syslog_-_Cisco_Email_Security_Appliance, Syslog_-_Cisco_FirePOWER, Syslog_-_Cisco_Firepower_Threat_Defense, Syslog_-_Cisco_FireSIGHT, Syslog_-_Cisco_FWSM, Syslog_-_Cisco_Global_Site_Selector, Syslog_-_Cisco_ISE, Syslog_-_Cisco_Meraki, Syslog_-_Cisco_Nexus_Switch, Syslog_-_Cisco_PIX, Syslog_-_Cisco_Prime_Infrastructure, Syslog_-_Cisco_Router, Syslog_-_Cisco_Secure_ACS_5, Syslog_-_Cisco_Session_Border_Controller, Syslog_-_Cisco_Switch, Syslog_-_Cisco_Telepresence_Video_Communications_Server, Syslog_-_Cisco_UCS, Syslog_-_Cisco_Unified_Comm_Mgr_(Call_Mgr), Syslog_-_Cisco_VPN_Concentrator, Syslog_-_Cisco_WAAS, Syslog_-_Cisco_Web_Security, Syslog_-_Cisco_Wireless_Access_Point, Syslog_-_Cisco_Wireless_Control_System, Syslog_-_CiscoWorks, Syslog_-_Citrix_Access_Gateway_Server, Syslog_-_Citrix_Netscaler, Syslog_-_Citrix_XenServer, Syslog_-_Claroty_CTD_CEF, Syslog_-_Clearswift_Secure_Email_Gateway, Syslog_-_CloudLock, Syslog_-_CodeGreen_Data_Loss_Prevention, Syslog_-_Cofense_Triage_CEF, Syslog_-_Consentry_NAC, Syslog_-_Corero_IPS, Syslog_-_Corero_SmartWall_DDoS, Syslog_-_CoyotePoint_Equalizer, Syslog_-_Crowdstrike_Falconhost_CEF, Syslog_-_CyberArk, Syslog_-_CyberArk_Privileged_Threat_Analytics, Syslog_-_Cylance_CEF, Syslog_-_CylancePROTECT, Syslog_-_DarkTrace_CEF, Syslog_-_Dell_Force_10, Syslog_-_Dell_PowerConnect_Switch, Syslog_-_Dell_Remote_Access_Controller, Syslog_-_Dell_SecureWorks_iSensor_IPS, Syslog_-_Dialogic_Media_Gateway, Syslog_-_Digital_Guardian_CEF, Syslog_-_D-Link_Switch, Syslog_-_Don_not_use, Syslog_-_Dragos_Platform_CEF, Syslog_-_Ecessa_ShieldLink, Syslog_-_EfficientIP, Syslog_-_EMC_Avamar, Syslog_-_EMC_Centera, Syslog_-_EMC_Data_Domain, Syslog_-_EMC_Isilon, Syslog_-_EMC_Unity_Array, Syslog_-_EMC_VNX, Syslog_-_Ensilo_NGAV, Syslog_-_Enterasys_Dragon_IDS, Syslog_-_Enterasys_Router, Syslog_-_Enterasys_Switch, Syslog_-_Entrust_Entelligence_Messaging_Server, Syslog_-_Entrust_IdentityGuard, Syslog_-_Epic_Hyperspace_CEF, Syslog_-_EqualLogic_SAN, Syslog_-_eSafe_Email_Security, Syslog_-_ESET_Remote_Administrator_(ERA)_LEEF, Syslog_-_Event_Reporter_(Win_2000/XP/2003), Syslog_-_Exabeam, Syslog_-_Exchange_Message_Tracking, Syslog_-_ExtraHop, Syslog_-_Extreme_Wireless_LAN, Syslog_-_ExtremeWare, Syslog_-_ExtremeXOS, Syslog_-_F5_BIG-IP_Access_Policy_Manager, Syslog_-_F5_BIG-IP_AFM, Syslog_-_F5_BIG-IP_ASM, Syslog_-_F5_BIG-IP_ASM_Key-Value_Pairs, Syslog_-_F5_BIG-IP_ASM_v12, Syslog_-_F5_Big-IP_GTM_&amp;_DNS, Syslog_-_F5_Big-IP_LTM, Syslog_-_F5_FirePass_Firewall, Syslog_-_F5_Silverline_DDoS_Protection, Syslog_-_Fargo_HDP_Card_Printer_and_Encoder, Syslog_-_Fat_Pipe_Load_Balancer, Syslog_-_Fidelis_XPS, Syslog_-_FireEye_E-Mail_MPS, Syslog_-_FireEye_EX, Syslog_-_FireEye_Web_MPS/CMS/ETP/HX, Syslog_-_Forcepoint_DLP, Syslog_-_Forcepoint_Email_Security_Gateway, Syslog_-_Forcepoint_Stonesoft_NGFW, Syslog_-_Forcepoint_SureView_Insider_Threat, Syslog_-_Forcepoint_Web_Security, Syslog_-_Forcepoint_Web_Security_CEF_Format, Syslog_-_Forescout_CounterACT_NAC, Syslog_-_Fortinet_FortiAnalyzer, Syslog_-_Fortinet_FortiAuthenticator, Syslog_-_Fortinet_FortiDDoS, Syslog_-_Fortinet_FortiGate, Syslog_-_Fortinet_FortiGate_v4.0, Syslog_-_Fortinet_FortiGate_v5.0, Syslog_-_Fortinet_FortiGate_v5.2, Syslog_-_Fortinet_FortiGate_v5.4/v5.6, Syslog_-_Fortinet_FortiGate_v5.6_CEF, Syslog_-_Fortinet_Fortigate_v6.0, Syslog_-_Fortinet_FortiMail, Syslog_-_Fortinet_FortiWeb, Syslog_-_Foundry_Switch, Syslog_-_Gene6_FTP, Syslog_-_Generic_CEF, Syslog_-_Generic_ISC_DHCP, Syslog_-_Generic_LEEF, Syslog_-_Guardium_Database_Activity_Monitor, Syslog_-_H3C_Router, Syslog_-_Hitachi_Universal_Storage_Platform, Syslog_-_HP_BladeSystem, Syslog_-_HP_iLO, Syslog_-_HP_Procurve_Switch, Syslog_-_HP_Router, Syslog_-_HP_Switch, Syslog_-_HP_Unix_Tru64, Syslog_-_HP_Virtual_Connect_Switch, Syslog_-_HP-UX_Host, Syslog_-_Huawei_Access_Router, Syslog_-_IBM_Blade_Center, Syslog_-_IBM_Security_Network_Protection, Syslog_-_IBM_Virtual_Tape_Library_Server, Syslog_-_IBM_WebSphere_DataPower_Integration, Syslog_-_IBM_zSecure_Alert_for_ACF2_2.1.0, Syslog_-_IceWarp_Server, Syslog_-_Imperva_Incapsula_CEF, Syslog_-_Imperva_SecureSphere, Syslog_-_Imprivata_OneSign_SSO, Syslog_-_InfoBlox, Syslog_-_Invincea_(LEEF), Syslog_-_iPrism_Proxy_Log, Syslog_-_IPSWITCH_MOVEit_Server, Syslog_-_IPTables, Syslog_-_IRIX_Host, Syslog_-_iSeries_via_Powertech_Interact, Syslog_-_Ivanti_FileDirector, Syslog_-_JetNexus_Load_Balancer, Syslog_-_Juniper_DX_Application_Accelerator, Syslog_-_Juniper_Firewall, Syslog_-_Juniper_Firewall_3400, Syslog_-_Juniper_Host_Checker, Syslog_-_Juniper_IDP, Syslog_-_Juniper_NSM, Syslog_-_Juniper_Router, Syslog_-_Juniper_SSL_VPN, Syslog_-_Juniper_SSL_VPN_WELF_Format, Syslog_-_Juniper_Switch, Syslog_-_Juniper_Trapeze, Syslog_-_Juniper_vGW_Virtual_Gateway, Syslog_-_Kaspersky_Security_Center, Syslog_-_Kea_DHCP_Server, Syslog_-_Kemp_Load_Balancer, Syslog_-_KFSensor_Honeypot, Syslog_-_KFSensor_Honeypot_CEF, Syslog_-_Lancope_StealthWatch, Syslog_-_Lancope_StealthWatch_CEF, Syslog_-_Layer_7_SecureSpan_SOA_Gateway, Syslog_-_Legacy_Checkpoint_Firewall_(Not_Log_Exporter), Syslog_-_Legacy_Checkpoint_IPS_(Not_Log_Exporter), Syslog_-_Lieberman_Enterprise_Random_Password_Manager, Syslog_-_Linux_Audit, Syslog_-_Linux_Host, Syslog_-_Linux_TACACS_Plus, Syslog_-_LOGbinder_EX, Syslog_-_LOGbinder_SP, Syslog_-_LOGbinder_SQL, Syslog_-_LogRhythm_Data_Indexer_Monitor, Syslog_-_LogRhythm_Inter_Deployment_Data_Sharing, Syslog_-_LogRhythm_Log_Distribution_Services, Syslog_-_LogRhythm_Network_Monitor, Syslog_-_LogRhythm_Syslog_Generator, Syslog_-_Lumension, Syslog_-_MacOS_X, Syslog_-_Malwarebytes_Endpoint_Security_CEF, Syslog_-_Mandiant_MIR, Syslog_-_McAfee_Advanced_Threat_Defense, Syslog_-_McAfee_Email_And_Web_Security, Syslog_-_McAfee_ePO, Syslog_-_McAfee_Firewall_Enterprise, Syslog_-_McAfee_Network_Security_Manager, Syslog_-_McAfee_Secure_Internet_Gateway, Syslog_-_McAfee_SecureMail, Syslog_-_McAfee_Skyhigh_for_Shadow_IT_LEEF, Syslog_-_McAfee_Web_Gateway, Syslog_-_mGuard_Firewall, Syslog_-_Microsoft_Advanced_Threat_Analytics_(ATA)_CEF, Syslog_-_Microsoft_Azure_Log_Integration, Syslog_-_Microsoft_Azure_MFA, Syslog_-_Microsoft_Forefront_UAG, Syslog_-_Mirapoint, Syslog_-_MobileIron, Syslog_-_Motorola_Access_Point, Syslog_-_MS_IIS_Web_Log_W3C_Format_(Snare), Syslog_-_MS_Windows_Event_Logging_XML_-_Application, Syslog_-_MS_Windows_Event_Logging_XML_-_Security, Syslog_-_MS_Windows_Event_Logging_XML_-_System, Syslog_-_Nagios, Syslog_-_nCircle_Configuration_Compliance_Manager, Syslog_-_NetApp_Filer, Syslog_-_NETASQ_Firewall, Syslog_-_NetGate_Router, Syslog_-_NetMotion_VPN, Syslog_-_Netscout_nGenius_InfiniStream, Syslog_-_NetScreen_Firewall, Syslog_-_Netskope, Syslog_-_Netskope_CEF, Syslog_-_Network_Chemistry_RFprotect, Syslog_-_Nginx_Web_Log, Syslog_-_Nimble_Storage, Syslog_-_Nortel_8600_Switch, Syslog_-_Nortel_BayStack_Switch, Syslog_-_Nortel_Contivity, Syslog_-_Nortel_Firewall, Syslog_-_Nortel_IP_1220, Syslog_-_Nortel_Passport_Switch, Syslog_-_Nozomi_Networks_Guardian_CEF, Syslog_-_NuSecure_Gateway, Syslog_-_Nutanix, Syslog_-_Open_Collector, Syslog_-_Open_Collector_-_AWS_CloudTrail, Syslog_-_Open_Collector_-_AWS_CloudWatch, Syslog_-_Open_Collector_-_AWS_Config_Events, Syslog_-_Open_Collector_-_AWS_Guard_Duty, Syslog_-_Open_Collector_-_AWS_S3, Syslog_-_Open_Collector_-_Azure_Event_Hub, Syslog_-_Open_Collector_-_Carbon_Black_Cloud, Syslog_-_Open_Collector_-_CarbonBlackBeat_Heartbeat, Syslog_-_Open_Collector_-_Cisco_AMP, Syslog_-_Open_Collector_-_Cisco_Umbrella, Syslog_-_Open_Collector_-_CiscoAMPBeat_Heartbeat, Syslog_-_Open_Collector_-_Duo_Authentication_Security, Syslog_-_Open_Collector_-_DuoBeat_Heartbeat, Syslog_-_Open_Collector_-_EventHubBeat_Heartbeat, Syslog_-_Open_Collector_-_GCP_Audit, Syslog_-_Open_Collector_-_GCP_Cloud_Key_Management_Service, Syslog_-_Open_Collector_-_GCP_Http_Load_Balancer, Syslog_-_Open_Collector_-_GCP_Pub_Sub, Syslog_-_Open_Collector_-_GCP_Security_Command_Center, Syslog_-_Open_Collector_-_GCP_Virtual_Private_Cloud, Syslog_-_Open_Collector_-_Gmail_Message_Tracking, Syslog_-_Open_Collector_-_GMTBeat_Heartbeat, Syslog_-_Open_Collector_-_GSuite, Syslog_-_Open_Collector_-_GSuiteBeat_Heartbeat, Syslog_-_Open_Collector_-_Metricbeat, Syslog_-_Open_Collector_-_Okta_System_Log, Syslog_-_Open_Collector_-_OktaSystemLogBeat_Heartbeat, Syslog_-_Open_Collector_-_PubSubBeat_Heartbeat, Syslog_-_Open_Collector_-_S3Beat_Heartbeat, Syslog_-_Open_Collector_-_Sophos_Central, Syslog_-_Open_Collector_-_SophosCentralBeat_Heartbeat, Syslog_-_Open_Collector_-_Webhook, Syslog_-_Open_Collector_-_Webhook_OneLogin, Syslog_-_Open_Collector_-_Webhook_Zoom, Syslog_-_Open_Collector_-_WebhookBeat_Heartbeat, Syslog_-_Opengear_Console, Syslog_-_OpenLDAP, Syslog_-_Oracle_10g_Audit_Trail, Syslog_-_Oracle_11g_Audit_Trail, Syslog_-_OSSEC_Alerts, Syslog_-_Other, Syslog_-_Outpost24, Syslog_-_Palo_Alto_Cortex_XDR, Syslog_-_Palo_Alto_Custom_Pipe, Syslog_-_Palo_Alto_Firewall, Syslog_-_Palo_Alto_Traps_CEF, Syslog_-_Palo_Alto_Traps_Management_Service, Syslog_-_Password_Manager_Pro, Syslog_-_pfSense_Firewall, Syslog_-_PingFederate_7.2, Syslog_-_PingFederate_CEF, Syslog_-_Polycom, Syslog_-_Postfix, Syslog_-_Procera_PacketLogic, Syslog_-_Proofpoint_Spam_Firewall, Syslog_-_Protegrity_Defiance_DPS, Syslog_-_QLogic_Infiniband_Switch, Syslog_-_Quest_Defender, Syslog_-_Radiator_Radius, Syslog_-_RADiFlow_3180_Switch, Syslog_-_Radware_Alteon_Load_Balancer, Syslog_-_Radware_DefensePro, Syslog_-_Radware_Web_Server_Director_Audit_Log, Syslog_-_Raritan_KVM, Syslog_-_Raz-Lee, Syslog_-_RedSeal, Syslog_-_Riverbed, Syslog_-_RSA_ACE, Syslog_-_RSA_Authentication_Manager_v7.1, Syslog_-_RSA_Authentication_Manager_v8.x, Syslog_-_RSA_Web_Threat_Detection, Syslog_-_RSA_Web_Threat_Detection_5.1, Syslog_-_RuggedRouter, Syslog_-_Safenet, Syslog_-_Sailpoint, Syslog_-_Sauce_Labs, Syslog_-_SecureAuth_IdP, Syslog_-_SecureAuth_IdP_v9, Syslog_-_SecureLink, Syslog_-_SecureTrack, Syslog_-_SEL_3610_Port_Switch, Syslog_-_SEL_3620_Ethernet_Security_Gateway, Syslog_-_Sentinel_IPS, Syslog_-_SentinelOne_CEF, Syslog_-_Sguil, Syslog_-_Siemens_Scalance_X400, Syslog_-_Smoothwall_Firewall, Syslog_-_SnapGear_Firewall, Syslog_-_Snare_Windows_2003_Event_Log, Syslog_-_Snare_Windows_2008_Event_Log, Syslog_-_Snort_IDS, Syslog_-_Solaris_(Snare), Syslog_-_Solaris_Host, Syslog_-_SonicWALL, Syslog_-_SonicWALL_SSL-VPN, Syslog_-_Sophos_Email_Encryption_Appliance, Syslog_-_Sophos_UTM, Syslog_-_Sophos_Web_Proxy, Syslog_-_Sophos_XG_Firewall, Syslog_-_Sourcefire_IDS_3D, Syslog_-_Sourcefire_RNA, Syslog_-_Spectracom_Network_Time_Server, Syslog_-_Splunk_API_-_Checkpoint_Firewall, Syslog_-_Splunk_API_-_Cisco_Netflow_V9, Syslog_-_Splunk_API_-_Nessus_Vulnerability_Scanner, Syslog_-_Squid_Proxy, Syslog_-_StealthBits_Activity_Monitor, Syslog_-_STEALTHbits_StealthINTERCEPT, Syslog_-_StoneGate_Firewall, Syslog_-_Stonesoft_IPS, Syslog_-_Stormshield_Network_Security_Firewall, Syslog_-_Sycamore_Networks_DNX-88, Syslog_-_Sygate_Firewall, Syslog_-_Symantec_Advanced_Threat_Protection_(ATP)_CEF, Syslog_-_Symantec_DLP_CEF, Syslog_-_Symantec_Endpoint_Server, Syslog_-_Symantec_Messaging_Gateway, Syslog_-_Symantec_PGP_Gateway, Syslog_-_Symbol_Wireless_Access_Point, Syslog_-_Tanium, Syslog_-_Temporary_LST-2, Syslog_-_Tenable_SecurityCenter, Syslog_-_Thycotic_Secret_Server, Syslog_-_Tipping_Point_IPS, Syslog_-_Tipping_Point_SSL_Reverse_Proxy, Syslog_-_Top_Layer_IPS, Syslog_-_Townsend_Alliance_LogAgent, Syslog_-_Trend_Micro_Control_Manager_CEF, Syslog_-_Trend_Micro_Deep_Discovery_Inspector, Syslog_-_Trend_Micro_Deep_Security_CEF, Syslog_-_Trend_Micro_Deep_Security_LEEF, Syslog_-_Trend_Micro_IWSVA, Syslog_-_Trend_Micro_Vulnerability_Protection_Manager, Syslog_-_Tripwire, Syslog_-_Trustwave_NAC, Syslog_-_Trustwave_Secure_Web_Gateway, Syslog_-_Trustwave_Web_Application_Firewall, Syslog_-_Tufin, Syslog_-_Tumbleweed_Mailgate_Server, Syslog_-_Ubiquiti_UniFi_Security_Gateway, Syslog_-_Ubiquiti_UniFi_Switch, Syslog_-_Ubiquiti_UniFi_WAP, Syslog_-_Untangle, Syslog_-_Vamsoft_ORF, Syslog_-_Vanguard_Active_Alerts, Syslog_-_Varonis_DatAlert, Syslog_-_Vasco_Digipass_Identikey_Server, Syslog_-_Vectra_Networks, Syslog_-_Versa_Networks_SD-WAN, Syslog_-_VMWare_ESX/ESXi_Server, Syslog_-_VMware_Horizon_View, Syslog_-_VMWare_NSX/NSX-T, Syslog_-_VMWare_Unified_Access_Gateway, Syslog_-_VMWare_vCenter_Server, Syslog_-_VMWare_vShield, Syslog_-_Voltage_Securemail, Syslog_-_Vormetric_CoreGuard, Syslog_-_Vormetric_Data_Security_Manager, Syslog_-_WALLIX_Bastion, Syslog_-_Watchguard_FireBox, Syslog_-_WS2000_Wireless_Access_Point, Syslog_-_Wurldtech_SmartFirewall, Syslog_-_Xirrus_Wireless_Array, Syslog_-_Zimbra_System_Log, Syslog_-_Zix_E-mail_Encryption, Syslog_-_Zscaler_Nano_Streaming_Service, Syslog_-_ZXT_Load_Balancer, Syslog_-_ZyWALL_VPN_Firewall, Syslog_Avaya_G450_Media_Gateway, Syslog_File_-_AIX_Host, Syslog_File_-_BSD_Format, Syslog_File_-_HP-UX_Host, Syslog_File_-_IRIX_Host, Syslog_File_-_Linux_Host, Syslog_File_-_LogRhythm_Syslog_Generator, Syslog_File_-_MS_2003_Event_Log_(Snare), Syslog_File_-_Oracle_10g_Audit_Trail, Syslog_File_-_Oracle_11g_Audit_Trail, Syslog_File_-_Solaris_Host, UDLA_-_CA_Single_Sign-On, UDLA_-_Deepnet_DualShield, UDLA_-_Drupal, UDLA_-_Finacle_Core, UDLA_-_Finacle_Treasury_Logs, UDLA_-_Forcepoint, UDLA_-_Gallagher_Command_Centre, UDLA_-_iManage_Worksite, UDLA_-_ISS_Proventia_SiteProtector_-_IPS, UDLA_-_LogRhythm_Enterprise_Monitoring_Solution, UDLA_-_LREnhancedAudit, UDLA_-_McAfee_ePolicy_Orchestrator_-_Universal_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_3.6_-_Events, UDLA_-_McAfee_ePolicy_Orchestrator_4.0_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_4.5_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.0_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.1_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.3_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.9_-_ePOEvents, UDLA_-_McAfee_Network_Access_Control, UDLA_-_McAfee_Network_Security_Manager, UDLA_-_Microsoft_System_Center_2012_Endpoint_Protection, UDLA_-_ObserveIT, UDLA_-_Oracle_10g_Audit_Trail, UDLA_-_Oracle_11g_Audit_Trail, UDLA_-_Oracle_12C_Unified_Auditing, UDLA_-_Oracle_9i_Audit_Trail, UDLA_-_Other, UDLA_-_SEL_3530_RTAC, UDLA_-_SharePoint_2007_AuditData, UDLA_-_SharePoint_2010_EventData, UDLA_-_SharePoint_2013_EventData, UDLA_-_Siemens_Invision, UDLA_-_Sophos_Anti-Virus, UDLA_-_Sophos_Endpoint_Security_and_Control, UDLA_-_Symantec_CSP, UDLA_-_Symantec_SEP, UDLA_-_Symmetry_Access_Control, UDLA_-_VMWare_vCenter_Server, UDLA_-_VMWare_vCloud, VLS_-_Syslog_-_Infoblox_-_DNS_RPZ, VLS_-_Syslog_-_Infoblox_-_Threat_Protection. | Optional | 
| host_name | Impacted host name. | Optional | 
| username | Username. | Optional | 
| subject | Email subject. | Optional | 
| sender | Email sender. | Optional | 
| recipient | Email recipient. | Optional | 
| hash | Hash. | Optional | 
| url | URL. | Optional | 
| process_name | Process name. | Optional | 
| object | Log object. | Optional | 
| ip_address | IP address. | Optional | 
| max_massage | Maximum number of log message to query. Default is 10. | Optional | 
| query_timeout | The query timeout in seconds. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Search.Task.TaskID | String | Task ID | 


#### Command Example
```json
{
    "Logrhythm": {
        "Search": {
            "Task": {
                "TaskID": "e1c3f960-e1c3f960-e1c3f960"
            }
        }
    }
}
```

#### Human Readable Output

>New search query created, Task ID=e1c3f960-e1c3f960-e1c3f960

### lr-get-query-result
***
Get search query result with task ID output from lr-execute-search-query command


#### Base Command

`lr-get-query-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID from lr-execute-search-query command output. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Search.Results.TaskStatus | String | Task Status | 
| Logrhythm.Search.Results.TaskID | String | Task ID | 
| Logrhythm.Search.Results.Items.originEntityId | Number | Entity ID | 
| Logrhythm.Search.Results.Items.impactedIp | String | Impacted IP | 
| Logrhythm.Search.Results.Items.classificationTypeName | String | Classification Name | 
| Logrhythm.Search.Results.Items.logSourceName | String | Log Source Name | 
| Logrhythm.Search.Results.Items.entityName | String | Entity Name | 
| Logrhythm.Search.Results.Items.normalDate | Date | Date | 
| Logrhythm.Search.Results.Items.vendorMessageId | String | Vendor Log message | 
| Logrhythm.Search.Results.Items.priority | Number | Log priority | 
| Logrhythm.Search.Results.Items.sequenceNumber | String | Seq number | 
| Logrhythm.Search.Results.Items.originHostId | Number | Origin Host ID | 
| Logrhythm.Search.Results.Items.mpeRuleId | Number | Log Rhythm rule ID | 
| Logrhythm.Search.Results.Items.originIp | String | Origin IP | 
| Logrhythm.Search.Results.Items.mpeRuleName | String | Log Rhythm rule name | 
| Logrhythm.Search.Results.Items.logSourceHostId | Number | Log Source host ID | 
| Logrhythm.Search.Results.Items.originHost | String | Origin Host | 
| Logrhythm.Search.Results.Items.logDate | Date | Log Date | 
| Logrhythm.Search.Results.Items.classificationName | String | Log classification name | 


#### Command Example
```json
{
    "Logrhythm": {
        "Search": {
            "Results": {
                "TaskStatus": "Completed",
                "TaskID": "e1c3f960-e1c3f960-e1c3f960",
                "Items": [
                    {
                        "originEntityId": 1,
                        "impactedIp": "10.0.0.1",
                        "logSourceName": "Linux Syslog",
                        "originHost": "1.2.3.4",
                        "entityName": "Nothing"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Search results for task e1c3f960-e1c3f960-e1c3f960
>|OriginEntityId|ImpactedIp|LogSourceName|OriginHost|EntityName|
>|---|---|---|---|---|
>| 1 | 10.0.0.1 | Linux Syslog | 1.2.3.4 | Nothing | 


### lr-get-users
***
Returns a list of users


#### Base Command

`lr-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The LogRhythm user ID. | Optional | 
| count | Number of users to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.User.ID | string | LogRhythm user ID | 
| Logrhythm.User.DateUpdated | string | Date that the user was updated. | 
| Logrhythm.User.HostStatus | string | Host status of the LogRhythm user. | 
| Logrhythm.User.LastName | string | Last name of the LogRhythm user. | 
| Logrhythm.User.FirstName | string | First name of the LogRhythm user. | 
| Logrhythm.User.UserType | string | LogRhythm user type | 
| Logrhythm.User.Entity | string | LogRhythm entity information | 
| Logrhythm.User.Owner | string | LogRhythm owner information | 
| Logrhythm.User.ReadAccess | string | Read Access of the LogRhythm user. | 
| Logrhythm.User.WriteAccess | string | Write Access of the LogRhythm user. | 


#### Command Example
```!lr-get-users user_id=5```

#### Context Example
```json
{
    "Logrhythm": {
        "User": {
            "DateUpdated": "2021-10-11T15:04:50.757Z",
            "Entity": {
                "id": 1,
                "name": "Primary Site"
            },
            "FirstName": "testuser",
            "HostStatus": "Retired",
            "ID": 5,
            "LastName": "testuser",
            "Owner": {
                "id": 1,
                "name": "myadmin"
            },
            "ReadAccess": "Private",
            "UserType": "Individual",
            "WriteAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### Users information
>|ID|DateUpdated|HostStatus|LastName|FirstName|UserType|Entity|Owner|ReadAccess|WriteAccess|
>|---|---|---|---|---|---|---|---|---|---|
>| 5 | 2021-10-11T15:04:50.757Z | Retired | testuser | testuser | Individual | id: 1<br/>name: Primary Site | id: 1<br/>name: myadmin | Private | Private |


### lr-get-logins
***
Returns a list of logins


#### Base Command

`lr-get-logins`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The LogRhythm user ID. | Optional | 
| count | Number of logins to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Login.Login | string | The login username | 
| Logrhythm.Login.UserProfileId | string | The profile ID for the LogRhythm user | 
| Logrhythm.Login.UserId | string | LogRhythm user ID | 
| Logrhythm.Login.DefaultEntityId | string | The default entity ID of the login | 
| Logrhythm.Login.HostStatus | string | Host status of the LogRhythm login. | 
| Logrhythm.Login.DateUpdated | string | Date that the login was updated. | 
| Logrhythm.Login.DateCreated | string | Date that the login was created. | 
| Logrhythm.Login.Entities | string | LogRhythm entities information | 


#### Command Example
```!lr-get-logins user_id=5```

#### Context Example
```json
{
    "Logrhythm": {
        "Login": {
            "DateCreated": "2021-09-21T13:27:59.72Z",
            "DateUpdated": "2021-10-11T15:04:50.753Z",
            "DefaultEntityId": 1,
            "Entities": [
                {
                    "id": -100,
                    "name": "Global Entity"
                },
                {
                    "id": 1,
                    "name": "Primary Site"
                },
                {
                    "id": 3,
                    "name": "v3"
                }
            ],
            "HostStatus": "Retired",
            "Login": "testusername",
            "UserId": 5,
            "UserProfileId": -100
        }
    }
}
```

#### Human Readable Output

>### Logins information
>|Login|UserProfileId|UserId|DefaultEntityId|HostStatus|DateUpdated|DateCreated|
>|---|---|---|---|---|---|---|
>| testusername | -100 | 5 | 1 | Retired | 2021-10-11T15:04:50.753Z | 2021-09-21T13:27:59.72Z |


### lr-get-privileges
***
Returns the privileges of a given user.


#### Base Command

`lr-get-privileges`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The LogRhythm user ID. | Required | 
| offset | The position to start at . Default is 0. | Optional | 
| count | Number of privileges to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Privileges.ID | string | The LogRhythm user ID | 
| Logrhythm.Privileges.Privileges | string | A list of the LogRhythm user's privileges. | 


#### Command Example
```!lr-get-privileges user_id=5 count=15```

#### Context Example
```json
{
    "Logrhythm": {
        "Privileges": {
            "ID": "5",
            "Privileges": [
                "GlobalAIEEventsAccess",
                "SecondLookMgmt",
                "LogRhythmAPIAccess",
                "CaseMgmtAccess",
                "CloudAIAccess",
                "ShowDeploymentManager",
                "ShowEntityMgr",
                "EntityMgmt",
                "ShowAgentAgentMgr",
                "AgentMgmt",
                "ShowLSMgr",
                "LSMgmt",
                "DPMgmt",
                "PMMgmt",
                "NMMgmt"
            ]
        }
    }
}
```

#### Human Readable Output

>### Privileges information
>|Privileges|
>|---|
>| GlobalAIEEventsAccess,<br/>SecondLookMgmt,<br/>LogRhythmAPIAccess,<br/>CaseMgmtAccess,<br/>CloudAIAccess,<br/>ShowDeploymentManager,<br/>ShowEntityMgr,<br/>EntityMgmt,<br/>ShowAgentAgentMgr,<br/>AgentMgmt,<br/>ShowLSMgr,<br/>LSMgmt,<br/>DPMgmt,<br/>PMMgmt,<br/>NMMgmt |


### lr-get-profiles
***
Returns a list of user profiles


#### Base Command

`lr-get-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The LogRhythm profile ID. | Optional | 
| count | Number of profiles to return. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Profile.ID | string | ID of the LogRhythm user profile | 
| LogRhythm.Profile.Name | string | Name of the Logrhythm user profile | 
| LogRhythm.Profile.ShortDescription | string | Short description of the profile | 
| LogRhythm.Profile.LongDescription | string | Long description of the profile | 
| LogRhythm.Profile.DataProcessorAccessMode | string | Data processor access mode | 
| LogRhythm.Profile.SecurityRole | string | The user profile's security role | 
| LogRhythm.Profile.ProfileType | string | The user profile's type | 
| LogRhythm.Profile.DateUpdated | string | Date that the profile was updated. | 
| LogRhythm.Profile.TotalAssociatedUsers | string | Total number of users with this profile | 
| LogRhythm.Profile.NotificationGroupsPermissions | string | Permissions on notification groups | 
| LogRhythm.Profile.ADGroupsPermissions | string | Active Directory group permissions | 
| LogRhythm.Profile.EntityPermissions | string | Entity permissions for the profile | 
| LogRhythm.Profile.DataProcessorsPermissions | string | Profile's data processor permissions | 
| LogRhythm.Profile.LogsourceListPermissions | string | Profile's logsource list permissions | 
| LogRhythm.Profile.LogSourcePermissions | string | Profile's permissions for log sources | 
| LogRhythm.Profile.Privileges | string | Profile's privileges | 
| LogRhythm.Profile.SmartResponsePluginsPermissions | string | Profile's smart response plugin permissions | 


#### Command Example
```!lr-get-profiles profile_id=-100```

#### Context Example
```json
{
    "Logrhythm": {
        "Profile": {
            "DataProcessorAccessMode": "All",
            "DateUpdated": "2021-07-09T16:03:19.62Z",
            "ID": -100,
            "LongDescription": "The LogRhythm Global Administrator profile is a system record which cannot be modified or deleted.",
            "Name": "LogRhythm Global Administrator",
            "NotificationGroupsPermissions": [
                {
                    "id": 1,
                    "name": "minim quis"
                }
            ],
            "ProfileType": "Allow",
            "SecurityRole": "GlobalAdmin",
            "ShortDescription": "LogRhythm Global Administrators have full access to the system.",
            "TotalAssociatedUsers": 11
        }
    }
}
```

#### Human Readable Output

>### Users information
>|ID|Name|ShortDescription|LongDescription|DataProcessorAccessMode|SecurityRole|ProfileType|DateUpdated|TotalAssociatedUsers|
>|---|---|---|---|---|---|---|---|---|
>| -100 | LogRhythm Global Administrator | LogRhythm Global Administrators have full access to the system. | The LogRhythm Global Administrator profile is a system record which cannot be modified or deleted. | All | GlobalAdmin | Allow | 2021-07-09T16:03:19.62Z | 11 |


### lr-add-user
***
Add a new user to the LogRhythm SIEM


#### Base Command

`lr-add-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | First name of the LogRhythm user. | Required | 
| last_name | Last name of the LogRhythm user. | Required | 
| abbreviation | Abbreviation of the user name. Defaults to first letter of first name and then last name, all lowercase. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.User.ID | string | LogRhythm user ID | 
| Logrhythm.User.DateUpdated | string | Date that the user was updated. | 
| Logrhythm.User.HostStatus | string | Host status of the LogRhythm user. | 
| Logrhythm.User.LastName | string | Last name of the LogRhythm user. | 
| Logrhythm.User.FirstName | string | First name of the LogRhythm user. | 
| Logrhythm.User.UserType | string | LogRhythm user type | 
| Logrhythm.User.Entity | string | LogRhythm entity information | 
| Logrhythm.User.Owner | string | LogRhythm owner information | 
| Logrhythm.User.ReadAccess | string | Read Access of the LogRhythm user. | 
| Logrhythm.User.WriteAccess | string | Write Access of the LogRhythm user. | 


#### Command Example
```!lr-add-user first_name=Alice last_name=Richards```

#### Context Example
```json
{
    "Logrhythm": {
        "User": {
            "DateUpdated": "2021-10-20T15:02:14.733Z",
            "Entity": {
                "id": 1,
                "name": "Primary Site"
            },
            "FirstName": "Alice",
            "HostStatus": "Active",
            "ID": 13,
            "LastName": "Richards",
            "Owner": {
                "id": 1,
                "name": "myadmin"
            },
            "ReadAccess": "Private",
            "UserType": "Individual",
            "WriteAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### User added
>|ID|DateUpdated|HostStatus|LastName|FirstName|UserType|Entity|Owner|ReadAccess|WriteAccess|
>|---|---|---|---|---|---|---|---|---|---|
>| 13 | 2021-10-20T15:02:14.733Z | Active | Richards | Alice | Individual | id: 1<br/>name: Primary Site | id: 1<br/>name: myadmin | Private | Private |


### lr-add-login
***
Add a new login to the LogRhythm user


#### Base Command

`lr-add-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of the user to attach the login to. | Required | 
| login | Login name for the user. | Required | 
| profile_id | ID of the user profile to associate with the login. | Required | 
| password | Password for the user. . | Required | 
| entity_id | ID of the entity to associate with the login. Defaults to 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Login.Login | string | The login username | 
| Logrhythm.Login.UserProfileId | string | The profile ID for the LogRhythm user | 
| Logrhythm.Login.UserId | string | LogRhythm user ID | 
| Logrhythm.Login.DefaultEntityId | string | The default entity ID of the login | 
| Logrhythm.Login.HostStatus | string | Host status of the LogRhythm login. | 
| Logrhythm.Login.DateUpdated | string | Date that the login was updated. | 
| Logrhythm.Login.DateCreated | string | Date that the login was created. | 
| Logrhythm.Login.Entities | string | LogRhythm entities information | 


#### Command Example
```!lr-add-login login=arichards password=Example0Password123!! profile_id=-100 user_id=13```

#### Context Example
```json
{
    "Logrhythm": {
        "User": {
            "DateCreated": "2021-10-20T15:02:17.78Z",
            "DateUpdated": "2021-10-20T15:02:17.783Z",
            "DefaultEntityId": 1,
            "Entities": [
                {
                    "id": -100,
                    "name": "Global Entity"
                },
                {
                    "id": 1,
                    "name": "Primary Site"
                },
                {
                    "id": 3,
                    "name": "v3"
                }
            ],
            "HostStatus": "Active",
            "Login": "arichards",
            "UserId": 13,
            "UserProfileId": -100
        }
    }
}
```

#### Human Readable Output

>### Login added
>|Login|UserProfileId|UserId|DefaultEntityId|HostStatus|DateUpdated|DateCreated|
>|---|---|---|---|---|---|---|
>| arichards | -100 | 13 | 1 | Active | 2021-10-20T15:02:17.783Z | 2021-10-20T15:02:17.78Z |
