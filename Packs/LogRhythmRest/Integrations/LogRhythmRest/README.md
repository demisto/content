LogRhythm security intelligence.
This integration was integrated and tested with version xx of LogRhythmRest
## Configure LogRhythmRest on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LogRhythmRest.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Hostname, IP address, or server URL. | True |
    | API Token | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Search API cluster ID. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lr-execute-query
***
Executes a query for logs that match query parameters.


#### Base Command

`lr-execute-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Filter log messages by this argument. | Required | 
| page-size | Number of logs to return. Default is 100. | Optional | 
| time-frame | If time_frame is "Custom", specify the start time for the time range. Possible values are: Today, Last2Days, LastWeek, LastMonth, Custom. Default is Custom. | Optional | 
| start-date | Start date for the data query, for example: "2018-04-20". Only use this argument if the time-frame argument is "Custom". | Optional | 
| end-date | End date for the data query, for example: "2018-04-20". Only use this argument if the time-frame argument is "Custom". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Log.Channel | string | Channel | 
| Logrhythm.Log.Computer | string | Computer | 
| Logrhythm.Log.EventData | string | Event data | 
| Logrhythm.Log.EventID | string | Event ID | 
| Logrhythm.Log.Keywords | string | Keywords | 
| Logrhythm.Log.Level | string | Level | 
| Logrhythm.Log.Opcode | string | Opcode | 
| Logrhythm.Log.Task | string | Task | 


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
            "Computer": "WIN-1234.demisto.lab", 
            "Opcode": "Info", 
            "Keywords": "Audit Failure", 
            "EventData": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tGPWARD\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", 
            "Channel": "Security"
        }, 
        {
            "EventID": "4625", 
            "Task": "Logon", 
            "Level": "Information", 
            "Computer": "WIN-1234.demisto.lab", 
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
>| Information | WIN-1234.demisto.lab | Security | Audit Failure | An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tGPWARD\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested. |
>| Information | WIN-1234.demisto.lab | Security | Audit Failure | An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tTMARTIN\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested. |


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
| Logrhythm.Host.OS | String | The host OS. | 
| Logrhythm.Host.ThreatLevel | String | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | String | Use event log credentials | 
| Logrhythm.Host.Name | String | The name of the host. | 
| Logrhythm.Host.DateUpdated | String | The last update date of the host. | 
| Logrhythm.Host.HostZone | String | The host zone. | 
| Logrhythm.Host.RiskLevel | String | The risk level. | 
| Logrhythm.Host.Location | String | The host location. | 
| Logrhythm.Host.Status | String | The host status. | 
| Logrhythm.Host.ID | String | The unique ID of the host object. | 
| Logrhythm.Host.OSType | String | The type of the host OS. | 


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
| short-description | The short description. Default is None. | Optional | 
| long-description | The long description. Default is None. | Optional | 
| risk-level | The short description. Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. Default is The host risk level.. | Required | 
| threat-level | The host threat level. Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. Default is None. | Optional | 
| threat-level-comments | Comments for the host threat level. Default is None. | Optional | 
| host-status | The host status. Possible values are: New, Retired, Active. | Required | 
| host-zone | The host zone. Possible values are: Unknown, Internal, DMZ, External. | Required | 
| os | The host OS. | Required | 
| use-eventlog-credentials | Use eventlog credentials. Possible values are: true, false. | Required | 
| os-type | The host OS. Possible values are: Unknown, Other, WindowsNT4, Windows2000Professional, Windows2000Server, Windows2003Standard, Windows2003Enterprise, Windows95, WindowsXP, WindowsVista, Linux, Solaris, AIX, HPUX, Windows. Default is Unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | string | The entity ID. | 
| Logrhythm.Host.EntityName | string | The entity name. | 
| Logrhythm.Host.OS | string | The host OS. | 
| Logrhythm.Host.ThreatLevel | string | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | string | Use event log credentials | 
| Logrhythm.Host.Name | string | The name of the host. | 
| Logrhythm.Host.DateUpdated | string | The last update date of the host. | 
| Logrhythm.Host.HostZone | string | The host zone. | 
| Logrhythm.Host.RiskLevel | string | The risk level. | 
| Logrhythm.Host.Location | string | The host location. | 
| Logrhythm.Host.Status | string | The host status. | 
| Logrhythm.Host.ID | string | The unique ID of the host object. | 
| Logrhythm.Host.OSType | string | The type of the host OS. | 


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
| status | The enumeration status of the host. Possible values are: Retired, Active. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | string | The entity ID. | 
| Logrhythm.Host.EntityName | string | The entity name. | 
| Logrhythm.Host.OS | string | The host OS. | 
| Logrhythm.Host.ThreatLevel | string | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | string | Use event log credentials | 
| Logrhythm.Host.Name | string | The name of the host. | 
| Logrhythm.Host.DateUpdated | string | The last update date of the host. | 
| Logrhythm.Host.HostZone | string | The host zone. | 
| Logrhythm.Host.RiskLevel | string | The risk level. | 
| Logrhythm.Host.Location | string | The host location. | 
| Logrhythm.Host.Status | string | The host status. | 
| Logrhythm.Host.ID | string | The unique ID of the host object. | 
| Logrhythm.Host.OSType | string | The type of the host OS. | 


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
Retrieves a list of persons.


#### Base Command

`lr-get-persons`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| person-id | The LogRhythm person ID. | Optional | 
| count | Number of persons to return. Default is 30. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Person.DateUpdated | String | Date that the person was updated. | 
| Logrhythm.Person.FirstName | String | First name. | 
| Logrhythm.Person.LastName | String | Last name. | 
| Logrhythm.Person.HostStatus | string | Host status. | 
| Logrhythm.Person.ID | String | Person ID. | 
| Logrhythm.Person.IsAPIPerson | Boolean | Whether the API is a person. | 
| Logrhythm.Person.UserID | String | User ID. | 
| Logrhythm.Person.UserLogin | String | User login. | 


#### Command Example
```!lr-get-persons person-id=7```

#### Context Example
```json
{
    "Logrhythm": {
        "Person": {
            "DateUpdated": "0001-01-01T00:00:00Z",
            "FirstName": "demisto",
            "HostStatus": "Retired",
            "ID": 7,
            "IsAPIPerson": false,
            "LastName": "demisto",
            "UserID": 5,
            "UserLogin": "DEMISTO\\lrapi2"
        }
    }
}
```

#### Human Readable Output

>### Persons information
>|ID|HostStatus|IsAPIPerson|FirstName|LastName|UserID|UserLogin|DateUpdated|
>|---|---|---|---|---|---|---|---|
>| 7 | Retired | false | demisto | demisto | 5 | DEMISTO\lrapi2 | 0001-01-01T00:00:00Z |


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
| Logrhythm.Network.BIP | String | Began IP address. | 
| Logrhythm.Network.ThreatLevel | String | Threat level. | 
| Logrhythm.Network.Name | String | Network name. | 
| Logrhythm.Network.EIP | String | End IP address. | 
| Logrhythm.Network.DateUpdated | String | Date updated. | 
| Logrhythm.Network.EntityName | String | Entity name. | 
| Logrhythm.Network.HostZone | String | Host zone. | 
| Logrhythm.Network.RiskLevel | String | Risk level. | 
| Logrhythm.Network.Location | String | Network location. | 
| Logrhythm.Network.HostStatus | String | Host status. | 
| Logrhythm.Network.ID | String | Network ID. | 
| Logrhythm.Network.EntityId | String | Entity ID. | 


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
| count | Number of hosts to return. Default is 30. Default is 30. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Logrhythm.Host.EntityId | String | The entity ID. | 
| Logrhythm.Host.EntityName | String | The entity name. | 
| Logrhythm.Host.OS | String | The host OS. | 
| Logrhythm.Host.ThreatLevel | String | The host threat level. | 
| Logrhythm.Host.UseEventlogCredentials | String | Use event log credentials. | 
| Logrhythm.Host.Name | String | The name of the host. | 
| Logrhythm.Host.DateUpdated | String | Date that the host was last updated. | 
| Logrhythm.Host.HostZone | String | The host zone. | 
| Logrhythm.Host.RiskLevel | String | The risk level. | 
| Logrhythm.Host.Location | String | The host location. | 
| Logrhythm.Host.Status | String | The host status. | 
| Logrhythm.Host.ID | String | The unique ID of the host object. | 
| Logrhythm.Host.OSType | String | Host OS type. | 


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
| Logrhythm.Alarm.Summary.DrillDownSummaryLogs | String | Drill down summary logs. | 


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
| count | Number of events to return. Default is 10. Default is 10. | Optional | 
| fields | A CSV list of fields (outputs) to return to the context. If empty, all fields are returned. Possible values are: . | Optional | 
| get-log-message | Returns the log message from the event. Possible values are: True, False. Default is False. | Optional | 


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
                    "impactedHost": "win-jsbol5ercqa.demisto.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.demisto.lab",
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
                    "impactedHost": "win-jsbol5ercqa.demisto.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.demisto.lab",
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
                    "impactedHost": "win-jsbol5ercqa.demisto.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.demisto.lab",
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
                    "impactedHost": "win-jsbol5ercqa.demisto.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.demisto.lab",
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
                    "impactedHost": "win-jsbol5ercqa.demisto.lab",
                    "impactedHostName": "",
                    "impactedName": "win-jsbol5ercqa.demisto.lab",
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
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.demisto.lab |  | win-jsbol5ercqa.demisto.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 1e28712d-4af4-4e82-9403-a2ebfda82f2d | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211157 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.demisto.lab |  | win-jsbol5ercqa.demisto.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | ec975fad-44fd-42cd-be8e-1573742c6d7a | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211156 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.demisto.lab |  | win-jsbol5ercqa.demisto.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 21318d09-2b01-4b88-8b18-efc48c597e1f | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211155 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.demisto.lab |  | win-jsbol5ercqa.demisto.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | 20384578-60c1-4828-bdea-68cdc202d719 | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211154 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |
>| 1040 | Authentication Failure | Audit | 3 | 19812 | User Logon Failure : Bad Password | 1 | 0 | Unknown | 1 | Primary Site | 1 | Primary Site | win-jsbol5ercqa.demisto.lab |  | win-jsbol5ercqa.demisto.lab | Unknown | messageId | 2019-06-20 05:27:03 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA | 1 | WIN-JSBOL5ERCQA MS Security Log | 1000030 | MS Windows Event Logging - Security | administrator | dd2c2251-ede1-4559-916b-0422ea8c0f9e | 1 | 1060400 | EVID 4625 : User Logon Type 3: Wrong Password | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | 2019-06-20 12:27:03 | NtLmSsp | 0xC000006A | 1 | Primary Site | -1 | 0 | Unknown | 0x0 | 3 | -1 | Unknown user name or bad password | 1 | Primary Site | 1 | 211153 | 0x0 | Information | 0xC000006D | Unknown user name or bad password | An account failed to log on | 4625 |

