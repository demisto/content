LogRhythm security intelligence.
This integration was integrated and tested with version 7.7 of LogRhythm Rest API. Previous versions that have been declared [EOL](https://docs.logrhythm.com/docs/enterprise/find-more-information/end-of-life-policy-for-software-and-hardware#EndofLifePolicyforSoftwareandHardware-Appendix:EndofLifeTables) by the vendor, are not supported.



Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-logrhythmrest-v2).

## Configure LogRhythmRest v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Token | True |
| Fetch incidents | False |
| Incidents Fetch Interval | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Incident type | False |
| Alarms max fetch | False |
| Cases max fetch | False |
| Fetch incidents from type | True |
| Alarm status filter | False |
| Alarm rule name filter | False |
| Case tags filter | False |
| Case status filter | False |
| Case priority filter | False |
| Fetch case evidences | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lr-alarms-list
***
Gets the details of the alarms using the filter criteria.


#### Base Command

`lr-alarms-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_status | The alarm status. Possible values: "New", "Opened", "Working", "Escalated", Closed, "Closed_FalseAlarm", "Closed_Resolved", "Closed_Unresolved", "Closed_Reported", "Closed_Monitor". Possible values are: New, Opened, Working, Escalated, Closed, Closed_FalseAlarm, Closed_Resolved, Closed_Unresolved, Closed_Reported, Closed_Monitor. | Optional | 
| offset | The number of alarms to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The numbers of alarms to return. Default is 50. | Optional | 
| alarm_rule_name | Filter by alarm rule name. | Optional | 
| entity_name | Filter by entity name. | Optional | 
| alarm_id | Filter by alarm ID. | Optional | 
| case_association | Filter by case ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Alarm.alarmId | Number | The alarm ID. | 
| LogRhythm.Alarm.alarmDataCached | String | A flag indicating whether the alarm data is cached. | 
| LogRhythm.Alarm.alarmRuleName | String | The alarm rule name. | 
| LogRhythm.Alarm.alarmStatus | String | The alarm status | 
| LogRhythm.Alarm.dateInserted | Date | The alarm date inserted. | 
| LogRhythm.Alarm.entityName | String | The alarm entity name. | 
| LogRhythm.Alarm.associatedCases | String | The alarm associated cases. | 


#### Command Example
```!lr-alarms-list count=2 alarm_status=Opened```

#### Context Example
```json
{
    "LogRhythm": {
        "Alarm": [
            {
                "alarmDataCached": "N",
                "alarmId": 882,
                "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                "alarmStatus": "Opened",
                "associatedCases": [
                    "7C2A040E-3014-41D5-ADF0-164A202D3518",
                    " 5FAA1AFB-5453-4FF7-92F8-28222A586368",
                    " 0795BCB1-28AA-4C3F-9739-B5431AE4004B"
                ],
                "dateInserted": "2021-10-13T09:13:20.103",
                "entityName": "EchoTestEntity"
            },
            {
                "alarmDataCached": "N",
                "alarmId": 334,
                "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                "alarmStatus": "Opened",
                "associatedCases": [
                    "15E63C0A-91EC-49E6-9694-32A432DD657E",
                    " CCB51B6F-083D-442F-8E3F-67BD797A6B52",
                    " 10F65BB5-8B49-42FF-862E-ABDEDF1BA7DE",
                    " C52E0A86-D894-4424-A7A6-EE152B232146",
                    " 58437431-2117-4982-A2B1-FDEC2F083A43"
                ],
                "dateInserted": "2021-08-29T11:30:48.083",
                "entityName": "EchoTestEntity"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alarms
>|Alarm Id|Alarm Status|Associated Cases|Alarm Rule Name|Date Inserted|Entity Name|Alarm Data Cached|
>|---|---|---|---|---|---|---|
>| 882 | Opened | 7C2A040E-3014-41D5-ADF0-164A202D3518,<br/> 5FAA1AFB-5453-4FF7-92F8-28222A586368,<br/> 0795BCB1-28AA-4C3F-9739-B5431AE4004B | LogRhythm Agent Heartbeat Missed | 2021-10-13T09:13:20.103 | EchoTestEntity | N |
>| 334 | Opened | 15E63C0A-91EC-49E6-9694-32A432DD657E,<br/> CCB51B6F-083D-442F-8E3F-67BD797A6B52,<br/> 10F65BB5-8B49-42FF-862E-ABDEDF1BA7DE,<br/> C52E0A86-D894-4424-A7A6-EE152B232146,<br/> 58437431-2117-4982-A2B1-FDEC2F083A43 | LogRhythm Agent Heartbeat Missed | 2021-08-29T11:30:48.083 | EchoTestEntity | N |


### lr-alarm-update
***
Updates the alarm status and RBP based on the alarm ID supplied. alarm_status or rbp are required.


#### Base Command

`lr-alarm-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | The alarm ID. | Required | 
| alarm_status | The alarm status. Possible values: "New", "Opened", "Working", "Escalated", Closed, "Closed_FalseAlarm", "Closed_Resolved", "Closed_Unresolved", "Closed_Reported", "Closed_Monitor". Possible values are: New, Opened, Working, Escalated, Closed, Closed_FalseAlarm, Closed_Resolved, Closed_Unresolved, Closed_Reported, Closed_Monitor. | Optional | 
| rbp | The alarm rbp. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lr-alarm-update alarm_id=200 alarm_status=Closed rbp=100```

#### Human Readable Output

>Alarm 200 has been updated.

### lr-alarm-add-comment
***
Updates the Alarm History table with comments in the Comments column based on the alarm ID supplied.


#### Base Command

`lr-alarm-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | The alarm ID. | Required | 
| alarm_comment | The alarm comment. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lr-alarm-add-comment alarm_id=200 alarm_comment=test```

#### Human Readable Output

>Comment added successfully to the alarm 200.

### lr-alarm-history-list
***
Gets the alarm history details by ID and filter criteria.


#### Base Command

`lr-alarm-history-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | The alarm ID. | Required | 
| person_id | Filter by person ID. | Optional | 
| date_updated | Filter by when the alarm was updated. The returned value will be greater than or equal to the given date. | Optional | 
| type | Filter by history type. Possible type: "comment", "status", and "rbp". Possible values are: comment, status, rbp. | Optional | 
| offset | The number of items to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The numbers of items to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmHistory.alarmId | Number | The alarm ID. | 
| LogRhythm.AlarmHistory.personId | Number | The ID of the person who edited the alarm \(changed status/ added comment, etc.\). | 
| LogRhythm.AlarmHistory.comments | String | The alarm comments. | 
| LogRhythm.AlarmHistory.dateInserted | Date | The date when the alarm was inserted. | 
| LogRhythm.AlarmHistory.dateUpdated | Date | The date when the alarm was updated. | 


#### Command Example
```!lr-alarm-history-list alarm_id=200 type=status```

#### Context Example
```json
{
    "LogRhythm": {
        "AlarmHistory": [
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed",
                "dateInserted": "2021-10-30T20:16:33.673",
                "dateUpdated": "2021-10-30T20:16:33.673",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed",
                "dateInserted": "2021-08-31T15:02:00.127",
                "dateUpdated": "2021-08-31T15:02:00.127",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Working",
                "dateInserted": "2021-08-26T05:17:38.19",
                "dateUpdated": "2021-08-26T05:17:38.19",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Working",
                "dateInserted": "2021-08-26T05:15:57.89",
                "dateUpdated": "2021-08-26T05:15:57.89",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed",
                "dateInserted": "2021-08-19T15:31:32.68",
                "dateUpdated": "2021-08-19T15:31:32.68",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed: Unresolved",
                "dateInserted": "2021-08-19T15:02:08.6",
                "dateUpdated": "2021-08-19T15:02:08.6",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed: Resolved",
                "dateInserted": "2021-08-19T15:01:34.403",
                "dateUpdated": "2021-08-19T15:01:34.403",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Escalated",
                "dateInserted": "2021-08-19T15:01:04.353",
                "dateUpdated": "2021-08-19T15:01:04.353",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Working",
                "dateInserted": "2021-08-19T15:00:38.097",
                "dateUpdated": "2021-08-19T15:00:38.097",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Opened",
                "dateInserted": "2021-08-19T15:00:00.247",
                "dateUpdated": "2021-08-19T15:00:00.247",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: New",
                "dateInserted": "2021-08-19T14:59:27.707",
                "dateUpdated": "2021-08-19T14:59:27.707",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed: Monitor",
                "dateInserted": "2021-08-19T14:58:06.113",
                "dateUpdated": "2021-08-19T14:58:06.113",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed: False Alarm",
                "dateInserted": "2021-08-19T14:57:35.607",
                "dateUpdated": "2021-08-19T14:57:35.607",
                "personId": 1
            },
            {
                "alarmId": 200,
                "comments": "Changed status to: Closed",
                "dateInserted": "2021-08-19T14:56:36.82",
                "dateUpdated": "2021-08-19T14:56:36.82",
                "personId": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### History for alarm 200
>|Alarm Id|Comments|Date Inserted|Date Updated|Person Id|
>|---|---|---|---|---|
>| 200 | Changed status to: Closed | 2021-10-30T20:16:33.673 | 2021-10-30T20:16:33.673 | 1 |
>| 200 | Changed status to: Closed | 2021-08-31T15:02:00.127 | 2021-08-31T15:02:00.127 | 1 |
>| 200 | Changed status to: Working | 2021-08-26T05:17:38.19 | 2021-08-26T05:17:38.19 | 1 |
>| 200 | Changed status to: Working | 2021-08-26T05:15:57.89 | 2021-08-26T05:15:57.89 | 1 |
>| 200 | Changed status to: Closed | 2021-08-19T15:31:32.68 | 2021-08-19T15:31:32.68 | 1 |
>| 200 | Changed status to: Closed: Unresolved | 2021-08-19T15:02:08.6 | 2021-08-19T15:02:08.6 | 1 |
>| 200 | Changed status to: Closed: Resolved | 2021-08-19T15:01:34.403 | 2021-08-19T15:01:34.403 | 1 |
>| 200 | Changed status to: Escalated | 2021-08-19T15:01:04.353 | 2021-08-19T15:01:04.353 | 1 |
>| 200 | Changed status to: Working | 2021-08-19T15:00:38.097 | 2021-08-19T15:00:38.097 | 1 |
>| 200 | Changed status to: Opened | 2021-08-19T15:00:00.247 | 2021-08-19T15:00:00.247 | 1 |
>| 200 | Changed status to: New | 2021-08-19T14:59:27.707 | 2021-08-19T14:59:27.707 | 1 |
>| 200 | Changed status to: Closed: Monitor | 2021-08-19T14:58:06.113 | 2021-08-19T14:58:06.113 | 1 |
>| 200 | Changed status to: Closed: False Alarm | 2021-08-19T14:57:35.607 | 2021-08-19T14:57:35.607 | 1 |
>| 200 | Changed status to: Closed | 2021-08-19T14:56:36.82 | 2021-08-19T14:56:36.82 | 1 |


### lr-alarm-events-list
***
Gets a list of events for the specified alarm ID.
Note: Currently, this command does not work as expected on LogRhythm's side. It always returns a list of one item, even if the given alarm ID is associated with more than one event.


#### Base Command

`lr-alarm-events-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | The alarm ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmEvents.alarmId | Number | The alarm ID. | 
| LogRhythm.AlarmEvents.account | String | The alarm event account. | 
| LogRhythm.AlarmEvents.action | String | The alarm event action. | 
| LogRhythm.AlarmEvents.amount | Unknown | The number of events related to the alarm. | 
| LogRhythm.AlarmEvents.bytesIn | Number | The number of bytes received or input from a device, system, or process. | 
| LogRhythm.AlarmEvents.bytesOut | Unknown | The number of bytes sent from a device, system, or process. | 
| LogRhythm.AlarmEvents.classificationId | Number | The alarm event classification ID. | 
| LogRhythm.AlarmEvents.classificationName | String | The alarm event classification name. | 
| LogRhythm.AlarmEvents.classificationTypeName | String | The alarm event classification type. | 
| LogRhythm.AlarmEvents.command | String | The specific command executed that was recorded in the log message. | 
| LogRhythm.AlarmEvents.commonEventId | Number | The common event name. | 
| LogRhythm.AlarmEvents.cve | String | The alarm event CVE. | 
| LogRhythm.AlarmEvents.commonEventName | String | The alarm event name. | 
| LogRhythm.AlarmEvents.count | Number | The number of alarm events. | 
| LogRhythm.AlarmEvents.directionId | Number | The direction by ID of the activity between a log’s origin and impacted zones. | 
| LogRhythm.AlarmEvents.directionName | String | The direction by name of the activity between a log’s origin and impacted zones. Values can be Internal, External, Outbound, Local, or Unknown. | 
| LogRhythm.AlarmEvents.domain | String | The alarm event domain. | 
| LogRhythm.AlarmEvents.duration | Number | The alarm event duration. | 
| LogRhythm.AlarmEvents.entityId | Number | The alarm event entity ID. | 
| LogRhythm.AlarmEvents.entityName | String | The alarm event entity name. | 
| LogRhythm.AlarmEvents.group | String | The alarm event group. | 
| LogRhythm.AlarmEvents.impactedEntityId | Number | The ID of the entity that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedEntityName | String | The name of the entity that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedHostId | Number | The ID of the host that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedHostName | String | The name of the host that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedInterface | String | The interface that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedIP | Unknown | The IP address that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.countryCode | String | The country code of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.name | String | The country name of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.latitude | Number | The latitude of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.locationId | Number | The ID of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.locationKey | String | The key of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.longitude | Number | The longitude of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.parentLocationId | Number | The parent location ID of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.recordStatus | String | The record status of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.regionCode | String | The region code of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.type | String | The type of the location that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedLocation.dateUpdated | Date | The date the impacted location was last updated. | 
| LogRhythm.AlarmEvents.impactedMAC | String | The MAC that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedName | String | The name of the event that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNATIP | String | The NAT IP address that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNATPort | Unknown | The NAT port that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.beginIPRange.value | String | The beginning of the IP range for the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.dateUpdated | Date | The date the impacted network was last updated. | 
| LogRhythm.AlarmEvents.impactedNetwork.riskThreshold | String | The risk threshold of the network impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.endIPRange.value | String | The end of the IP range for the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.entityId | Number | The ID of the entity for the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.hostZone | String | The host zone for the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.locationId | Number | The location ID of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.longDesc | String | The long description of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.name | String | The name of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.networkId | Number | The ID of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.recordStatus | String | The status of the record of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedNetwork.shortDesc | String | The short description of the network that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedPort | Number | The port that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.impactedZone | String | The zone that was impacted by the alarm. | 
| LogRhythm.AlarmEvents.itemsPacketsIn | Number | Items such as packets received or input from a device, system, or process. | 
| LogRhythm.AlarmEvents.itemsPacketsOut | Number | Items such as packets sent from a device, system, or process. | 
| LogRhythm.AlarmEvents.logDate | Date | The event log date. | 
| LogRhythm.AlarmEvents.login | String | The user associated with the log activity. | 
| LogRhythm.AlarmEvents.logMessage | String | The event log message. | 
| LogRhythm.AlarmEvents.logSourceHostId | Unknown | The host ID of the log source of the event. | 
| LogRhythm.AlarmEvents.logSourceHostName | String | The log source host name. | 
| LogRhythm.AlarmEvents.logSourceName | String | The log source name. | 
| LogRhythm.AlarmEvents.logSourceTypeName | String | The log source type. | 
| LogRhythm.AlarmEvents.messageId | Number | The event message ID. | 
| LogRhythm.AlarmEvents.mpeRuleId | Number | The event MPE rule ID, | 
| LogRhythm.AlarmEvents.mpeRuleName | String | The event MPE rule name. | 
| LogRhythm.AlarmEvents.normalDateMax | Date | If the message is aggregated, the maximum creation date contained in the group of logs. It can be in UTC or user-selected time zone. | 
| LogRhythm.AlarmEvents.objectName | String | The object name of the event. | 
| LogRhythm.AlarmEvents.objectType | String | The object type of the event. | 
| LogRhythm.AlarmEvents.originEntityId | Number | The origin entity ID of the event. | 
| LogRhythm.AlarmEvents.originEntityName | String | The origin entity name of the event. | 
| LogRhythm.AlarmEvents.originHostId | Number | The host ID of where the event originated. | 
| LogRhythm.AlarmEvents.originHostName | String | The host name of where the event originated. | 
| LogRhythm.AlarmEvents.originInterface | String | The interface of where the event originated. | 
| LogRhythm.AlarmEvents.originIP | Unknown | The IP address of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.countryCode | String | The country code of the  location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.name | String | The name of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.latitude | Number | The latitude of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.locationId | Number | The location ID of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.locationKey | String | The location key of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.longitude | Number | The longitude of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.parentLocationId | Number | The parent location ID of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.recordStatus | String | The record status of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.regionCode | String | The region code of the location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.type | String | The type of location of where the event originated. | 
| LogRhythm.AlarmEvents.originLocation.dateUpdated | Date | The date the location of where the event originated was last updated. | 
| LogRhythm.AlarmEvents.originMAC | String | The MAC address of where the event originated. | 
| LogRhythm.AlarmEvents.originName | String | The name of where the event originated. | 
| LogRhythm.AlarmEvents.originNATIP | String | The NAT IP address of where the event originated. | 
| LogRhythm.AlarmEvents.originNATPort | Unknown | The NAT port of where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.beginIPRange.value | String | The beginning address of the IP range of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.dateUpdated | Date | The date of the network when the event originate was last updated. | 
| LogRhythm.AlarmEvents.originNetwork.riskThreshold | String | The risk threshold of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.endIPRange.value | String | The end of the IP range for the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.entityId | Number | The entity ID of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.hostZone | String | The host zone of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.locationId | Number | The ID of the location of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.longDesc | String | The long description of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.name | String | The name of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.networkId | Number | The ID of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.recordStatus | String | The record status of the network where the event originated. | 
| LogRhythm.AlarmEvents.originNetwork.shortDesc | String | The short description of the network where the event originated. | 
| LogRhythm.AlarmEvents.originPort | Number | The port where the event originated. | 
| LogRhythm.AlarmEvents.originZone | String | The zone where the event originated. | 
| LogRhythm.AlarmEvents.parentProcessId | String | The parent process ID of the event. | 
| LogRhythm.AlarmEvents.parentProcessName | String | The parent process name of the event. | 
| LogRhythm.AlarmEvents.parentProcessPath | String | The parent process path of the event. | 
| LogRhythm.AlarmEvents.policy | String | The event policy. | 
| LogRhythm.AlarmEvents.priority | Number | The event priority. | 
| LogRhythm.AlarmEvents.process | String | The event process. | 
| LogRhythm.AlarmEvents.processId | Number | The event process ID. | 
| LogRhythm.AlarmEvents.protocolId | Number | The event protocol ID. | 
| LogRhythm.AlarmEvents.protocolName | String | The event protocol name. | 
| LogRhythm.AlarmEvents.quantity | Number | The event quantity. | 
| LogRhythm.AlarmEvents.rate | Number | The event rate. | 
| LogRhythm.AlarmEvents.reason | String | The event reason. | 
| LogRhythm.AlarmEvents.recipient | String | The event recipient. | 
| LogRhythm.AlarmEvents.result | String | The event result. | 
| LogRhythm.AlarmEvents.responseCode | String | The event response code. | 
| LogRhythm.AlarmEvents.sender | String | The event sender. | 
| LogRhythm.AlarmEvents.session | String | The event session. | 
| LogRhythm.AlarmEvents.sessionType | String | The event session type. | 
| LogRhythm.AlarmEvents.serialNumber | String | The event serial number. | 
| LogRhythm.AlarmEvents.serviceId | Number | The event service ID. | 
| LogRhythm.AlarmEvents.serviceName | String | The event service name. | 
| LogRhythm.AlarmEvents.severity | String | The event severity. | 
| LogRhythm.AlarmEvents.status | String | The event status. | 
| LogRhythm.AlarmEvents.size | Number | The event size. | 
| LogRhythm.AlarmEvents.subject | String | The event subject. | 
| LogRhythm.AlarmEvents.threatId | String | The event threat ID. | 
| LogRhythm.AlarmEvents.threatName | String | The event threat name. | 
| LogRhythm.AlarmEvents.url | String | The event URL. | 
| LogRhythm.AlarmEvents.userAgent | String | The event user agent. | 
| LogRhythm.AlarmEvents.vendorInfo | String | The event vendor info. | 
| LogRhythm.AlarmEvents.vendorMsgId | String | The event vendor message ID. | 
| LogRhythm.AlarmEvents.version | String | The alarm event version | 
| LogRhythm.AlarmEvents.originUserIdentityName | String | The event origin user identity. | 
| LogRhythm.AlarmEvents.impactedUserIdentityName | String | The event impacted user identity. | 
| LogRhythm.AlarmEvents.originUserIdentityId | Unknown | The event origin user identity ID. | 
| LogRhythm.AlarmEvents.impactedUserIdentityId | Unknown | The event impacted user identity ID. | 
| LogRhythm.AlarmEvents.senderIdentityId | Unknown | The event sender identity ID. | 
| LogRhythm.AlarmEvents.senderIdentityName | String | The event sender identity name. | 
| LogRhythm.AlarmEvents.recipientIdentityId | Unknown | The event recipient identity ID. | 
| LogRhythm.AlarmEvents.recipientIdentityName | String | The event recipient identity. | 


#### Command Example
```!lr-alarm-events-list alarm_id=200```

#### Context Example
```json
{
    "LogRhythm": {
        "AlarmEvents": {
            "account": "",
            "action": "",
            "alarmId": 200,
            "amount": null,
            "bytesIn": null,
            "bytesOut": null,
            "classificationId": 3200,
            "classificationName": "Error",
            "classificationTypeName": "Operations",
            "command": "",
            "commonEventId": -1100003,
            "commonEventName": "LogRhythm Agent Heartbeat Missed",
            "count": 1,
            "cve": "",
            "directionId": 1,
            "directionName": "Local",
            "domain": "",
            "duration": 0,
            "entityId": 2,
            "entityName": "EchoTestEntity",
            "group": "",
            "impactedEntityId": 2,
            "impactedEntityName": "EchoTestEntity",
            "impactedHostId": 3,
            "impactedHostName": "",
            "impactedIP": null,
            "impactedInterface": "",
            "impactedLocation": {
                "countryCode": "",
                "dateUpdated": "0001-01-01T00:00:00",
                "latitude": 0,
                "locationId": 0,
                "locationKey": "",
                "longitude": 0,
                "name": "",
                "parentLocationId": 0,
                "recordStatus": "Deleted",
                "regionCode": "",
                "type": "NULL"
            },
            "impactedMAC": "",
            "impactedNATIP": "",
            "impactedNATPort": null,
            "impactedName": "",
            "impactedNetwork": {
                "beginIPRange": {
                    "value": ""
                },
                "dateUpdated": "0001-01-01T00:00:00",
                "endIPRange": {
                    "value": ""
                },
                "entityId": 0,
                "hostZone": "Unknown",
                "locationId": 0,
                "longDesc": "",
                "name": "",
                "networkId": 0,
                "recordStatus": "Deleted",
                "riskThreshold": "",
                "shortDesc": ""
            },
            "impactedPort": -1,
            "impactedUserIdentityId": null,
            "impactedUserIdentityName": "",
            "impactedZone": "Internal",
            "itemsPacketsIn": 0,
            "itemsPacketsOut": 0,
            "logDate": "2021-08-18T13:05:59.477",
            "logMessage": "A heartbeat message from the LogRhythm System Monitor Agent service was not received in the allotted time.",
            "logSourceHostId": null,
            "logSourceHostName": "",
            "logSourceName": "",
            "logSourceTypeName": "",
            "login": "",
            "messageId": 32077,
            "mpeRuleId": -1,
            "mpeRuleName": "",
            "normalDateMax": "0001-01-01T00:00:00",
            "objectName": "",
            "objectType": "",
            "originEntityId": 2,
            "originEntityName": "EchoTestEntity",
            "originHostId": 3,
            "originHostName": "",
            "originIP": null,
            "originInterface": "",
            "originLocation": {
                "countryCode": "",
                "dateUpdated": "0001-01-01T00:00:00",
                "latitude": 0,
                "locationId": 0,
                "locationKey": "",
                "longitude": 0,
                "name": "",
                "parentLocationId": 0,
                "recordStatus": "Deleted",
                "regionCode": "",
                "type": "NULL"
            },
            "originMAC": "",
            "originNATIP": "",
            "originNATPort": null,
            "originName": "",
            "originNetwork": {
                "beginIPRange": {
                    "value": ""
                },
                "dateUpdated": "0001-01-01T00:00:00",
                "endIPRange": {
                    "value": ""
                },
                "entityId": 0,
                "hostZone": "Unknown",
                "locationId": 0,
                "longDesc": "",
                "name": "",
                "networkId": 0,
                "recordStatus": "Deleted",
                "riskThreshold": "",
                "shortDesc": ""
            },
            "originPort": -1,
            "originUserIdentityId": null,
            "originUserIdentityName": "",
            "originZone": "Internal",
            "parentProcessId": "",
            "parentProcessName": "",
            "parentProcessPath": "",
            "policy": "",
            "priority": 100,
            "process": "",
            "processId": -1,
            "protocolId": -1,
            "protocolName": "",
            "quantity": 0,
            "rate": 0,
            "reason": "",
            "recipient": "",
            "recipientIdentityId": null,
            "recipientIdentityName": "",
            "responseCode": "",
            "result": "",
            "sender": "",
            "senderIdentityId": null,
            "senderIdentityName": "",
            "serialNumber": "",
            "serviceId": -1000004,
            "serviceName": "LogRhythm Agent",
            "session": "",
            "sessionType": "",
            "severity": "",
            "size": 0,
            "status": "",
            "subject": "",
            "threatId": "",
            "threatName": "",
            "url": "",
            "userAgent": "",
            "vendorInfo": "",
            "vendorMsgId": "",
            "version": ""
        }
    }
}
```

#### Human Readable Output

>### Events for alarm 200
>|Common Event Name|Log Message|Priority|Log Date|Impacted Host Id|Impacted Zone|Service Name||Entity Name|Classification Name|Classification Type Name|
>|---|---|---|---|---|---|---|---|---|---|---|
>| LogRhythm Agent Heartbeat Missed | A heartbeat message from the LogRhythm System Monitor Agent service was not received in the allotted time. | 100 | 2021-08-18T13:05:59.477 | 3 | Internal | LogRhythm Agent |  | EchoTestEntity | Error | Operations |


### lr-alarm-summary
***
Get the alarm summary by the specified alarm ID.


#### Base Command

`lr-alarm-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Numeric ID of the alarm to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmSummary.dateInserted | Date | The date the alarm was inserted. | 
| LogRhythm.AlarmSummary.rbpMax | Number | The alarm rbp max. | 
| LogRhythm.AlarmSummary.rbpAvg | Number | The alarm rbp average. | 
| LogRhythm.AlarmSummary.alarmRuleId | Number | The alarm rule ID. | 
| LogRhythm.AlarmSummary.alarmRuleGroup | String | The alarm rule group. | 
| LogRhythm.AlarmSummary.briefDescription | String | The alarm brief description. | 
| LogRhythm.AlarmSummary.additionalDetails | String | The alarm additional details. | 
| LogRhythm.AlarmSummary.alarmId | Number | The alarm ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.msgClassId | Number | The alarm summary message class ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.msgClassName | String | The alarm summary message class name. | 
| LogRhythm.AlarmSummary.alarmEventSummary.commonEventId | Number | The alarm summary common event ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.commonEventName | String | The alarm summary common event name. | 
| LogRhythm.AlarmSummary.alarmEventSummary.originHostId | Number | The alarm summary origin host ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.impactedHostId | Number | The alarm summary impacted host ID | 
| LogRhythm.AlarmSummary.alarmEventSummary.originUser | String | The alarm summary origin user. | 
| LogRhythm.AlarmSummary.alarmEventSummary.impactedUser | String | The alarm summary impacted user. | 
| LogRhythm.AlarmSummary.alarmEventSummary.originUserIdentityId | Unknown | The alarm summary origin user identity ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.impactedUserIdentityId | Unknown | The alarm summary impacted user identity ID. | 
| LogRhythm.AlarmSummary.alarmEventSummary.originUserIdentityName | String | The alarm summary origin user identity name. | 
| LogRhythm.AlarmSummary.alarmEventSummary.impactedUserIdentityName | String | The alarm summary impacted user identity name. | 
| LogRhythm.AlarmSummary.alarmEventSummary.originEntityName | String | The alarm summary origin entity name. | 
| LogRhythm.AlarmSummary.alarmEventSummary.impactedEntityName | String | The alarm summary impacted entity name. | 


#### Command Example
```!lr-alarm-summary alarm_id=200```

#### Context Example
```json
{
    "LogRhythm": {
        "AlarmSummary": {
            "additionalDetails": "Action:\r\n1.  Use LogRhythm to analyze and collect all information regarding the alarm, related events/logs, and surrounding logs from affected sources. \r\n2.  Check System Monitor service health (try restarting). \r\n3.  Check network connectivity between Agent and Mediator. \r\n4.  Check scsm.log for errors. \r\n5.  If the steps above do not provide a solution or if you require assistance, please contact LogRhythm Support.",
            "alarmEventSummary": [
                {
                    "commonEventId": -1100003,
                    "commonEventName": "LogRhythm Agent Heartbeat Missed",
                    "impactedEntityName": "EchoTestEntity",
                    "impactedHostId": 3,
                    "impactedUser": "",
                    "impactedUserIdentityId": null,
                    "impactedUserIdentityName": "",
                    "msgClassId": 3200,
                    "msgClassName": "Error",
                    "originEntityName": "EchoTestEntity",
                    "originHostId": 3,
                    "originUser": "",
                    "originUserIdentityId": null,
                    "originUserIdentityName": ""
                }
            ],
            "alarmId": 200,
            "alarmRuleGroup": "LogRhythm Diagnostics",
            "alarmRuleId": 98,
            "briefDescription": "Alarms on the occurrence of a LogRhythm Agent Heartbeat Missed event which could indicate a LogRhythm Agent going down.",
            "dateInserted": "2021-08-18T13:05:59.683",
            "rbpAvg": 100,
            "rbpMax": 100
        }
    }
}
```

#### Human Readable Output

>### Alarm summary
>|Additional Details|Alarm Id|Alarm Rule Group|Alarm Rule Id|Brief Description|Date Inserted|Rbp Avg|Rbp Max|
>|---|---|---|---|---|---|---|---|
>| Action:<br/>1.  Use LogRhythm to analyze and collect all information regarding the alarm, related events/logs, and surrounding logs from affected sources. <br/>2.  Check System Monitor service health (try restarting). <br/>3.  Check network connectivity between Agent and Mediator. <br/>4.  Check scsm.log for errors. <br/>5.  If the steps above do not provide a solution or if you require assistance, please contact LogRhythm Support. | 200 | LogRhythm Diagnostics | 98 | Alarms on the occurrence of a LogRhythm Agent Heartbeat Missed event which could indicate a LogRhythm Agent going down. | 2021-08-18T13:05:59.683 | 100 | 100 |
>### Alarm event summary
>|Common Event Id|Common Event Name|Impacted Entity Name|Impacted Host Id|Impacted User|Impacted User Identity Id|Impacted User Identity Name|Msg Class Id|Msg Class Name|Origin Entity Name|Origin Host Id|Origin User|Origin User Identity Id|Origin User Identity Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| -1100003 | LogRhythm Agent Heartbeat Missed | EchoTestEntity | 3 |  |  |  | 3200 | Error | EchoTestEntity | 3 |  |  |  |


### lr-alarm-drilldown
***
Gets the drill-down logs per rule block for a specific alarm Id that fired associated with an AIE alarm.


#### Base Command

`lr-alarm-drilldown`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Numeric ID of the alarm to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmDrilldown.AlarmID | Number | The alarm ID. | 
| LogRhythm.AlarmDrilldown.AIERuleID | Number | The alarm AIE rule ID. | 
| LogRhythm.AlarmDrilldown.Status.value | Number | The value of the drilldown request. | 
| LogRhythm.AlarmDrilldown.Status.name | String | The name of the drilldown request. | 
| LogRhythm.AlarmDrilldown.Status.description | String | The description of the drilldown request. | 
| LogRhythm.AlarmDrilldown.RetryCount | Number | The number of times the Data Indexer is queried for the drill-down results. | 
| LogRhythm.AlarmDrilldown.LastDxTimestamp | Date | The timestamp, in UTC, at which the Data Indexer was queried to obtain the drill-down results. | 
| LogRhythm.AlarmDrilldown.DateInserted | Date | The timestamp, in UTC, when the Alarm was added to the cache. | 
| LogRhythm.AlarmDrilldown.AlarmGuid | String | The unique identification of the Alarm GUID. | 
| LogRhythm.AlarmDrilldown.WebConsoleId | String | The unique identification of the Web Console ID. | 
| LogRhythm.AlarmDrilldown.NotificationSent | Boolean | The unique identification of the Alarm GUID. | 
| LogRhythm.AlarmDrilldown.AIEMsgXml | String | The message XML associated with the event that triggered by the AI Engine. | 
| LogRhythm.AlarmDrilldown.EventID | Number | The event ID associated with the AI Engine alarm. | 
| LogRhythm.AlarmDrilldown.NormalMessageDate | Date | The date, in UTC, that specifies the time of occurrence of the log. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.RuleBlockID | Number | The Rule Block Id associated with the AI Engine rule that triggered the alarm. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.RuleBlockTypeID | Number | The type of rule block as specified in the Events Msg XML. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.DrillDownLogs | String | Logs that triggered the AI Engine rule associated with the rule block. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.AIECount | Number | The number of logs identified by the AI Engine that triggered the alarm. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.DXCount | Number | The number of logs stored in the Data Indexer that matched the drill-down criteria. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.NormalMessageDate | Date | The date, in UTC, that specifies the time of occurence of the log. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.NormalMessageDateUpper | Date | The date, in UTC, that specifies the upper bound for the rule block triggered. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.NormalMessageDateLower | Date | The date, in UTC, that specifies the lower bound for the rule block triggered. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.DDSummaries.SummaryFieldType | Number | The Summary Field type selected for the rule block. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.DDSummaries.DrillDownSummaries | String | The aggregate of the Summary Field type as found in the drill-down logs associated with the alarm. | 
| LogRhythm.AlarmDrilldown.RuleBlocks.DDSummaries.DefaultValue | String | The value populated from the ARM when an alarm is added to the cache. | 


### lr-get-alarm-details
***
Get the details of an alarm by the specified alarm ID.


#### Base Command

`lr-get-alarm-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarm_id | Numeric ID of the alarm to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmDetails.alarmId | Number | The alarm ID. | 
| LogRhythm.AlarmDetails.personId | Number | The person ID. | 
| LogRhythm.AlarmDetails.entityId | Number | The entity ID. | 
| LogRhythm.AlarmDetails.entityName | String | The name of the entity. | 
| LogRhythm.AlarmDetails.alarmDate | String | The date in UTC of the alarm. | 
| LogRhythm.AlarmDetails.alarmRuleID | Number | The Rule ID of the rule which triggered the alarm | 
| LogRhythm.AlarmDetails.alarmRuleName | String | The name of the rule which triggered the alarm | 
| LogRhythm.AlarmDetails.alarmStatus | String | The status of the alarm. | 
| LogRhythm.AlarmDetails.alarmStatusName | String | The name for the status of the alarm. | 
| LogRhythm.AlarmDetails.lastUpdatedID | Number | The ID of the last person to update the alarm. | 
| LogRhythm.AlarmDetails.lastUpdatedName | String | The name of the last person to update the alarm. | 
| LogRhythm.AlarmDetails.dateInserted | String | The date in UTC, that the alarm was inserted. | 
| LogRhythm.AlarmDetails.dateUpdated | String | The date in UTC, that the alarm was updated. | 
| LogRhythm.AlarmDetails.associatedCases | String | The cases associated with this alarm. | 
| LogRhythm.AlarmDetails.lastPersonID | Number | The ID of the last person to edit this alarm. | 
| LogRhythm.AlarmDetails.eventCount | Number | The amount of events that triggered this alarm. | 
| LogRhythm.AlarmDetails.eventDateFirst | String | The date in UTC of the first event to trigger this alarm. | 
| LogRhythm.AlarmDetails.eventDateLast | String | The date in UTC of the last event to trigger this alarm. | 
| LogRhythm.AlarmDetails.rBPMax | Number | The maximum Risk Based Priority for this alarm. | 
| LogRhythm.AlarmDetails.rBPAvg | Number | The average Risk Based Priority for this alarm. | 
| LogRhythm.AlarmDetails.executionTarget | Number | The target which the alarm was executed against. | 
| LogRhythm.AlarmDetails.alarmDataCached | String | The cached alarm data. | 

### lr-cases-list
***
Get cases details using filter criteria.


#### Base Command

`lr-cases-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID by which to filter the results. | Optional | 
| timestamp_filter_type | The type by which to filter case results combined with the argument timestamp. Possible values: "updatedAfter", "updatedBefore", "createdAfter", and "createdBefore". Possible values are: updatedAfter, updatedBefore, createdAfter, createdBefore. | Optional | 
| timestamp | The timestamp by which to filter case results combined with the argument timestamp_filter_type. | Optional | 
| priority | The priority by which to filter the results. Possible values: "1", "2", "3", "4", and "5", where 1 is the highest priority. Possible values are: 1, 2, 3, 4, 5. | Optional | 
| status | The status by which to filter the results. Possible values are "1", (created), "2" (completed), "3" (incident), "4" (mitigated), and "5" (resolved). Possible values are: 1, 2, 3, 4, 5. | Optional | 
| owners | A comma-separated list of owner numbers. | Optional | 
| tags | A comma-separated list of  tag numbers. | Optional | 
| text | Filter results that have a case number or name that contains the specified value. | Optional | 
| evidence_type | Filter results that have evidence of the specified type. Possible values: "alarm", "userEvents", "log", no"te, and "file". Possible values are: alarm, userEvents, log, note, file. | Optional | 
| reference_id | Filter results that have evidence with the given reference identifier. For example, an alarm ID. | Optional | 
| external_id | Filter results that have the specified, unique, external identifier. | Optional | 
| offset | The number of cases to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The number of cases to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the case owner is disabled. | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the user who last updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-cases-list priority=5```

#### Context Example
```json
{
    "LogRhythm": {
        "Case": [
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-08-11T14:10:08.617291Z",
                "dateUpdated": "2021-08-31T15:18:26.8118901Z",
                "dueDate": "2021-08-12T14:10:08.617291Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "B055F3D5-6F49-4D94-AEF1-FAEDC4A25251",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test case",
                "number": 4,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Incident",
                    "number": 3
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-08-11T14:19:48.7669718Z",
                "dateUpdated": "2021-08-11T14:19:48.7669718Z",
                "dueDate": "2021-08-12T14:19:48.7669718Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "75081347-EB56-4AEA-A6F9-A6EB6662F48E",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test case from API",
                "number": 5,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-05T10:53:07.0405063Z",
                "dateUpdated": "2021-10-05T10:53:07.0405063Z",
                "dueDate": "2021-10-06T10:53:07.0405063Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "BB8EB00A-F4A7-4710-BB1C-E89DA7BF866B",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test",
                "number": 35,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-06T06:13:06.6792318Z",
                "dateUpdated": "2021-10-06T06:13:06.6792318Z",
                "dueDate": "2021-10-07T06:13:06.6792318Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "5091AD33-E29E-41A4-A975-E792EFCFF8E1",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test",
                "number": 38,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-06T07:57:30.7682964Z",
                "dateUpdated": "2021-10-06T07:57:30.7682964Z",
                "dueDate": "2021-10-07T07:57:30.7682964Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "B9F8031A-7420-4080-96A7-4FF9AB6B6ECF",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test",
                "number": 39,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-06T09:30:58.6568951Z",
                "dateUpdated": "2021-10-06T09:30:58.6568951Z",
                "dueDate": "2021-10-07T09:30:58.6568951Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "9D7AEA2E-F9D4-4787-9A9B-F8F0E9CE817E",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test1111",
                "number": 40,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-06T09:37:39.7847983Z",
                "dateUpdated": "2021-10-06T09:37:39.7847983Z",
                "dueDate": "2021-10-07T09:37:39.7847983Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "805BCD50-D301-4F20-9757-A96AC3B1E52C",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test1111",
                "number": 41,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-06T09:44:06.4646762Z",
                "dateUpdated": "2021-10-06T09:44:06.4646762Z",
                "dueDate": "2021-10-07T09:44:06.4646762Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "FE8A7A3F-2D33-449F-83A5-09D3351E67DC",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test1111",
                "number": 42,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-18T11:45:02.190818Z",
                "dateUpdated": "2021-10-18T11:45:02.190818Z",
                "dueDate": "2021-10-19T11:45:02.190818Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "01825095-3D3E-4082-9F3D-29BC68EBCE9F",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test123123",
                "number": 58,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-19T05:44:36.6091003Z",
                "dateUpdated": "2021-10-19T05:44:36.6091003Z",
                "dueDate": "2021-10-20T05:44:36.6091003Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "97F336B2-D18E-438A-8FB1-7F49DCB0A867",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test777777",
                "number": 59,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            },
            {
                "collaborators": [
                    {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    }
                ],
                "dateClosed": null,
                "dateCreated": "2021-10-19T05:51:51.6372007Z",
                "dateUpdated": "2021-10-19T05:51:51.6372007Z",
                "dueDate": "2021-10-20T05:51:51.6372007Z",
                "entity": {
                    "fullName": "Global Entity",
                    "name": "Global Entity",
                    "number": -100
                },
                "externalId": "",
                "id": "064C632E-E7E8-4913-A123-EB6153FE4BE4",
                "lastUpdatedBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "name": "test777777",
                "number": 60,
                "owner": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "priority": 5,
                "resolution": null,
                "resolutionDateUpdated": null,
                "resolutionLastUpdatedBy": null,
                "status": {
                    "name": "Created",
                    "number": 1
                },
                "summary": "",
                "tags": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Cases
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-11T14:10:08.617291Z | 2021-08-31T15:18:26.8118901Z | 2021-08-12T14:10:08.617291Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | B055F3D5-6F49-4D94-AEF1-FAEDC4A25251 | number: 1<br/>name: LR Soap API<br/>disabled: false | test case | 4 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Incident<br/>number: 3 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-11T14:19:48.7669718Z | 2021-08-11T14:19:48.7669718Z | 2021-08-12T14:19:48.7669718Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 75081347-EB56-4AEA-A6F9-A6EB6662F48E | number: 1<br/>name: LR Soap API<br/>disabled: false | test case from API | 5 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-05T10:53:07.0405063Z | 2021-10-05T10:53:07.0405063Z | 2021-10-06T10:53:07.0405063Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | BB8EB00A-F4A7-4710-BB1C-E89DA7BF866B | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 35 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-06T06:13:06.6792318Z | 2021-10-06T06:13:06.6792318Z | 2021-10-07T06:13:06.6792318Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 5091AD33-E29E-41A4-A975-E792EFCFF8E1 | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 38 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-06T07:57:30.7682964Z | 2021-10-06T07:57:30.7682964Z | 2021-10-07T07:57:30.7682964Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | B9F8031A-7420-4080-96A7-4FF9AB6B6ECF | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 39 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-06T09:30:58.6568951Z | 2021-10-06T09:30:58.6568951Z | 2021-10-07T09:30:58.6568951Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 9D7AEA2E-F9D4-4787-9A9B-F8F0E9CE817E | number: 1<br/>name: LR Soap API<br/>disabled: false | test1111 | 40 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-06T09:37:39.7847983Z | 2021-10-06T09:37:39.7847983Z | 2021-10-07T09:37:39.7847983Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 805BCD50-D301-4F20-9757-A96AC3B1E52C | number: 1<br/>name: LR Soap API<br/>disabled: false | test1111 | 41 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-06T09:44:06.4646762Z | 2021-10-06T09:44:06.4646762Z | 2021-10-07T09:44:06.4646762Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | FE8A7A3F-2D33-449F-83A5-09D3351E67DC | number: 1<br/>name: LR Soap API<br/>disabled: false | test1111 | 42 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-18T11:45:02.190818Z | 2021-10-18T11:45:02.190818Z | 2021-10-19T11:45:02.190818Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 01825095-3D3E-4082-9F3D-29BC68EBCE9F | number: 1<br/>name: LR Soap API<br/>disabled: false | test123123 | 58 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-19T05:44:36.6091003Z | 2021-10-19T05:44:36.6091003Z | 2021-10-20T05:44:36.6091003Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 97F336B2-D18E-438A-8FB1-7F49DCB0A867 | number: 1<br/>name: LR Soap API<br/>disabled: false | test777777 | 59 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-19T05:51:51.6372007Z | 2021-10-19T05:51:51.6372007Z | 2021-10-20T05:51:51.6372007Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity |  | 064C632E-E7E8-4913-A123-EB6153FE4BE4 | number: 1<br/>name: LR Soap API<br/>disabled: false | test777777 | 60 | number: 1<br/>name: LR Soap API<br/>disabled: false | 5 |  |  |  | name: Created<br/>number: 1 |  |  |


### lr-case-create
***
Create a new case.


#### Base Command

`lr-case-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the case. | Required | 
| priority | The priority by which to filter the results. Possible values: "1", "2", "3", "4", and "5", where 1 is the highest priority. Possible values are: 1, 2, 3, 4, 5. | Required | 
| external_id | Externally defined identifier for the case. | Optional | 
| due_date | The timedate of when the case is due, as an RFC 3339 formatted string. E.g., 2020-04-20T14:15:22Z. | Optional | 
| summary | Note summarizing the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the owner is disabled. | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-case-create name=test priority=1 external_id=8200 summary=`test case````

#### Context Example
```json
{
    "LogRhythm": {
        "Case": {
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "dateClosed": null,
            "dateCreated": "2021-10-30T20:33:44.6636405Z",
            "dateUpdated": "2021-10-30T20:33:44.6636405Z",
            "dueDate": "2021-10-31T20:33:44.6636405Z",
            "entity": {
                "fullName": "Global Entity",
                "name": "Global Entity",
                "number": -100
            },
            "externalId": "8200",
            "id": "83E66AB6-5F9A-441E-BF96-52CA53E20BEA",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "name": "test",
            "number": 98,
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "priority": 1,
            "resolution": null,
            "resolutionDateUpdated": null,
            "resolutionLastUpdatedBy": null,
            "status": {
                "name": "Created",
                "number": 1
            },
            "summary": "test case",
            "tags": []
        }
    }
}
```

#### Human Readable Output

>### Case created successfully
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-10-30T20:33:44.6636405Z | 2021-10-30T20:33:44.6636405Z | 2021-10-31T20:33:44.6636405Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity | 8200 | 83E66AB6-5F9A-441E-BF96-52CA53E20BEA | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 98 | number: 1<br/>name: LR Soap API<br/>disabled: false | 1 |  |  |  | name: Created<br/>number: 1 | test case |  |


### lr-case-update
***
Update case information. For example, the case name, priority, and due date.


#### Base Command

`lr-case-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| name | Name of the case. | Optional | 
| priority | The priority of the case. Possible values: "1", "2", "3", "4", and "5", where 1 is the highest priority. Possible values are: 1, 2, 3, 4, 5. | Optional | 
| external_id | Externally defined identifier for the case. | Optional | 
| due_date | The timedate of when the case is due, as an RFC 3339 formatted string. E.g., 2020-04-20T14:15:22Z. | Optional | 
| summary | Note summarizing the case. | Optional | 
| entity_id | Entity to assign to the case. | Optional | 
| resolution | Description of how the case was resolved. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the owner is disabled. | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-case-update case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE priority=3```

#### Context Example
```json
{
    "LogRhythm": {
        "Case": {
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "dateClosed": null,
            "dateCreated": "2021-08-19T15:38:07.8995494Z",
            "dateUpdated": "2021-08-31T15:31:24.9870972Z",
            "dueDate": "2021-08-20T15:38:07.8995494Z",
            "entity": {
                "fullName": "Global Entity",
                "name": "Global Entity",
                "number": -100
            },
            "externalId": "9930",
            "id": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "name": "test",
            "number": 17,
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "priority": 3,
            "resolution": null,
            "resolutionDateUpdated": null,
            "resolutionLastUpdatedBy": null,
            "status": {
                "name": "Incident",
                "number": 3
            },
            "summary": "test case",
            "tags": []
        }
    }
}
```

#### Human Readable Output

>### Case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE updated successfully
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-19T15:38:07.8995494Z | 2021-08-31T15:31:24.9870972Z | 2021-08-20T15:38:07.8995494Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity | 9930 | 2E7FA20D-191E-4733-B7DC-A18BBFE762CE | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 17 | number: 1<br/>name: LR Soap API<br/>disabled: false | 3 |  |  |  | name: Incident<br/>number: 3 | test case |  |


### lr-case-status-change
***
Update the status of a case.


#### Base Command

`lr-case-status-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| status | The case status. Possible values: "Created", "Completed", "Incident", "Mitigated", and "Resolved". Possible values are: Created, Completed, Incident, Mitigated, Resolved. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the owner is disabled. | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-case-status-change case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE status=Incident```

#### Context Example
```json
{
    "LogRhythm": {
        "Case": {
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "dateClosed": null,
            "dateCreated": "2021-08-19T15:38:07.8995494Z",
            "dateUpdated": "2021-08-31T15:31:24.9870972Z",
            "dueDate": "2021-08-20T15:38:07.8995494Z",
            "entity": {
                "fullName": "Global Entity",
                "name": "Global Entity",
                "number": -100
            },
            "externalId": "9930",
            "id": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "name": "test",
            "number": 17,
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "priority": 3,
            "resolution": null,
            "resolutionDateUpdated": null,
            "resolutionLastUpdatedBy": null,
            "status": {
                "name": "Incident",
                "number": 3
            },
            "summary": "test case",
            "tags": []
        }
    }
}
```

#### Human Readable Output

>### Case status updated successfully
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-19T15:38:07.8995494Z | 2021-08-31T15:31:24.9870972Z | 2021-08-20T15:38:07.8995494Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity | 9930 | 2E7FA20D-191E-4733-B7DC-A18BBFE762CE | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 17 | number: 1<br/>name: LR Soap API<br/>disabled: false | 3 |  |  |  | name: Incident<br/>number: 3 | test case |  |


### lr-case-evidence-list
***
Return a list of evidence summaries for a case.


#### Base Command

`lr-case-evidence-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| evidence_type | Filter results that have evidence of the specified type. Possible values are: "alarm", "userEvents", "log", "note", and "file". Possible values are: alarm, userEvents, log, note, file. | Optional | 
| status | Filter results that have a specific evidence status. Possible values: "pending", "completed", and "failed". Possible values are: pending, completed, failed. | Optional | 
| evidence_number | Filter results by evidence number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.CaseEvidence.CaseID | String | The case ID. | 
| LogRhythm.CaseEvidence.Evidences.number | Number | The evidence number. | 
| LogRhythm.CaseEvidence.Evidences.dateCreated | Date | The date the evidence was created. | 
| LogRhythm.CaseEvidence.Evidences.dateUpdated | Date | The date the evidence was updated. | 
| LogRhythm.CaseEvidence.Evidences.createdBy.number | Number | The ID of the user who created the evidence. | 
| LogRhythm.CaseEvidence.Evidences.createdBy.name | String | The name of the user who created the evidence. | 
| LogRhythm.CaseEvidence.Evidences.createdBy.disabled | Boolean | Whether the user is disabled. | 
| LogRhythm.CaseEvidence.Evidences.lastUpdatedBy.number | Number | The ID of the user who last updated the case evidence. | 
| LogRhythm.CaseEvidence.Evidences.lastUpdatedBy.name | String | The name of the user who last updated the case evidence. | 
| LogRhythm.CaseEvidence.Evidences.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case evidence is disabled. | 
| LogRhythm.CaseEvidence.Evidences.type | String | The evidence type. | 
| LogRhythm.CaseEvidence.Evidences.status | String | The evidence status | 
| LogRhythm.CaseEvidence.Evidences.statusMessage | Unknown | The evidence status message. | 
| LogRhythm.CaseEvidence.Evidences.text | String | The evidence text. | 
| LogRhythm.CaseEvidence.Evidences.pinned | Boolean | Whether the evidence is pinned. | 
| LogRhythm.CaseEvidence.Evidences.datePinned | Unknown | The date the evidence was pinned. | 


#### Command Example
```!lr-case-evidence-list case_id=583A7DAA-872A-4ECE-80B8-0DECB6FC3061```

#### Context Example
```json
{
    "LogRhythm": {
        "CaseEvidence": {
            "CaseID": "583A7DAA-872A-4ECE-80B8-0DECB6FC3061",
            "Evidences": [
                {
                    "alarm": {
                        "alarmDate": "2021-08-19T13:08:08.713Z",
                        "alarmId": 212,
                        "alarmRuleId": 98,
                        "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                        "dateInserted": "2021-08-19T13:08:08.727Z",
                        "entityId": 2,
                        "entityName": "EchoTestEntity",
                        "riskBasedPriorityMax": 39
                    },
                    "createdBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "dateCreated": "2021-08-19T14:21:01.7066667Z",
                    "datePinned": null,
                    "dateUpdated": "2021-08-19T14:21:01.7066667Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "number": 58,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "",
                    "type": "alarm"
                },
                {
                    "alarm": {
                        "alarmDate": "2021-08-19T11:07:56.86Z",
                        "alarmId": 211,
                        "alarmRuleId": 98,
                        "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                        "dateInserted": "2021-08-19T11:07:56.877Z",
                        "entityId": 2,
                        "entityName": "EchoTestEntity",
                        "riskBasedPriorityMax": 39
                    },
                    "createdBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "dateCreated": "2021-08-19T14:21:11.7766667Z",
                    "datePinned": null,
                    "dateUpdated": "2021-08-19T14:21:11.7766667Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "number": 59,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "",
                    "type": "alarm"
                },
                {
                    "createdBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "dateCreated": "2021-08-19T14:25:33.5976206Z",
                    "datePinned": null,
                    "dateUpdated": "2021-08-19T14:25:33.5976206Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LogRhythm Administrator",
                        "number": -100
                    },
                    "number": 61,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "test note",
                    "type": "note"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Evidences for case 583A7DAA-872A-4ECE-80B8-0DECB6FC3061
>|Number|Type|Status|Date Created|Created By|Text|Alarm|File|
>|---|---|---|---|---|---|---|---|
>| 58 | alarm | completed | 2021-08-19T14:21:01.7066667Z | number: -100<br/>name: LogRhythm Administrator<br/>disabled: false |  | alarmId: 212<br/>alarmDate: 2021-08-19T13:08:08.713Z<br/>alarmRuleId: 98<br/>alarmRuleName: LogRhythm Agent Heartbeat Missed<br/>dateInserted: 2021-08-19T13:08:08.727Z<br/>entityId: 2<br/>entityName: EchoTestEntity<br/>riskBasedPriorityMax: 39 |  |
>| 59 | alarm | completed | 2021-08-19T14:21:11.7766667Z | number: -100<br/>name: LogRhythm Administrator<br/>disabled: false |  | alarmId: 211<br/>alarmDate: 2021-08-19T11:07:56.86Z<br/>alarmRuleId: 98<br/>alarmRuleName: LogRhythm Agent Heartbeat Missed<br/>dateInserted: 2021-08-19T11:07:56.877Z<br/>entityId: 2<br/>entityName: EchoTestEntity<br/>riskBasedPriorityMax: 39 |  |
>| 61 | note | completed | 2021-08-19T14:25:33.5976206Z | number: -100<br/>name: LogRhythm Administrator<br/>disabled: false | test note |  |  |


### lr-case-alarm-evidence-add
***
Add multiple alarms as evidence on a case.


#### Base Command

`lr-case-alarm-evidence-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| alarm_numbers | A comma-separated list of alarm IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.AlarmEvidence.CaseID | String | The case ID. | 
| LogRhythm.AlarmEvidence.Evidences.number | Number | The evidence number. | 
| LogRhythm.AlarmEvidence.Evidences.dateCreated | Date | The date the evidence was created. | 
| LogRhythm.AlarmEvidence.Evidences.dateUpdated | Date | The date the evidence was updated. | 
| LogRhythm.AlarmEvidence.Evidences.createdBy.number | Number | The ID of the user who created the evidence. | 
| LogRhythm.AlarmEvidence.Evidences.createdBy.name | String | The name of the user who created the evidence. | 
| LogRhythm.AlarmEvidence.Evidences.createdBy.disabled | Boolean | Whether the user is disabled. | 
| LogRhythm.AlarmEvidence.Evidences.lastUpdatedBy.number | Number | The ID of the user who last updated the alarm evidence. | 
| LogRhythm.AlarmEvidence.Evidences.lastUpdatedBy.name | String | The name of the user who last updated the alarm evidence. | 
| LogRhythm.AlarmEvidence.Evidences.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the alarm evidence is disabled. | 
| LogRhythm.AlarmEvidence.Evidences.type | String | The evidence type. | 
| LogRhythm.AlarmEvidence.Evidences.status | String | The evidence status | 
| LogRhythm.AlarmEvidence.Evidences.statusMessage | Unknown | The evidence status message. | 
| LogRhythm.AlarmEvidence.Evidences.text | String | The evidence text. | 
| LogRhythm.AlarmEvidence.Evidences.pinned | Boolean | Whether the evidence is pinned. | 
| LogRhythm.AlarmEvidence.Evidences.datePinned | Unknown | The date the evidence was pinned. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.alarmId | Number | The alarm ID. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.alarmDate | Date | The alarm date. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.alarmRuleId | Number | The alarm rule ID. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.alarmRuleName | String | The alarm rule name. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.dateInserted | Date | The date the alarm was inserted. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.entityId | Number | The alarm entity ID. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.entityName | String | The alarm entity name. | 
| LogRhythm.AlarmEvidence.Evidences.alarm.riskBasedPriorityMax | Number | The maximum Risk Based Priority \(RBP\) threshold of events to monitor. | 


#### Command Example
```!lr-case-alarm-evidence-add case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE alarm_numbers=200,201```

#### Context Example
```json
{
    "LogRhythm": {
        "AlarmEvidence": {
            "CaseID": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "Evidences": [
                {
                    "alarm": {
                        "alarmDate": "2021-08-18T13:05:59.663Z",
                        "alarmId": 200,
                        "alarmRuleId": 98,
                        "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                        "dateInserted": "2021-08-18T13:05:59.683Z",
                        "entityId": 2,
                        "entityName": "EchoTestEntity",
                        "riskBasedPriorityMax": 100
                    },
                    "createdBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "dateCreated": "2021-08-19T15:41:35.54Z",
                    "datePinned": null,
                    "dateUpdated": "2021-08-19T15:41:35.54Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "number": 62,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "",
                    "type": "alarm"
                },
                {
                    "alarm": {
                        "alarmDate": "2021-08-18T15:06:10.623Z",
                        "alarmId": 201,
                        "alarmRuleId": 98,
                        "alarmRuleName": "LogRhythm Agent Heartbeat Missed",
                        "dateInserted": "2021-08-18T15:06:10.637Z",
                        "entityId": 2,
                        "entityName": "EchoTestEntity",
                        "riskBasedPriorityMax": 39
                    },
                    "createdBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "dateCreated": "2021-08-19T15:41:35.54Z",
                    "datePinned": null,
                    "dateUpdated": "2021-08-19T15:41:35.54Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "number": 63,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "",
                    "type": "alarm"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Alarms added as evidence to case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE successfully
>|Number|Type|Status|Date Created|Created By|Text|Alarm|File|
>|---|---|---|---|---|---|---|---|
>| 62 | alarm | completed | 2021-08-19T15:41:35.54Z | number: 1<br/>name: LR Soap API<br/>disabled: false |  | alarmId: 200<br/>alarmDate: 2021-08-18T13:05:59.663Z<br/>alarmRuleId: 98<br/>alarmRuleName: LogRhythm Agent Heartbeat Missed<br/>dateInserted: 2021-08-18T13:05:59.683Z<br/>entityId: 2<br/>entityName: EchoTestEntity<br/>riskBasedPriorityMax: 100 |  |
>| 63 | alarm | completed | 2021-08-19T15:41:35.54Z | number: 1<br/>name: LR Soap API<br/>disabled: false |  | alarmId: 201<br/>alarmDate: 2021-08-18T15:06:10.623Z<br/>alarmRuleId: 98<br/>alarmRuleName: LogRhythm Agent Heartbeat Missed<br/>dateInserted: 2021-08-18T15:06:10.637Z<br/>entityId: 2<br/>entityName: EchoTestEntity<br/>riskBasedPriorityMax: 39 |  |


### lr-case-note-evidence-add
***
Add a note as evidence on a case.


#### Base Command

`lr-case-note-evidence-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| note | Note text. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.NoteEvidence.CaseID | String | The case ID. | 
| LogRhythm.NoteEvidence.Evidences.number | Number | The evidence number. | 
| LogRhythm.NoteEvidence.Evidences.dateCreated | Date | The date the evidence was created. | 
| LogRhythm.NoteEvidence.Evidences.dateUpdated | Date | The date the evidence was updated. | 
| LogRhythm.NoteEvidence.Evidences.createdBy.number | Number | The ID of the user who created the evidence. | 
| LogRhythm.NoteEvidence.Evidences.createdBy.name | String | The name of the user who created the evidence. | 
| LogRhythm.NoteEvidence.Evidences.createdBy.disabled | Boolean | Whether the user is disabled. | 
| LogRhythm.NoteEvidence.Evidences.lastUpdatedBy.number | Number | The ID of the user who last updated the evidence. | 
| LogRhythm.NoteEvidence.Evidences.lastUpdatedBy.name | String | The name of the user who last updated the evidence. | 
| LogRhythm.NoteEvidence.Evidences.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the evidence is disabled. | 
| LogRhythm.NoteEvidence.Evidences.type | String | The evidence type. | 
| LogRhythm.NoteEvidence.Evidences.status | String | The evidence status, | 
| LogRhythm.NoteEvidence.Evidences.statusMessage | Unknown | The evidence status message. | 
| LogRhythm.NoteEvidence.Evidences.text | String | The evidence text. | 
| LogRhythm.NoteEvidence.Evidences.pinned | Boolean | Whether the evidence is pinned. | 
| LogRhythm.NoteEvidence.Evidences.datePinned | Unknown | The date the evidence was pinned. | 


#### Command Example
```!lr-case-note-evidence-add case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE note=test```

#### Context Example
```json
{
    "LogRhythm": {
        "NoteEvidence": [
            {
                "CaseID": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
                "Evidences": {
                    "createdBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "dateCreated": "2021-10-30T20:17:09.2251906Z",
                    "datePinned": null,
                    "dateUpdated": "2021-10-30T20:17:09.2251906Z",
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "number": 243,
                    "pinned": false,
                    "status": "completed",
                    "statusMessage": null,
                    "text": "test",
                    "type": "note"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Note added as evidence to case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE successfully
>|Number|Type|Status|Date Created|Created By|Text|Alarm|File|
>|---|---|---|---|---|---|---|---|
>| 243 | note | completed | 2021-10-30T20:17:09.2251906Z | number: 1<br/>name: LR Soap API<br/>disabled: false | test |  |  |


### lr-case-file-evidence-add
***
Upload a file as evidence on a case.


#### Base Command

`lr-case-file-evidence-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case,. | Required | 
| entryId | The entry ID of the file to attach. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.FileEvidence.CaseID | String | The case ID. | 
| LogRhythm.FileEvidence.Evidences.number | Number | The evidence number. | 
| LogRhythm.FileEvidence.Evidences.dateCreated | Date | The date the evidence was created. | 
| LogRhythm.FileEvidence.Evidences.dateUpdated | Date | The date the evidence was updated. | 
| LogRhythm.FileEvidence.Evidences.createdBy.number | Number | The ID of the user who created the evidence. | 
| LogRhythm.FileEvidence.Evidences.createdBy.name | String | The name of the user who created the evidence. | 
| LogRhythm.FileEvidence.Evidences.createdBy.disabled | Boolean | Whether the user is disabled. | 
| LogRhythm.FileEvidence.Evidences.lastUpdatedBy.number | Number | The ID of the user who last updated the evidence. | 
| LogRhythm.FileEvidence.Evidences.lastUpdatedBy.name | String | The name of the user who last updated the evidence. | 
| LogRhythm.FileEvidence.Evidences.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the evidence is disabled. | 
| LogRhythm.FileEvidence.Evidences.type | String | The evidence type. | 
| LogRhythm.FileEvidence.Evidences.status | String | The evidence status | 
| LogRhythm.FileEvidence.Evidences.statusMessage | Unknown | The evidence status message. | 
| LogRhythm.FileEvidence.Evidences.text | String | The evidence text. | 
| LogRhythm.FileEvidence.Evidences.pinned | Boolean | Whether the evidence is pinned. | 
| LogRhythm.FileEvidence.Evidences.datePinned | Unknown | The date the evidence was pinned. | 


#### Command Example
```!lr-case-file-evidence-add case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE entryId=8502@383ed6ae-1fd7-431a-858d-a11f2620c73b```

#### Context Example
```json
{
    "LogRhythm": {
        "FileEvidence": [
            {
                "CaseID": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
                "Evidences": {
                    "createdBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "dateCreated": "2021-10-30T20:33:46.8Z",
                    "datePinned": null,
                    "dateUpdated": "2021-10-30T20:33:46.8Z",
                    "file": {
                        "name": "File.jpeg",
                        "size": 170781
                    },
                    "lastUpdatedBy": {
                        "disabled": false,
                        "name": "LR Soap API",
                        "number": 1
                    },
                    "number": 244,
                    "pinned": false,
                    "status": "pending",
                    "statusMessage": null,
                    "text": "",
                    "type": "file"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### File added as evidence to case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE successfully
>|Number|Type|Status|Date Created|Created By|Text|Alarm|File|
>|---|---|---|---|---|---|---|---|
>| 244 | file | pending | 2021-10-30T20:33:46.8Z | number: 1<br/>name: LR Soap API<br/>disabled: false |  |  | name: File.jpeg<br/>size: 170781 |


### lr-case-evidence-delete
***
Remove evidence from a case.


#### Base Command

`lr-case-evidence-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| evidence_number | Unique, numeric identifier for the evidence to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lr-case-evidence-delete case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE evidence_number=65```

#### Human Readable Output

>Evidence deleted successfully from case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE.

### lr-case-file-evidence-download
***
Download an item of file evidence from a case.


#### Base Command

`lr-case-file-evidence-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| evidence_number | Unique, numeric identifier for the evidence. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lr-case-file-evidence-download case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE evidence_number=66```

#### Context Example
```json
{
    "File": {
        "EntryID": "8420@383ed6ae-1fd7-431a-858d-a11f2620c73b",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "0f9e8a7d9e49fee24f6a34424ad45662",
        "Name": "IMG_20210723_165057.jpg",
        "SHA1": "SHA1",
        "SHA256": "SHA256",
        "SHA512": "SHA512",
        "SSDeep": "SSDeep",
        "Size": 3021461,
        "Type": "JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=12, height=2112, manufacturer=OnePlus, model=ONEPLUS A6013, orientation=upper-left, xresolution=180, yresolution=188, resolutionunit=2, datetime=2021:07:23 16:50:59, GPS-Data, width=4608], baseline, precision 8, 4608x2112, frames 3"
    }
}
```

#### Human Readable Output



### lr-case-tags-add
***
Add tags to a case.


#### Base Command

`lr-case-tags-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| tag_numbers | A comma-separated list of tag numbers to add. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the owner is disabled or not | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-case-tags-add case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE tag_numbers=2,3```

#### Context Example
```json
{
    "LogRhythm": {
        "Case": {
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "dateClosed": null,
            "dateCreated": "2021-08-19T15:38:07.8995494Z",
            "dateUpdated": "2021-10-30T20:17:15.9861818Z",
            "dueDate": "2021-08-20T15:38:07.8995494Z",
            "entity": {
                "fullName": "Global Entity",
                "name": "Global Entity",
                "number": -100
            },
            "externalId": "9930",
            "id": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "name": "test",
            "number": 17,
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "priority": 3,
            "resolution": null,
            "resolutionDateUpdated": null,
            "resolutionLastUpdatedBy": null,
            "status": {
                "name": "Incident",
                "number": 3
            },
            "summary": "test case",
            "tags": [
                {
                    "number": 2,
                    "text": "tag #2"
                },
                {
                    "number": 3,
                    "text": "tag #3"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Tags added successfully to case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-19T15:38:07.8995494Z | 2021-10-30T20:17:15.9861818Z | 2021-08-20T15:38:07.8995494Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity | 9930 | 2E7FA20D-191E-4733-B7DC-A18BBFE762CE | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 17 | number: 1<br/>name: LR Soap API<br/>disabled: false | 3 |  |  |  | name: Incident<br/>number: 3 | test case | {'number': 2, 'text': 'tag #2'},<br/>{'number': 3, 'text': 'tag #3'} |


### lr-case-tags-remove
***
Remove tags from a case.


#### Base Command

`lr-case-tags-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| tag_numbers | A comma-separated list of tag numbers to remove. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Case.id | String | The case ID. | 
| LogRhythm.Case.number | Number | The case number. | 
| LogRhythm.Case.externalId | String | The case external ID. | 
| LogRhythm.Case.dateCreated | Date | The date the case was created. | 
| LogRhythm.Case.dateUpdated | Date | The date the case was updated. | 
| LogRhythm.Case.dateClosed | Unknown | The date the case was closed. | 
| LogRhythm.Case.owner.number | Number | The ID of the case owner. | 
| LogRhythm.Case.owner.name | String | The name of the case owner. | 
| LogRhythm.Case.owner.disabled | Boolean | Whether the owner is disabled or not | 
| LogRhythm.Case.lastUpdatedBy.number | Number | The ID of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.name | String | The name of the user who last updated the case. | 
| LogRhythm.Case.lastUpdatedBy.disabled | Boolean | Whether the last user who updated the case is disabled. | 
| LogRhythm.Case.name | String | The case name. | 
| LogRhythm.Case.status.name | String | The case status. | 
| LogRhythm.Case.status.number | Number | The case status number. | 
| LogRhythm.Case.priority | Number | The case priority. | 
| LogRhythm.Case.dueDate | Date |  The datetime the case is due. | 
| LogRhythm.Case.resolution | Unknown | The case resolution. | 
| LogRhythm.Case.resolutionDateUpdated | Unknown | The date the case resolution was last updated. | 
| LogRhythm.Case.resolutionLastUpdatedBy | Unknown | The user who last updated the case resolution. | 
| LogRhythm.Case.summary | String | The case summary. | 
| LogRhythm.Case.entity.number | Number | The case entity number. | 
| LogRhythm.Case.entity.name | String | The case entity name. | 
| LogRhythm.Case.entity.fullName | String | The case entity full name. | 
| LogRhythm.Case.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.Case.collaborators.name | String | The case collaborator name. | 
| LogRhythm.Case.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 
| LogRhythm.Case.tags.text | String | The case tag name. | 
| LogRhythm.Case.tags.number | Number | The case tag number. | 


#### Command Example
```!lr-case-tags-remove case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE tag_numbers=1,2```

#### Context Example
```json
{
    "LogRhythm": {
        "Case": {
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "dateClosed": null,
            "dateCreated": "2021-08-19T15:38:07.8995494Z",
            "dateUpdated": "2021-10-30T20:17:17.3901952Z",
            "dueDate": "2021-08-20T15:38:07.8995494Z",
            "entity": {
                "fullName": "Global Entity",
                "name": "Global Entity",
                "number": -100
            },
            "externalId": "9930",
            "id": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "lastUpdatedBy": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "name": "test",
            "number": 17,
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            },
            "priority": 3,
            "resolution": null,
            "resolutionDateUpdated": null,
            "resolutionLastUpdatedBy": null,
            "status": {
                "name": "Incident",
                "number": 3
            },
            "summary": "test case",
            "tags": [
                {
                    "number": 3,
                    "text": "tag #3"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Tags removed successfully from case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE
>|Collaborators|Date Closed|Date Created|Date Updated|Due Date|Entity|External Id|Id|Last Updated By|Name|Number|Owner|Priority|Resolution|Resolution Date Updated|Resolution Last Updated By|Status|Summary|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'number': 1, 'name': 'LR Soap API', 'disabled': False} |  | 2021-08-19T15:38:07.8995494Z | 2021-10-30T20:17:17.3901952Z | 2021-08-20T15:38:07.8995494Z | number: -100<br/>name: Global Entity<br/>fullName: Global Entity | 9930 | 2E7FA20D-191E-4733-B7DC-A18BBFE762CE | number: 1<br/>name: LR Soap API<br/>disabled: false | test | 17 | number: 1<br/>name: LR Soap API<br/>disabled: false | 3 |  |  |  | name: Incident<br/>number: 3 | test case | {'number': 3, 'text': 'tag #3'} |


### lr-tags-list
***
Return a list of tags using filter criteria.


#### Base Command

`lr-tags-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Filter results that have a tag name that contains the specified value. | Optional | 
| offset | The number of tags to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The numbers of tags to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Tag.number | Number | The tag number. | 
| LogRhythm.Tag.text | String | The tag text. | 
| LogRhythm.Tag.dateCreated | Date | The date the tag was created. | 
| LogRhythm.Tag.createdBy.number | Number | The ID of the user who created the tag. | 
| LogRhythm.Tag.createdBy.name | String | The name of the user who created the tag. | 
| LogRhythm.Tag.createdBy.disabled | Boolean | Whether the user is disabled. | 


#### Command Example
```!lr-tags-list count=2```

#### Context Example
```json
{
    "LogRhythm": {
        "Tag": [
            {
                "createdBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "dateCreated": "2021-08-11T13:44:00.4433333Z",
                "number": 2,
                "text": "tag #2"
            },
            {
                "createdBy": {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                },
                "dateCreated": "2021-08-11T13:44:05.7433333Z",
                "number": 3,
                "text": "tag #3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tags
>|Number|Text|Date Created|Created By|
>|---|---|---|---|
>| 2 | tag #2 | 2021-08-11T13:44:00.4433333Z | number: 1<br/>name: LR Soap API<br/>disabled: false |
>| 3 | tag #3 | 2021-08-11T13:44:05.7433333Z | number: 1<br/>name: LR Soap API<br/>disabled: false |


### lr-case-collaborators-list
***
Returns the owner and a list of collaborators associated with a specific case.


#### Base Command

`lr-case-collaborators-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.CaseCollaborator.CaseID | String | The case ID. | 
| LogRhythm.CaseCollaborator.owner.number | Number | The ID of the case owner. | 
| LogRhythm.CaseCollaborator.owner.name | String | The name of the case owner. | 
| LogRhythm.CaseCollaborator.owner.disabled | Boolean | Whether the owner is disabled. | 
| LogRhythm.CaseCollaborator.collaborators.number | Number | The case collaborator number. | 
| LogRhythm.CaseCollaborator.collaborators.name | String | The case collaborator name. | 
| LogRhythm.CaseCollaborator.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 


#### Command Example
```!lr-case-collaborators-list case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE```

#### Context Example
```json
{
    "LogRhythm": {
        "CaseCollaborator": {
            "CaseID": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Case owner
>|Disabled|Name|Number|
>|---|---|---|
>| false | LR Soap API | 1 |
>### Case collaborators
>|Disabled|Name|Number|
>|---|---|---|
>| false | LR Soap API | 1 |


### lr-case-collaborators-update
***
Updates the owner and collaborators associated with a specific case.


#### Base Command

`lr-case-collaborators-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Unique identifier for the case. | Required | 
| owner | Unique, numeric identifier for the person. | Required | 
| collaborators | A comma-separated list of user IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.CaseCollaborator.CaseID | String | The case ID. | 
| LogRhythm.CaseCollaborator.owner.number | Number | The ID of the case owner. | 
| LogRhythm.CaseCollaborator.owner.name | String | The name of the case owner. | 
| LogRhythm.CaseCollaborator.owner.disabled | Boolean | Whether the owner is disabled. | 
| LogRhythm.CaseCollaborator.collaborators.number | Number | The case collaborator ID. | 
| LogRhythm.CaseCollaborator.collaborators.name | String | The case collaborator name. | 
| LogRhythm.CaseCollaborator.collaborators.disabled | Boolean | Whether the case collaborator is disabled. | 


#### Command Example
```!lr-case-collaborators-update case_id=2E7FA20D-191E-4733-B7DC-A18BBFE762CE collaborators=1 owner=1```

#### Context Example
```json
{
    "LogRhythm": {
        "CaseCollaborator": {
            "CaseID": "2E7FA20D-191E-4733-B7DC-A18BBFE762CE",
            "collaborators": [
                {
                    "disabled": false,
                    "name": "LR Soap API",
                    "number": 1
                }
            ],
            "owner": {
                "disabled": false,
                "name": "LR Soap API",
                "number": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Case 2E7FA20D-191E-4733-B7DC-A18BBFE762CE updated successfully
>### Case owner
>|Disabled|Name|Number|
>|---|---|---|
>| false | LR Soap API | 1 |
>### Case collaborators
>|Disabled|Name|Number|
>|---|---|---|
>| false | LR Soap API | 1 |


### lr-entities-list
***
Returns all Entities that match the specified criteria.


#### Base Command

`lr-entities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_entity_id | Filter by the object parent entity ID. | Optional | 
| entity_id | Filter by the entity ID. | Optional | 
| offset | The number of entities to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The number of entities to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Entity.id | Number | The entity ID. | 
| LogRhythm.Entity.name | String | The entity name. | 
| LogRhythm.Entity.fullName | String | The entity full name. | 
| LogRhythm.Entity.recordStatusName | String | The entity record status. | 
| LogRhythm.Entity.shortDesc | String | The entity short description. | 
| LogRhythm.Entity.dateUpdated | Date | The date the entity was updated. | 


#### Command Example
```!lr-entities-list count=2```

#### Context Example
```json
{
    "LogRhythm": {
        "Entity": [
            {
                "dateUpdated": "2021-10-12T14:01:21.54Z",
                "fullName": "EchoTestEntity",
                "id": 2,
                "name": "EchoTestEntity",
                "recordStatusName": "Active",
                "shortDesc": "LogRhythm ECHO"
            },
            {
                "dateUpdated": "2021-10-27T16:27:14.363Z",
                "fullName": "Global Entity",
                "id": -100,
                "name": "Global Entity",
                "recordStatusName": "Active",
                "shortDesc": "Global entity containing shared network and host records"
            }
        ]
    }
}
```

#### Human Readable Output

>### Entities
>|Id|Name|Full Name|Record Status Name|Short Desc|Date Updated|
>|---|---|---|---|---|---|
>| 2 | EchoTestEntity | EchoTestEntity | Active | LogRhythm ECHO | 2021-10-12T14:01:21.54Z |
>| -100 | Global Entity | Global Entity | Active | Global entity containing shared network and host records | 2021-10-27T16:27:14.363Z |


### lr-hosts-list
***
Returns all hosts that match the specified criteria.


#### Base Command

`lr-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Filter by host ID. | Optional | 
| host_name | Filter by host name. | Optional | 
| entity_name | Filter by entity name. | Optional | 
| record_status | Filter by record status. Possible values: "all", "active", "retired". Possible values are: all, active, retired. | Optional | 
| offset | The number of hosts to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The number of hosts to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Host.id | Number | The host ID. | 
| LogRhythm.Host.entity.id | Number | The host entity ID. | 
| LogRhythm.Host.entity.name | String | The host entity name. | 
| LogRhythm.Host.name | String | The host name. | 
| LogRhythm.Host.riskLevel | String | The host risk level. | 
| LogRhythm.Host.threatLevel | String | The host threat level. | 
| LogRhythm.Host.threatLevelComments | String | The threat level comments | 
| LogRhythm.Host.recordStatusName | String | The host record status name. | 
| LogRhythm.Host.hostZone | String | The host zone. | 
| LogRhythm.Host.location.id | Number | The host location ID. | 
| LogRhythm.Host.os | String | The operating system type supported by LogRhythm. | 
| LogRhythm.Host.useEventlogCredentials | Boolean | Whether to use the event log credentials. | 
| LogRhythm.Host.osType | String | The agent server type on which the operating system is installed. | 
| LogRhythm.Host.dateUpdated | Date | The date the host was updated. | 
| LogRhythm.Host.shortDesc | String | The host short description. | 
| LogRhythm.Host.osVersion | String | The host operation system version. | 
| LogRhythm.Host.hostIdentifiers.type | String | The host identifier type. | 
| LogRhythm.Host.hostIdentifiers.value | String | The host identifier value. | 
| LogRhythm.Host.hostIdentifiers.dateAssigned | Date | The date the host identifier was assigned. | 
| LogRhythm.Host.eventlogPassword | String | The event log password. | 


#### Command Example
```!lr-hosts-list count=2```

#### Context Example
```json
{
    "LogRhythm": {
        "Host": [
            {
                "dateUpdated": "2021-07-27T15:56:14.34Z",
                "entity": {
                    "id": -100,
                    "name": "Global Entity"
                },
                "hostIdentifiers": [],
                "hostRoles": [],
                "hostZone": "Internal",
                "id": -1000001,
                "location": {
                    "id": -1
                },
                "name": "AI Engine Server",
                "os": "Unknown",
                "osType": "Server",
                "recordStatusName": "Active",
                "riskLevel": "None",
                "threatLevel": "None",
                "threatLevelComments": "",
                "useEventlogCredentials": false
            },
            {
                "dateUpdated": "2021-07-27T15:56:14.343Z",
                "entity": {
                    "id": 1,
                    "name": "Primary Site"
                },
                "hostIdentifiers": [],
                "hostRoles": [],
                "hostZone": "Internal",
                "id": -1000002,
                "location": {
                    "id": -1
                },
                "name": "AI Engine Server",
                "os": "Unknown",
                "osType": "Server",
                "recordStatusName": "Active",
                "riskLevel": "None",
                "threatLevel": "None",
                "threatLevelComments": "",
                "useEventlogCredentials": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Hosts
>|Date Updated|Entity|Host Identifiers|Host Roles|Host Zone|Id|Location|Name|Os|Os Type|Record Status Name|Risk Level|Threat Level|Threat Level Comments|Use Eventlog Credentials|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-07-27T15:56:14.34Z | id: -100<br/>name: Global Entity |  |  | Internal | -1000001 | id: -1 | AI Engine Server | Unknown | Server | Active | None | None |  | false |
>| 2021-07-27T15:56:14.343Z | id: 1<br/>name: Primary Site |  |  | Internal | -1000002 | id: -1 | AI Engine Server | Unknown | Server | Active | None | None |  | false |


### lr-users-list
***
Returns user records based on the permissions of the currently logged in user and the specified criteria.


#### Base Command

`lr-users-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | A comma-separated list of user IDs. | Optional | 
| entity_ids | A comma-separated list of entity IDs. | Optional | 
| user_status | Filter by user status. Possible values: "Active" and "Retired". Possible values are: Active, Retired. | Optional | 
| offset | The ID of users to skip before starting to collect the result set. Default is 0. | Optional | 
| count | The IDs of the users to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.User.firstName | String | The user first name. | 
| LogRhythm.User.lastName | String | The user last name. | 
| LogRhythm.User.userType | String | The user type | 
| LogRhythm.User.fullName | String | The user full name. | 
| LogRhythm.User.objectPermissions.readAccess | String | The user read access permissions. | 
| LogRhythm.User.objectPermissions.writeAccess | String | The user write access permissions. | 
| LogRhythm.User.objectPermissions.entity.id | Number | The user permissions entity ID. | 
| LogRhythm.User.objectPermissions.entity.name | String | The user permissions entity name. | 
| LogRhythm.User.objectPermissions.owner.id | Number | The user permissions owner ID. | 
| LogRhythm.User.objectPermissions.owner.name | String | The user permissions owner. | 
| LogRhythm.User.id | Number | The user ID. | 
| LogRhythm.User.recordStatusName | String | The user record status. | 
| LogRhythm.User.dateUpdated | Date | The date the user was updated. | 


#### Command Example
```!lr-users-list count=2```

#### Context Example
```json
{
    "LogRhythm": {
        "User": [
            {
                "dateUpdated": "2021-07-27T20:38:31.443Z",
                "firstName": "",
                "fullName": "LR Soap API",
                "id": 1,
                "lastName": "",
                "objectPermissions": {
                    "entity": {
                        "id": 1,
                        "name": "Primary Site"
                    },
                    "owner": {
                        "id": -100,
                        "name": "LogRhythmAdmin"
                    },
                    "readAccess": "PublicGlobalAdmin",
                    "writeAccess": "PublicGlobalAdmin"
                },
                "recordStatusName": "Active",
                "userType": "Role"
            },
            {
                "dateUpdated": "2021-07-27T15:07:47.05Z",
                "firstName": "LogRhythm",
                "fullName": "LogRhythm Analyst",
                "id": -101,
                "lastName": "Analyst",
                "objectPermissions": {
                    "entity": {
                        "id": -100,
                        "name": "Global Entity"
                    },
                    "owner": {
                        "id": -100,
                        "name": "LogRhythmAdmin"
                    },
                    "readAccess": "PublicAll",
                    "writeAccess": "PublicGlobalAdmin"
                },
                "recordStatusName": "Active",
                "userType": "Role"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>|Id|Full Name|User Type|First Name|Last Name|Record Status Name|Date Updated|Object Permissions|
>|---|---|---|---|---|---|---|---|
>| 1 | LR Soap API | Role |  |  | Active | 2021-07-27T20:38:31.443Z | readAccess: PublicGlobalAdmin<br/>writeAccess: PublicGlobalAdmin<br/>entity: {"id": 1, "name": "Primary Site"}<br/>owner: {"id": -100, "name": "LogRhythmAdmin"} |
>| -101 | LogRhythm Analyst | Role | LogRhythm | Analyst | Active | 2021-07-27T15:07:47.05Z | readAccess: PublicAll<br/>writeAccess: PublicGlobalAdmin<br/>entity: {"id": -100, "name": "Global Entity"}<br/>owner: {"id": -100, "name": "LogRhythmAdmin"} |


### lr-lists-get
***
Returns list details using the filter criteria.


#### Base Command

`lr-lists-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The list type. Possible values: "None", "Application", "Classification", "CommonEvent", "Host", "Location", "MsgSource", "MsgSourceType", "MPERule", "Network", "User", "GeneralValue", "Entity", "RootEntity", "IP", "IPRange", and "Identity". Possible values are: None, Application, Classification, CommonEvent, Host, Location, MsgSource, MsgSourceType, MPERule, Network, User, GeneralValue, Entity, RootEntity, IP, IPRange, Identity. | Optional | 
| list_name | The name of the object or regex match. | Optional | 
| can_edit | Specifies if Write Only (true) or Read Only (false) lists are required for a user. Possible values: "true" and "false". Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.List.listType | String | The list type. | 
| LogRhythm.List.status | String | The list status. | 
| LogRhythm.List.name | String | The list name. | 
| LogRhythm.List.shortDescription | String | The list short description. | 
| LogRhythm.List.useContext | String | The use context type. | 
| LogRhythm.List.autoImportOption.enabled | Boolean | Whether the list auto import is enabled. | 
| LogRhythm.List.autoImportOption.usePatterns | Boolean | Whether the auto import use patterns is enabled. | 
| LogRhythm.List.autoImportOption.replaceExisting | Boolean | Whether the auto import replace existing is enabled. | 
| LogRhythm.List.id | Number | The list ID. | 
| LogRhythm.List.guid | String | The list GUID. | 
| LogRhythm.List.dateCreated | Date | The date the list was created. | 
| LogRhythm.List.dateUpdated | Date | The date the list was updated. | 
| LogRhythm.List.readAccess | String | The read permission level. | 
| LogRhythm.List.writeAccess | String | The write permission level. | 
| LogRhythm.List.restrictedRead | Boolean | Whether the list is read restricted. | 
| LogRhythm.List.entityName | String | The list entity name. | 
| LogRhythm.List.entryCount | Number | The list entry count. | 
| LogRhythm.List.needToNotify | Boolean | Whether the list will notify the user when updated. | 
| LogRhythm.List.doesExpire | Boolean | Whether the list expires. | 
| LogRhythm.List.owner | Number | The ID of the list owner. | 
| LogRhythm.List.longDescription | String | The list long description. | 
| LogRhythm.List.timeToLiveSeconds | Number | The list time for the list to live in seconds. | 
| LogRhythm.List.revisitDate | Date | The list revisit date. | 


#### Command Example
```!lr-lists-get```

#### Context Example
```json
{
    "LogRhythm": {
        "List": [
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2019-11-05T04:11:38.303Z",
                "dateUpdated": "2021-07-27T16:03:30.617Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "B1E34445-2693-411E-8BE2-9B97AFFF20A9",
                "id": -1000130,
                "listType": "GeneralValue",
                "name": "Windows System32 Hashes",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Hashes of executables in the %systemroot%\\system32 directory. Use Case: Masquerading technique in MITRE ATT&CK",
                "status": "Active",
                "useContext": [
                    "Hash"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-07-27T15:07:50.893Z",
                "dateUpdated": "2021-07-27T15:07:50.893Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F205DE21-9F73-462E-8F83-DE64CAD2A401",
                "id": -1000001,
                "listType": "Identity",
                "longDescription": "Anomaly scores from CloudAI will not be displayed for the identities in this list. Identities added to this list will automatically expire 24 hours after they are added.",
                "name": "CloudAI: Ignore for 24 Hours",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Anomaly scores from CloudAI will not be displayed for the identities in this list. Identities added to this list will automatically expire 24 hours after they are added.",
                "status": "Active",
                "timeToLiveSeconds": 86400,
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-07-27T15:07:50.893Z",
                "dateUpdated": "2021-07-27T15:07:50.893Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "5A2E34FB-3AD1-44CB-8E5F-643CAEDD1EC2",
                "id": -1000000,
                "listType": "Identity",
                "longDescription": "Identities monitored by CloudAI",
                "name": "CloudAI: Monitored Identities",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Identities monitored by CloudAI",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2015-06-06T00:15:20.033Z",
                "dateUpdated": "2021-07-27T16:03:30.627Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "6B9A54EF-70C9-49E0-B051-75C363178603",
                "id": -2389,
                "listType": "MsgSource",
                "longDescription": "This list will need to capture all related systems according to their classification as high, medium, or low impacts within the environment. \r\n\r\nThis list is used in the following:\r\n(Reports)\r\nNERC-CIP: Access Failure Summary\r\nNERC-CIP: Default Act Auth/Accs Success Summary\r\nNERC-CIP: Default Act Management Summary\r\nNERC-CIP: Host Authentication Success Summary\r\nNERC-CIP: Non-encrypted protocol\r\nNERC-CIP: Priv Act Auth/Accs Success Summary\r\nNERC-CIP: Priv Act Management Summary\r\nNERC-CIP: Shared Act Auth/Accs Success Summary\r\nNERC-CIP: Shared Act Management Summary\r\nNERC-CIP: Suspicious Activity Summary\r\nNERC-CIP: Term Act Auth/Accs Success Summary\r\nNERC-CIP: Term Act Management Summary\r\nNERC-CIP: Vendor Act Auth/Accs Success Summary\r\nNERC-CIP: Vendor Act Management Summary\r\nNERC-CIP: VPN Node Registration Failure (Auth)\r\nNERC-CIP: VPN Node Registration Failure (un-Auth)\r\n(Investigation)\r\nNERC-CIP: Access Failure Detail\r\nNERC-CIP: Host Authentication Success Detail\r\nNERC-CIP: Priv Group Access Granted Detail\r\nNERC-CIP: Rogue WAP Detected Detail\r\nNERC-CIP: Suspicious Activity Detail\r\nNERC-CIP: VPN Node Registration Failure Detail (Auth)\r\nNERC-CIP: VPN Node Registration Failure Detail (un- Auth)\r\nNERC-CIP: Windows Firewall Change Detail\r\n(AIE Rules)\r\nNERC-CIP: Account Locked or Disabled Rule\r\nNERC-CIP: Attack Detected Rule\r\nNERC-CIP: Compromise Detected Rule\r\nNERC-CIP: Concur VPN From Multiple Country\r\nNERC-CIP: Concur VPN Same User\r\nNERC-CIP: Concurrent VPN From Multiple Cities\r\nNERC-CIP: Concurrent VPN From Multiple Region\r\nNERC-CIP: Config/Policy Change\r\nNERC-CIP: Data Destruction Rule\r\nNERC-CIP: Data Exfiltration Rule\r\nNERC-CIP: Data Loss Prevention Rule\r\nNERC-CIP: ESP Network Allow Egress Rule\r\nNERC-CIP: ESP Network Allow Ingress Rule\r\nNERC-CIP: ESP Network Denied Egress Rule\r\nNERC-CIP: ESP Network Denied Ingress Rule\r\nNERC-CIP: Malware Detected Rule\r\nNERC-CIP: Port Misuse: FTP\r\nNERC-CIP: Port Misuse: HTTP \r\nNERC-CIP: Port Misuse: SSH In\r\nNERC-CIP: Port Misuse: S",
                "name": "NERC-CIP: Electronic Security Perimeter",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This log source list represents various network related systems such as security perimeter enforcing devices (i.e. IPS, firewalls), security perimeter monitoring devices (i.e. IDS),  VPNs, wireless access points, remote access devices, anti-malware, etc. ",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2015-06-05T21:31:30.7Z",
                "dateUpdated": "2021-07-27T16:03:30.64Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F7A6369A-33C3-4249-91EF-6710E13F48F6",
                "id": -2379,
                "listType": "MsgSource",
                "longDescription": "This list will need to capture all related systems according to their classification as high, medium, or low impacts within the environment. \r\n\r\nThis list is used in the following:\r\n(Reports)\r\nNERC-CIP: Access Failure Summary\r\nNERC-CIP: Authentication Failure Summary\r\nNERC-CIP: Change in Software Config (Linux)\r\nNERC-CIP: Change in Software Config (Windows)\r\nNERC-CIP: Default Act Auth/Accs Success Summary\r\nNERC-CIP: Default Act Management Summary\r\nNERC-CIP: Failed File Access (Linux)\r\nNERC-CIP: Failed File Access (Windows)\r\nNERC-CIP: Host Authentication Success Summary\r\nNERC-CIP: Object Creation/Disposal Summary\r\nNERC-CIP: Priv Act Auth/Accs Success Summary\r\nNERC-CIP: Priv Act Management Summary\r\nNERC-CIP: Shared Act Auth/Accs Success Summary\r\nNERC-CIP: Shared Act Management Summary\r\nNERC-CIP: Suspicious Activity Summary\r\nNERC-CIP: Term Act Auth/Accs Success Summary\r\nNERC-CIP: Term Act Management Summary\r\nNERC-CIP: Vendor Act Auth/Accs Success Summary\r\nNERC-CIP: Vendor Act Management Summary\r\n (Investigation)\r\nNERC-CIP: Access Failure Detail\r\nNERC-CIP: Host Authentication Success Detail\r\nNERC-CIP: Priv Group Access Granted Detail\r\nNERC-CIP: Suspicious Activity Detail\r\n (AIE Rules)\r\nNERC-CIP: Account Locked or Disabled Rule\r\nNERC-CIP: Attack Detected Rule\r\nNERC-CIP: Compromise Detected Rule\r\nNERC-CIP: Concur VPN From Multiple Country\r\nNERC-CIP: Concur VPN Same User\r\nNERC-CIP: Concurrent VPN From Multiple Cities\r\nNERC-CIP: Concurrent VPN From Multiple Region\r\nNERC-CIP: Config/Policy Change\r\nNERC-CIP: Data Destruction Rule\r\nNERC-CIP: Data Exfiltration Rule\r\nNERC-CIP: Data Loss Prevention Rule\r\nNERC-CIP: ESP Network Allow Egress Rule\r\nNERC-CIP: ESP Network Allow Ingress Rule\r\nNERC-CIP: ESP Network Denied Egress Rule\r\nNERC-CIP: ESP Network Denied Ingress Rule\r\nNERC-CIP: Malware Detected Rule\r\nNERC-CIP: Port Misuse: FTP\r\nNERC-CIP: Port Misuse: HTTP \r\nNERC-CIP: Port Misuse: SSH In\r\nNERC-CIP: Port Misuse: SSH Out\r\nNERC-CIP: Rogue WAP Detected Rule\r\nNERC-CIP: Software Instal",
                "name": "NERC-CIP: BES Cyber Systems",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This log source list represents various BES Cyber Assets related to IT operations that reflect groupings of the BES Cyber System(s)",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T03:39:14.56Z",
                "dateUpdated": "2021-07-27T16:03:30.663Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "4E629B5B-7D5D-447B-B672-BBCAF8E32E37",
                "id": -2085,
                "listType": "Application",
                "longDescription": "This list is used in the following package elements:  \r\n\nPCI-DSS: Invalid DMZ => Internal Comm AIE Rule\n\r\nPCI-DSS: Invalid DMZ => Internal Comm Details\r\n\nPCI-DSS: Invalid DMZ => Internal Comm Summary\r\n\nPCI-DSS: Invalid DMZ => Internal Comm Detail\n\r\n",
                "name": "PCI-DSS: Allowed DMZ => Internal App List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with the impacted applications, ports, and protocols which are allowed from the demilitarized zone environment to the internal network.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T02:43:14.257Z",
                "dateUpdated": "2021-07-27T16:03:30.683Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "AFD1ACEB-A5CB-4EE7-BB46-331CE023F750",
                "id": -2078,
                "listType": "Network",
                "longDescription": "This list is used in the following package elements:  \r\n\nPCI-DSS: Internal Communication\r\nPCI-DSS: Denied Intrn => Intrn Comm AIE Rule\r\nPCI-DSS: Denied  Intrn => Intrn Comm Detail\n\r\nPCI-DSS: Denied  Intrn => Intrn Comm Details\r\nPCI-DSS: Denied  Intrn => Intrn Comm Summary\r\n\n\nPCI-DSS: Invalid Intrn => Intrn Comm AIE Rule\r\nPCI-DSS: Invalid Intrn => Intrn Comm Detail\n\r\nPCI-DSS: Invalid Intrn => Intrn Comm Details\n\r\nPCI-DSS: Invalid Intrn => Intrn Comm Summary\r\n\nPCI-DSS: Denied Inet => Intrn Comm AIE Rule\r\nPCI-DSS: Denied  Inet => Intrn Comm Detail\n\r\nPCI-DSS: Denied  Inet => Intrn Comm Details\r\nPCI-DSS: Denied  Inet => Intrn Comm Summary\r\n\n\nPCI-DSS: Invalid Inet => Intrn Comm AIE Rule\r\nPCI-DSS: Invalid Inet => Intrn Comm Detail\n\r\nPCI-DSS: Invalid Inet => Intrn Comm Details\n\r\nPCI-DSS: Invalid Inet => Intrn Comm Summary\r\nPCI-DSS: Denied Inet => Intrn Comm AIE Rule\r\nPCI-DSS: Denied Inet => Intrn Comm Detail\n\r\nPCI-DSS: Denied Inet => Intrn Comm Details\r\nPCI-DSS: Denied Inet => Intrn Comm Summary\r\n\n\nPCI-DSS: Invalid Inet => Intrn Comm AIE Rule\r\nPCI-DSS: Invalid Inet => Intrn Comm Detail\n\r\nPCI-DSS: Invalid Inet => Intrn Comm Details\n\r\nPCI-DSS: Invalid Inet => Intrn Comm Summary\r\n\nPCI-DSS: Denied Test => Intrn Comm AIE Rule\r\nPCI-DSS: Denied Test => Intrn Comm Detail\n\r\nPCI-DSS: Denied Test => Intrn Comm Details\r\nPCI-DSS: Denied Test => Intrn Comm Summary\r\n\n\nPCI-DSS: Invalid Test => Intrn Comm AIE Rule\r\nPCI-DSS: Invalid Test => Intrn Comm Detail\n\r\nPCI-DSS: Invalid Test => Intrn Comm Details\n\r\nPCI-DSS: Invalid Test => Intrn Comm Summary\n",
                "name": "PCI-DSS: Internal Environment List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with internal IP addresses of your entire internal  network.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T02:29:50.9Z",
                "dateUpdated": "2021-07-27T16:03:30.7Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "2A5E5FCE-1FEF-4A7A-A827-93B7676028EA",
                "id": -2077,
                "listType": "Network",
                "longDescription": "This list is used in the following package elements:  \r\nPCI-DSS: DMZ Communication\r\nPCI-DSS: DMZ Communication Detail\r\nPCI-DSS: Denied DMZ => Internal Comm AIE Rule\r\nPCI-DSS: Denied DMZ => Internal Comm Details\r\nPCI-DSS: Denied DMZ => Internal Comm Summary\r\nPCI-DSS: Denied DMZ => Internal Comm Detail\r\nPCI-DSS: Denied Internet => DMZ Comm AIE Rule\r\nPCI-DSS: Denied Internet => DMZ Comm Details\r\nPCI-DSS: Denied Internet => DMZ Comm Summary\r\nPCI-DSS: Denied Internet => DMZ Comm Detail\r\nPCI-DSS: Invalid DMZ => Internal Comm AIE Rule\r\nPCI-DSS: Invalid DMZ => Internal Comm Details\r\nPCI-DSS: Invalid DMZ => Internal Comm Summary\r\nPCI-DSS: Invalid DMZ => Internal Comm Detail\r\nPCI-DSS: Invalid Internet => DMZ Comm AIE Rule\r\nPCI-DSS: Invalid Internet => DMZ Comm Details\r\nPCI-DSS: Invalid Internet => DMZ Comm Summary\r\nPCI-DSS: Invalid Internet => DMZ Comm Detail\r\n",
                "name": "PCI-DSS: DMZ Environment List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with internal IP addresses of your demilitarized zone network.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T02:22:50.693Z",
                "dateUpdated": "2021-07-27T16:03:30.713Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "4CAB138D-9BD4-4ED4-AB4E-FF5F48D4BC3E",
                "id": -2076,
                "listType": "Network",
                "longDescription": "This list is used in the following package elements:  \n\r\nPCI-DSS: CDE Communication \r\n\nPCI-DSS: Denied CDE => Internet Comm AIE Rule\n\r\nPCI-DSS: Denied CDE => Internet Comm Detail\n\r\nPCI-DSS: Denied CDE => Internet Comm Details\r\n\nPCI-DSS: Denied CDE => Internet Comm Summary\r\n\nPCI-DSS: Denied Internet => CDE Comm AIE Rule\n\r\nPCI-DSS: Denied Internet => CDE Comm Detail\n\r\nPCI-DSS: Denied Internet => CDE Comm Details\r\n\nPCI-DSS: Denied Internet => CDE Comm Summary\r\n\nPCI-DSS: Denied Wireless => CDE Comm AIE Rule\n\r\nPCI-DSS: Denied Wireless => CDE Comm Detail\n\r\nPCI-DSS: Denied Wireless => CDE Comm Details\r\n\nPCI-DSS: Denied Wireless => CDE Comm Summary\r\n\nPCI-DSS: Invalid CDE => Internet Comm AIE Rule\n\r\nPCI-DSS: Invalid CDE => Internet Comm Detail\n\r\nPCI-DSS: Invalid CDE => Internet Comm Details\n\r\nPCI-DSS: Invalid CDE => Internet Comm Summary\n\r\nPCI-DSS: Invalid Internet => CDE Comm AIE Rule\n\r\nPCI-DSS: Invalid Internet => CDE Comm Detail\n\r\nPCI-DSS: Invalid Internet => CDE Comm Details\r\n\nPCI-DSS: Invalid Internet => CDE Comm Summary\r\n\nPCI-DSS:  Invalid Wireless => CDE Comm AIE Rule\r\n\nPCI-DSS: Invalid Wireless => CDE Comm Detail\r\n\nPCI-DSS: Invalid Wireless => CDE Comm Details\r\n\nPCI-DSS: Invalid Wireless => CDE Comm Summary\n\r\n",
                "name": "PCI-DSS: Cardholder Data Environment List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with internal IP addresses of your cardholder data.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T02:10:32.13Z",
                "dateUpdated": "2021-07-27T16:03:30.723Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "76B503F9-7F63-4EBC-B06F-0AB083ECDCF1",
                "id": -2073,
                "listType": "MsgSource",
                "longDescription": "This list is used in many of the package elements covering network security system including: \r\nfirewalls, intrusion detection/prevention, malware detection/prevention, network access control, remote access, virtual private network, and vulnerability scanning.",
                "name": "PCI-DSS: Network Security Systems",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with network security systems (firewalls, intrusion detection/prevention, malware detection/prevention, network access control, remote access, virtual private network, vulnerability scanning) on the network.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T00:31:39.017Z",
                "dateUpdated": "2021-07-27T16:03:30.733Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "EAAC1F68-44F7-477E-BBB5-CFAEF5AEDBF6",
                "id": -2063,
                "listType": "Application",
                "longDescription": "This list is used in the following package elements:  \n\r\nPCI-DSS: Invalid Inet => Intrn Comm AIE Rule\r\n\nPCI-DSS: Invalid Inet => Intrn Comm Detail\n\r\nPCI-DSS: Invalid Inet => Intrn  Comm Details\n\r\nPCI-DSS: Invalid Inet => Intrn  Comm Summary\n\r\n\r\n",
                "name": "PCI-DSS: Allowed Internet => Internal App List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet environment to the internal environment network.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T00:29:15.183Z",
                "dateUpdated": "2021-07-27T16:03:30.74Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "3D987185-2C72-4AE0-B453-FB27E8412510",
                "id": -2062,
                "listType": "Application",
                "longDescription": "This list is used in the following package elements:  \r\n\nPCI-DSS: Invalid Internet => DMZ Comm AIE Rule\n\r\nPCI-DSS: Invalid Internet => DMZ Comm Details\n\r\nPCI-DSS: Invalid Internet => DMZ Comm Summary\n\r\nPCI-DSS: Invalid Internet => DMZ Comm Detail\n\r\n",
                "name": "PCI-DSS: Allowed Internet => DMZ App List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet to the demilitarized zone environment network.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T00:27:14.477Z",
                "dateUpdated": "2021-07-27T16:03:30.757Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "8A030E0F-870C-4F59-A5DD-28F8572723DD",
                "id": -2061,
                "listType": "Application",
                "longDescription": "This list is used in the following package elements:  \n\r\nPCI-DSS: Invalid Internet => CDE Comm AIE Rule\n\r\nPCI-DSS: Invalid Internet => CDE Comm Details\n\r\nPCI-DSS: Invalid Internet => CDE Comm Summary\r\n\nPCI-DSS: Invalid Internet => CDE Comm Detail\n\r\n\r\n",
                "name": "PCI-DSS: Allowed Internet => CDE App List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet to the internal cardholder data environment network.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2012-06-14T00:18:04.5Z",
                "dateUpdated": "2021-08-09T05:25:25.377Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 1,
                "guid": "DBA00254-D606-43D0-B291-EF38DA092DB3",
                "id": -2058,
                "listType": "Application",
                "longDescription": "This list is used in the following package elements:  \r\n\nPCI-DSS: Invalid CDE => Internet Comm AIE Rule\r\n\nPCI-DSS: Invalid CDE => Internet Comm Detail\n\r\nPCI-DSS: Invalid CDE => Internet Comm Details\n\r\nPCI-DSS: Invalid CDE => Internet Comm Summary\r\n",
                "name": "PCI-DSS: Allowed CDE => Internet App List",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "This list should be populated with the impacted applications, ports, and protocols which are allowed from the cardholder data environment network to the external internet.\r\n",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2011-12-14T06:13:01.05Z",
                "dateUpdated": "2021-07-27T16:03:30.78Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "642A7B7B-274E-4A66-9FBD-E4EC1CFC2404",
                "id": -2031,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from workstations that store or process data applicable to compliance regulations.  Examples include personal computers, notebooks, netbooks, tablet PCs, and publicly accessible systems such as kiosks. Virtualized application servers may also qualify as a workstation log source.",
                "name": "NRC: Workstations",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2011-12-14T06:09:16.99Z",
                "dateUpdated": "2021-07-27T16:03:30.79Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "229E1613-221C-4961-90F6-0B19B282B80F",
                "id": -2027,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from production servers that store or process data applicable to compliance regulations.  Examples include servers that store/process financial data, customer data, and employee data.",
                "name": "NRC: Production Servers",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2011-12-14T00:43:04.903Z",
                "dateUpdated": "2021-07-27T16:03:30.8Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F0F6C2E0-5EBD-41D8-B64E-3D67E649B2F1",
                "id": -2023,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from workstations that store or process data applicable to compliance regulations.  Examples include personal computers, notebooks, netbooks, tablet PCs, and publicly accessible systems such as kiosks. Virtualized application servers may also qualify as a workstation log source.",
                "name": "NEI: Workstations",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2011-12-14T00:39:35.59Z",
                "dateUpdated": "2021-07-27T16:03:30.81Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "35EB656F-CEB0-498D-B684-9E97B325B14B",
                "id": -2019,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from production servers that store or process data applicable to compliance regulations.  Examples include servers that store/process financial data, customer data, and employee data.",
                "name": "NEI: Production Servers",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:21:23.91Z",
                "dateUpdated": "2021-07-27T16:03:30.817Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "48555D7B-0BEB-43F0-B758-29D7838B0907",
                "id": -1049,
                "listType": "MsgSource",
                "longDescription": "Populate with all production data loss prevention devices, including LogRhythm Data Loss Defender.",
                "name": "QsEMP: Data Loss Prevention",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Production data loss prevention devices, including LogRhythm Data Loss Defender.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:20:56.847Z",
                "dateUpdated": "2021-07-27T16:03:30.827Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "280E2A9C-EB0C-4CCC-9776-FE1C164B8C5D",
                "id": -1048,
                "listType": "MsgSource",
                "longDescription": "Populate with the system and audit logs of all production UNIX and Linux servers, as well as LogRhythm User Activity Monitor and Network Connection Monitor for production agents.",
                "name": "QsEMP: Production *NIX Servers",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System and audit logs of production UNIX and Linux servers. LogRhythm User Activity Monitor and Network Connection Monitor for production agents.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:20:34.41Z",
                "dateUpdated": "2021-07-27T16:03:30.84Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "60390FB9-0419-4A01-A517-611098B9171E",
                "id": -1047,
                "listType": "MsgSource",
                "longDescription": "Populate with the System, Application, and Security Event Logs of all production Windows Servers, as well as LogRhythm User Activity Monitor, Process Monitor and Network Connection Monitor for production agents.",
                "name": "QsEMP: Production Windows Servers",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System, Application, and Security Event Logs of production Windows Servers. LogRhythm User Activity Monitor, Process Monitor and Network Connection Monitor for production agents.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:20:10.877Z",
                "dateUpdated": "2021-07-27T16:03:30.85Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "A55CE990-D057-4760-9845-2E9CD173FE5B",
                "id": -1046,
                "listType": "MsgSource",
                "longDescription": "Populate with the system logs of all production routers and switches.",
                "name": "QsEMP: Production Routers and Switches",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System logs of all production routers and switches.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:19:46.61Z",
                "dateUpdated": "2021-07-27T16:03:30.86Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "AE1EDD58-9DE0-4E72-BC87-A4939D9CA0B7",
                "id": -1045,
                "listType": "MsgSource",
                "longDescription": "Populate with the system logs of all production firewalls.",
                "name": "QsEMP: Production Firewalls",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System logs of all production firewalls.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:19:25.033Z",
                "dateUpdated": "2021-07-27T16:03:30.867Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "6658537A-358C-435F-8451-B02440B6C50B",
                "id": -1044,
                "listType": "MsgSource",
                "longDescription": "Populate with the system or application logs of all devices providing malware detection capabilities.  This includes anti-virus, spyware, and general malware detection software and central servers.",
                "name": "QsEMP: Production Malware Detection Devices",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System or application logs of devices providing malware detection capabilities.  Examples: anti-virus, spyware, general malware detection software and central servers.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-08-16T20:18:57.753Z",
                "dateUpdated": "2021-07-27T16:03:30.877Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "DE466E5C-19D6-46B5-936C-7A7E5ADFB03E",
                "id": -1043,
                "listType": "MsgSource",
                "longDescription": "Populate with the system logs of all devices with intrusion detection or prevention capabilities.  This typically includes IDS/IPS devices, but may also include firewalls and UTM devices that include these capabilities.",
                "name": "QsEMP: Production IDS/IPS Devices",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "System logs of devices with intrusion detection or prevention capabilities.  Examples: firewalls and UTM devices that include these capabilities.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-02-25T00:42:26.083Z",
                "dateUpdated": "2021-07-27T16:03:30.887Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "41BCC625-7E73-4603-8B39-AE1E6DEEDC18",
                "id": -1038,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from workstations that store or process data applicable to compliance regulations.  Examples include personal computers, notebooks, netbooks, tablet PCs, and publicly accessible systems such as kiosks. Virtualized application servers may also qualify as a workstation log source.",
                "name": "FISMA: Workstations",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2010-02-25T00:41:57.283Z",
                "dateUpdated": "2021-07-27T16:03:30.9Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "BF568BD1-E69E-4377-BB7F-2BD5FEE593A0",
                "id": -1037,
                "listType": "MsgSource",
                "longDescription": "This list should contain all log sources from production servers that store or process data applicable to compliance regulations.  Examples include servers that store/process financial data, customer data, and employee data.",
                "name": "FISMA: Production Servers",
                "needToNotify": false,
                "owner": -1000000,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data.",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicGlobalAdmin"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-08-09T05:04:50.927Z",
                "dateUpdated": "2021-08-09T05:35:48.757Z",
                "doesExpire": false,
                "entityName": "Primary Site",
                "entryCount": 0,
                "guid": "2D0073F7-DB6A-4751-91E7-38272D12C737",
                "id": 2001,
                "listType": "Network",
                "name": "test list",
                "needToNotify": false,
                "owner": -100,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "shortDescription": "test for logrhythm integration",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-08-09T05:41:30.443Z",
                "dateUpdated": "2021-10-27T16:27:32.467Z",
                "doesExpire": false,
                "entityName": "Primary Site",
                "entryCount": 2,
                "guid": "EA778B8F-20CA-4413-9A2D-CF69FB536793",
                "id": 2002,
                "listType": "Application",
                "name": "test list 2",
                "needToNotify": false,
                "owner": -100,
                "readAccess": "Private",
                "restrictedRead": false,
                "revisitDate": "2031-10-27T16:27:32.467Z",
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T14:09:10.093Z",
                "dateUpdated": "2021-09-29T14:09:10.093Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "15C307AE-CDA6-4BA0-A605-F3FAE5215C1B",
                "id": 2003,
                "listType": "Application",
                "name": "test",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T14:51:55.337Z",
                "dateUpdated": "2021-09-29T14:51:55.337Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "B8D0E804-928A-492E-85FF-4E2940BB8B3C",
                "id": 2004,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T14:53:03.013Z",
                "dateUpdated": "2021-10-27T13:51:08.88Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "1120112E-4743-4BE8-BF95-ADE3252CB915",
                "id": 2005,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:03:03.84Z",
                "dateUpdated": "2021-09-29T15:03:03.84Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "7C8B63A6-68D3-4B1C-AD95-06125A77CF99",
                "id": 2006,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:03:07.51Z",
                "dateUpdated": "2021-09-29T15:03:07.51Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F52EDC03-ECED-4683-86E9-4783409D1C92",
                "id": 2007,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:06:38.853Z",
                "dateUpdated": "2021-09-29T15:06:38.853Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "A2D11D2A-3017-4216-870E-6F3E1E5682BF",
                "id": 2008,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:10:14.497Z",
                "dateUpdated": "2021-09-29T15:10:14.497Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "325E81FC-2D62-461B-BB7C-5C9169600C97",
                "id": 2009,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:10:17.113Z",
                "dateUpdated": "2021-09-29T15:10:17.113Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "D3EA4CDC-5A58-4D60-8CAB-096B466AE4B7",
                "id": 2010,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:10:17.98Z",
                "dateUpdated": "2021-09-29T15:10:17.98Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "8BC72673-1C8C-4B26-BB21-E65AA908A4EF",
                "id": 2011,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:10:18.923Z",
                "dateUpdated": "2021-09-29T15:10:18.923Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "A927EB2E-8850-46A0-9798-E2C3B8C6C4F6",
                "id": 2012,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:10:55.743Z",
                "dateUpdated": "2021-09-29T15:10:55.743Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "D0D70666-1BF2-4C34-A10A-F4C131C76687",
                "id": 2013,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:11:03.187Z",
                "dateUpdated": "2021-09-29T15:11:03.187Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "CBC412AE-F98C-4CE9-A290-B36C0D3344E4",
                "id": 2014,
                "listType": "Application",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:11:05.657Z",
                "dateUpdated": "2021-09-29T15:11:05.657Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F4CB25B5-F190-482C-A82D-B3C4AF4BCAAE",
                "id": 2015,
                "listType": "Application",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:13:22.533Z",
                "dateUpdated": "2021-09-29T15:13:22.533Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F9597684-1119-42B9-911C-0114968D402E",
                "id": 2016,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-09-29T15:13:40Z",
                "dateUpdated": "2021-09-29T15:13:40Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "4CBB4771-0A44-4B8B-BF05-DD832369A864",
                "id": 2017,
                "listType": "Application",
                "name": "test1",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T07:44:41.107Z",
                "dateUpdated": "2021-10-05T07:44:41.107Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "B21EA8F5-3031-42B5-8410-F6AEE42B8E42",
                "id": 2018,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T07:45:20.603Z",
                "dateUpdated": "2021-10-05T07:45:20.603Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "3624C3B7-04E5-4820-BF93-3D22D2DDEF96",
                "id": 2019,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T07:45:24.86Z",
                "dateUpdated": "2021-10-05T07:45:24.86Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "D73FEF9B-D9BA-4C1E-8C6A-A5A15EB9F657",
                "id": 2020,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-05T07:56:28.223Z",
                "dateUpdated": "2021-10-05T07:56:28.223Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "DA3B78E8-A0EF-4BEC-A41D-0671D509A56D",
                "id": 2021,
                "listType": "User",
                "name": "tesl list",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:03:35.007Z",
                "dateUpdated": "2021-10-05T08:03:35.007Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "43BC3DD5-00B9-4F3D-9A6E-B01F96560B46",
                "id": 2022,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:04:27.267Z",
                "dateUpdated": "2021-10-05T08:04:27.27Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "2888D7FD-1C6F-40E0-AAB7-AF292BCB8A3D",
                "id": 2023,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:04:37.11Z",
                "dateUpdated": "2021-10-05T08:04:37.11Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "CBA4C600-ED03-4F5E-A274-A694144F362F",
                "id": 2024,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-05T08:05:11.877Z",
                "dateUpdated": "2021-10-05T08:05:11.877Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "D35B50C4-3CA3-4A20-9B31-742137965A64",
                "id": 2025,
                "listType": "Application",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-05T08:05:14.59Z",
                "dateUpdated": "2021-10-05T08:05:14.59Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "58041B5B-2B8A-4353-8DF8-5169D28E71DA",
                "id": 2026,
                "listType": "Application",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-05T08:05:19.55Z",
                "dateUpdated": "2021-10-05T08:05:19.55Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "20CC50DF-7352-4521-8642-50C93BBD0182",
                "id": 2027,
                "listType": "Application",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:05:51.01Z",
                "dateUpdated": "2021-10-05T08:05:51.01Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "FD411415-93C4-4094-B3E5-8415A42A7F9E",
                "id": 2028,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:06:14.563Z",
                "dateUpdated": "2021-10-05T08:06:14.567Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "6C353897-F317-4077-A720-62F4204C8BB0",
                "id": 2029,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-05T08:06:18.727Z",
                "dateUpdated": "2021-10-05T08:06:18.727Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "73E09328-94C5-4166-B1CE-8DC581F98496",
                "id": 2030,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:46:24.71Z",
                "dateUpdated": "2021-10-27T13:46:24.713Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "6B417043-4740-4821-8474-8DC8972F529C",
                "id": 2031,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:47:30.467Z",
                "dateUpdated": "2021-10-27T13:47:30.467Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "3D9ED83F-0ED6-4911-B13D-1FC750A411C3",
                "id": 2032,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:47:39.58Z",
                "dateUpdated": "2021-10-27T13:47:39.58Z",
                "doesExpire": false,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "7C13886C-A9E7-42F2-8553-33B6AFEFD079",
                "id": 2033,
                "listType": "User",
                "name": "test1",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T13:50:09.693Z",
                "dateUpdated": "2021-10-27T13:51:55.893Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "9B279A23-2822-43C2-BABC-23D08AD0046E",
                "id": 2034,
                "listType": "Application",
                "name": "test202020",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T13:50:23.25Z",
                "dateUpdated": "2021-10-27T13:50:23.25Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "A2F0C0AB-6C8C-46D5-9F57-13A5298DC7AC",
                "id": 2035,
                "listType": "Application",
                "name": "test2020201",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:54:14.383Z",
                "dateUpdated": "2021-10-27T13:54:39.233Z",
                "doesExpire": false,
                "entityName": "Primary Site",
                "entryCount": 0,
                "guid": "F4A3EAE5-E5F8-4A6B-92DD-06C9CCCFF67A",
                "id": 2036,
                "listType": "Application",
                "name": "a",
                "needToNotify": false,
                "owner": -100,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:54:48.01Z",
                "dateUpdated": "2021-10-27T13:54:48.01Z",
                "doesExpire": false,
                "entityName": "Primary Site",
                "entryCount": 0,
                "guid": "B8B79601-76E5-4C19-94E3-053A0D41EC67",
                "id": 2037,
                "listType": "CommonEvent",
                "name": "a",
                "needToNotify": false,
                "owner": -100,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": false,
                    "replaceExisting": false,
                    "usePatterns": false
                },
                "dateCreated": "2021-10-27T13:55:27.393Z",
                "dateUpdated": "2021-10-27T13:55:27.393Z",
                "doesExpire": false,
                "entityName": "Primary Site",
                "entryCount": 0,
                "guid": "5FEDBC14-EE01-4B00-BF9D-20D0BE549C14",
                "id": 2038,
                "listType": "MsgSource",
                "name": "a",
                "needToNotify": false,
                "owner": -100,
                "readAccess": "Private",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "Private"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T13:56:45.6Z",
                "dateUpdated": "2021-10-27T13:58:02.647Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "741FAD03-E3AC-4C43-BE93-A17407A66C89",
                "id": 2039,
                "listType": "Application",
                "name": "test20202012",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T13:58:18.13Z",
                "dateUpdated": "2021-10-27T14:00:08.607Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "07F90C7D-F205-4614-9B2D-8F2005878226",
                "id": 2040,
                "listType": "Application",
                "name": "test20202012_true",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": true,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T13:58:26.87Z",
                "dateUpdated": "2021-10-27T13:58:26.873Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "02684746-10C2-4153-A854-D4465E24B82C",
                "id": 2041,
                "listType": "Application",
                "name": "test20202012_false",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": true,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T14:02:32.25Z",
                "dateUpdated": "2021-10-27T14:04:08.84Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "CB767AFE-65BC-4243-AC82-22B398FB61D9",
                "id": 2042,
                "listType": "Application",
                "name": "test1818_false",
                "needToNotify": false,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            },
            {
                "autoImportOption": {
                    "enabled": true,
                    "replaceExisting": false,
                    "usePatterns": true
                },
                "dateCreated": "2021-10-27T14:02:44.92Z",
                "dateUpdated": "2021-10-27T14:08:48.587Z",
                "doesExpire": true,
                "entityName": "Global Entity",
                "entryCount": 0,
                "guid": "F89F6CAF-4892-4E83-81C5-C64DE02591E8",
                "id": 2043,
                "listType": "Application",
                "name": "test1818_true",
                "needToNotify": true,
                "owner": 1,
                "readAccess": "PublicAll",
                "restrictedRead": false,
                "status": "Active",
                "useContext": [
                    "None"
                ],
                "writeAccess": "PublicAll"
            }
        ]
    }
}
```

#### Human Readable Output

>### Lists
>|Guid|Name|List Type|Status|Short Description|Id|Entity Name|Date Created|Owner|Write Access|Read Access|
>|---|---|---|---|---|---|---|---|---|---|---|
>| B1E34445-2693-411E-8BE2-9B97AFFF20A9 | Windows System32 Hashes | GeneralValue | Active | Hashes of executables in the %systemroot%\system32 directory. Use Case: Masquerading technique in MITRE ATT&CK -1000130 | Global Entity | 2019-11-05T04:11:38.303Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| F205DE21-9F73-462E-8F83-DE64CAD2A401 | CloudAI: Ignore for 24 Hours | Identity | Active | Anomaly scores from CloudAI will not be displayed for the identities in this list. Identities added to this list will automatically expire 24 hours after they are added. | -1000001 | Global Entity | 2021-07-27T15:07:50.893Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 5A2E34FB-3AD1-44CB-8E5F-643CAEDD1EC2 | CloudAI: Monitored Identities | Identity | Active | Identities monitored by CloudAI | -1000000 | Global Entity | 2021-07-27T15:07:50.893Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 6B9A54EF-70C9-49E0-B051-75C363178603 | NERC-CIP: Electronic Security Perimeter | MsgSource | Active | This log source list represents various network related systems such as security perimeter enforcing devices (i.e. IPS, firewalls), security perimeter monitoring devices (i.e. IDS),  VPNs, wireless access points, remote access devices, anti-malware, etc.  | -2389 | Global Entity | 2015-06-06T00:15:20.033Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| F7A6369A-33C3-4249-91EF-6710E13F48F6 | NERC-CIP: BES Cyber Systems | MsgSource | Active | This log source list represents various BES Cyber Assets related to IT operations that reflect groupings of the BES Cyber System(s) | -2379 | Global Entity | 2015-06-05T21:31:30.7Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 4E629B5B-7D5D-447B-B672-BBCAF8E32E37 | PCI-DSS: Allowed DMZ => Internal App List | Application | Active | This list should be populated with the impacted applications, ports, and protocols which are allowed from the demilitarized zone environment to the internal network. | -2085 | Global Entity | 2012-06-14T03:39:14.56Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| AFD1ACEB-A5CB-4EE7-BB46-331CE023F750 | PCI-DSS: Internal Environment List | Network | Active | This list should be populated with internal IP addresses of your entire internal  network.<br/> | -2078 | Global Entity | 2012-06-14T02:43:14.257Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 2A5E5FCE-1FEF-4A7A-A827-93B7676028EA | PCI-DSS: DMZ Environment List | Network | Active | This list should be populated with internal IP addresses of your demilitarized zone network. | -2077 | Global Entity | 2012-06-14T02:29:50.9Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 4CAB138D-9BD4-4ED4-AB4E-FF5F48D4BC3E | PCI-DSS: Cardholder Data Environment List | Network | Active | This list should be populated with internal IP addresses of your cardholder data.<br/> | -2076 | Global Entity | 2012-06-14T02:22:50.693Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 76B503F9-7F63-4EBC-B06F-0AB083ECDCF1 | PCI-DSS: Network Security Systems | MsgSource | Active | This list should be populated with network security systems (firewalls, intrusion detection/prevention, malware detection/prevention, network access control, remote access, virtual private network, vulnerability scanning) on the network.<br/> | -2073 | Global Entity | 2012-06-14T02:10:32.13Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| EAAC1F68-44F7-477E-BBB5-CFAEF5AEDBF6 | PCI-DSS: Allowed Internet => Internal App List | Application | Active | This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet environment to the internal environment network.<br/> | -2063 | Global Entity | 2012-06-14T00:31:39.017Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 3D987185-2C72-4AE0-B453-FB27E8412510 | PCI-DSS: Allowed Internet => DMZ App List | Application | Active | This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet to the demilitarized zone environment network.<br/> | -2062 | Global Entity | 2012-06-14T00:29:15.183Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 8A030E0F-870C-4F59-A5DD-28F8572723DD | PCI-DSS: Allowed Internet => CDE App List | Application | Active | This list should be populated with the impacted applications, ports, and protocols which are allowed from the external internet to the internal cardholder data environment network.<br/> | -2061 | Global Entity | 2012-06-14T00:27:14.477Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| DBA00254-D606-43D0-B291-EF38DA092DB3 | PCI-DSS: Allowed CDE => Internet App List | Application | Active | This list should be populated with the impacted applications, ports, and protocols which are allowed from the cardholder data environment network to the external internet.<br/> | -2058 | Global Entity | 2012-06-14T00:18:04.5Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 642A7B7B-274E-4A66-9FBD-E4EC1CFC2404 | NRC: Workstations | MsgSource | Active | Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems. | -2031 | Global Entity | 2011-12-14T06:13:01.05Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 229E1613-221C-4961-90F6-0B19B282B80F | NRC: Production Servers | MsgSource | Active | Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data. | -2027 | Global Entity | 2011-12-14T06:09:16.99Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| F0F6C2E0-5EBD-41D8-B64E-3D67E649B2F1 | NEI: Workstations | MsgSource | Active | Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems. | -2023 | Global Entity | 2011-12-14T00:43:04.903Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 35EB656F-CEB0-498D-B684-9E97B325B14B | NEI: Production Servers | MsgSource | Active | Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data. | -2019 | Global Entity | 2011-12-14T00:39:35.59Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 48555D7B-0BEB-43F0-B758-29D7838B0907 | QsEMP: Data Loss Prevention | MsgSource | Active | Production data loss prevention devices, including LogRhythm Data Loss Defender. | -1049 | Global Entity | 2010-08-16T20:21:23.91Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 280E2A9C-EB0C-4CCC-9776-FE1C164B8C5D | QsEMP: Production *NIX Servers | MsgSource | Active | System and audit logs of production UNIX and Linux servers. LogRhythm User Activity Monitor and Network Connection Monitor for production agents. | -1048 | Global Entity | 2010-08-16T20:20:56.847Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 60390FB9-0419-4A01-A517-611098B9171E | QsEMP: Production Windows Servers | MsgSource | Active | System, Application, and Security Event Logs of production Windows Servers. LogRhythm User Activity Monitor, Process Monitor and Network Connection Monitor for production agents. | -1047 | Global Entity | 2010-08-16T20:20:34.41Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| A55CE990-D057-4760-9845-2E9CD173FE5B | QsEMP: Production Routers and Switches | MsgSource | Active | System logs of all production routers and switches. | -1046 | Global Entity | 2010-08-16T20:20:10.877Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| AE1EDD58-9DE0-4E72-BC87-A4939D9CA0B7 | QsEMP: Production Firewalls | MsgSource | Active | System logs of all production firewalls. | -1045 | Global Entity | 2010-08-16T20:19:46.61Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 6658537A-358C-435F-8451-B02440B6C50B | QsEMP: Production Malware Detection Devices | MsgSource | Active | System or application logs of devices providing malware detection capabilities.  Examples: anti-virus, spyware, general malware detection software and central servers. | -1044 | Global Entity | 2010-08-16T20:19:25.033Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| DE466E5C-19D6-46B5-936C-7A7E5ADFB03E | QsEMP: Production IDS/IPS Devices | MsgSource | Active | System logs of devices with intrusion detection or prevention capabilities.  Examples: firewalls and UTM devices that include these capabilities. | -1043 | Global Entity | 2010-08-16T20:18:57.753Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 41BCC625-7E73-4603-8B39-AE1E6DEEDC18 | FISMA: Workstations | MsgSource | Active | Workstations that store or process data applicable to compliance regulations.  Examples: personal computers, notebooks, tablet PCs, and publicly accessible systems. | -1038 | Global Entity | 2010-02-25T00:42:26.083Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| BF568BD1-E69E-4377-BB7F-2BD5FEE593A0 | FISMA: Production Servers | MsgSource | Active | Production servers applicable to compliance regulations.  Examples: servers that store/process financial data, customer data, and employee data. | -1037 | Global Entity | 2010-02-25T00:41:57.283Z | -1000000 | PublicGlobalAdmin | PublicAll |
>| 2D0073F7-DB6A-4751-91E7-38272D12C737 | test list | Network | Active | test for logrhythm integration | 2001 | Primary Site | 2021-08-09T05:04:50.927Z | -100 | PublicAll | PublicAll |
>| EA778B8F-20CA-4413-9A2D-CF69FB536793 | test list 2 | Application | Active |  | 2002 | Primary Site | 2021-08-09T05:41:30.443Z | -100 | Private | Private |
>| 15C307AE-CDA6-4BA0-A605-F3FAE5215C1B | test | Application | Active |  | 2003 | Global Entity | 2021-09-29T14:09:10.093Z | 1 | PublicAll | PublicAll |
>| B8D0E804-928A-492E-85FF-4E2940BB8B3C | test1 | Application | Active |  | 2004 | Global Entity | 2021-09-29T14:51:55.337Z | 1 | PublicAll | PublicAll |
>| 1120112E-4743-4BE8-BF95-ADE3252CB915 | test1 | Application | Active |  | 2005 | Global Entity | 2021-09-29T14:53:03.013Z | 1 | Private | Private |
>| 7C8B63A6-68D3-4B1C-AD95-06125A77CF99 | test1 | Application | Active |  | 2006 | Global Entity | 2021-09-29T15:03:03.84Z | 1 | Private | Private |
>| F52EDC03-ECED-4683-86E9-4783409D1C92 | test1 | Application | Active |  | 2007 | Global Entity | 2021-09-29T15:03:07.51Z | 1 | Private | Private |
>| A2D11D2A-3017-4216-870E-6F3E1E5682BF | test1 | Application | Active |  | 2008 | Global Entity | 2021-09-29T15:06:38.853Z | 1 | Private | Private |
>| 325E81FC-2D62-461B-BB7C-5C9169600C97 | test1 | Application | Active |  | 2009 | Global Entity | 2021-09-29T15:10:14.497Z | 1 | Private | Private |
>| D3EA4CDC-5A58-4D60-8CAB-096B466AE4B7 | test1 | Application | Active |  | 2010 | Global Entity | 2021-09-29T15:10:17.113Z | 1 | Private | Private |
>| 8BC72673-1C8C-4B26-BB21-E65AA908A4EF | test1 | Application | Active |  | 2011 | Global Entity | 2021-09-29T15:10:17.98Z | 1 | Private | Private |
>| A927EB2E-8850-46A0-9798-E2C3B8C6C4F6 | test1 | Application | Active |  | 2012 | Global Entity | 2021-09-29T15:10:18.923Z | 1 | Private | Private |
>| D0D70666-1BF2-4C34-A10A-F4C131C76687 | test1 | Application | Active |  | 2013 | Global Entity | 2021-09-29T15:10:55.743Z | 1 | Private | Private |
>| CBC412AE-F98C-4CE9-A290-B36C0D3344E4 | test1 | Application | Active |  | 2014 | Global Entity | 2021-09-29T15:11:03.187Z | 1 | Private | Private |
>| F4CB25B5-F190-482C-A82D-B3C4AF4BCAAE | test1 | Application | Active |  | 2015 | Global Entity | 2021-09-29T15:11:05.657Z | 1 | Private | Private |
>| F9597684-1119-42B9-911C-0114968D402E | test1 | Application | Active |  | 2016 | Global Entity | 2021-09-29T15:13:22.533Z | 1 | Private | Private |
>| 4CBB4771-0A44-4B8B-BF05-DD832369A864 | test1 | Application | Active |  | 2017 | Global Entity | 2021-09-29T15:13:40Z | 1 | Private | Private |
>| B21EA8F5-3031-42B5-8410-F6AEE42B8E42 | test1 | User | Active |  | 2018 | Global Entity | 2021-10-05T07:44:41.107Z | 1 | Private | Private |
>| 3624C3B7-04E5-4820-BF93-3D22D2DDEF96 | test1 | User | Active |  | 2019 | Global Entity | 2021-10-05T07:45:20.603Z | 1 | Private | Private |
>| D73FEF9B-D9BA-4C1E-8C6A-A5A15EB9F657 | test1 | User | Active |  | 2020 | Global Entity | 2021-10-05T07:45:24.86Z | 1 | Private | Private |
>| DA3B78E8-A0EF-4BEC-A41D-0671D509A56D | tesl list | User | Active |  | 2021 | Global Entity | 2021-10-05T07:56:28.223Z | 1 | PublicAll | PublicAll |
>| 43BC3DD5-00B9-4F3D-9A6E-B01F96560B46 | test1 | User | Active |  | 2022 | Global Entity | 2021-10-05T08:03:35.007Z | 1 | Private | Private |
>| 2888D7FD-1C6F-40E0-AAB7-AF292BCB8A3D | test1 | User | Active |  | 2023 | Global Entity | 2021-10-05T08:04:27.267Z | 1 | Private | Private |
>| CBA4C600-ED03-4F5E-A274-A694144F362F | test1 | User | Active |  | 2024 | Global Entity | 2021-10-05T08:04:37.11Z | 1 | Private | Private |
>| D35B50C4-3CA3-4A20-9B31-742137965A64 | test1 | Application | Active |  | 2025 | Global Entity | 2021-10-05T08:05:11.877Z | 1 | Private | Private |
>| 58041B5B-2B8A-4353-8DF8-5169D28E71DA | test1 | Application | Active |  | 2026 | Global Entity | 2021-10-05T08:05:14.59Z | 1 | Private | Private |
>| 20CC50DF-7352-4521-8642-50C93BBD0182 | test1 | Application | Active |  | 2027 | Global Entity | 2021-10-05T08:05:19.55Z | 1 | Private | Private |
>| FD411415-93C4-4094-B3E5-8415A42A7F9E | test1 | User | Active |  | 2028 | Global Entity | 2021-10-05T08:05:51.01Z | 1 | Private | Private |
>| 6C353897-F317-4077-A720-62F4204C8BB0 | test1 | User | Active |  | 2029 | Global Entity | 2021-10-05T08:06:14.563Z | 1 | Private | Private |
>| 73E09328-94C5-4166-B1CE-8DC581F98496 | test1 | User | Active |  | 2030 | Global Entity | 2021-10-05T08:06:18.727Z | 1 | Private | Private |
>| 6B417043-4740-4821-8474-8DC8972F529C | test1 | User | Active |  | 2031 | Global Entity | 2021-10-27T13:46:24.71Z | 1 | Private | Private |
>| 3D9ED83F-0ED6-4911-B13D-1FC750A411C3 | test1 | User | Active |  | 2032 | Global Entity | 2021-10-27T13:47:30.467Z | 1 | Private | Private |
>| 7C13886C-A9E7-42F2-8553-33B6AFEFD079 | test1 | User | Active |  | 2033 | Global Entity | 2021-10-27T13:47:39.58Z | 1 | Private | Private |
>| 9B279A23-2822-43C2-BABC-23D08AD0046E | test202020 | Application | Active |  | 2034 | Global Entity | 2021-10-27T13:50:09.693Z | 1 | PublicAll | PublicAll |
>| A2F0C0AB-6C8C-46D5-9F57-13A5298DC7AC | test2020201 | Application | Active |  | 2035 | Global Entity | 2021-10-27T13:50:23.25Z | 1 | PublicAll | PublicAll |
>| F4A3EAE5-E5F8-4A6B-92DD-06C9CCCFF67A | a | Application | Active |  | 2036 | Primary Site | 2021-10-27T13:54:14.383Z | -100 | Private | Private |
>| B8B79601-76E5-4C19-94E3-053A0D41EC67 | a | CommonEvent | Active |  | 2037 | Primary Site | 2021-10-27T13:54:48.01Z | -100 | Private | Private |
>| 5FEDBC14-EE01-4B00-BF9D-20D0BE549C14 | a | MsgSource | Active |  | 2038 | Primary Site | 2021-10-27T13:55:27.393Z | -100 | Private | Private |
>| 741FAD03-E3AC-4C43-BE93-A17407A66C89 | test20202012 | Application | Active |  | 2039 | Global Entity | 2021-10-27T13:56:45.6Z | 1 | PublicAll | PublicAll |
>| 07F90C7D-F205-4614-9B2D-8F2005878226 | test20202012_true | Application | Active |  | 2040 | Global Entity | 2021-10-27T13:58:18.13Z | 1 | PublicAll | PublicAll |
>| 02684746-10C2-4153-A854-D4465E24B82C | test20202012_false | Application | Active |  | 2041 | Global Entity | 2021-10-27T13:58:26.87Z | 1 | PublicAll | PublicAll |
>| CB767AFE-65BC-4243-AC82-22B398FB61D9 | test1818_false | Application | Active |  | 2042 | Global Entity | 2021-10-27T14:02:32.25Z | 1 | PublicAll | PublicAll |
>| F89F6CAF-4892-4E83-81C5-C64DE02591E8 | test1818_true | Application | Active |  | 2043 | Global Entity | 2021-10-27T14:02:44.92Z | 1 | PublicAll | PublicAll |


### lr-list-summary-create-update
***
Updates a list summary based on the GUID and other required details. Searches the system for existing list summaries by GUID. Creates a new list summary if the GUID does not exist. Otherwise, updates the list summary.


#### Base Command

`lr-list-summary-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The list type. Possible values: "None", "Application", "Classification", "CommonEvent", "Host", "Location", "MsgSource", "MsgSourceType", "MPERule", "Network", "User", "GeneralValue", "Entity", "RootEntity", "IP", "IPRange", and "Identity". Possible values are: None, Application, Classification, CommonEvent, Host, Location, MsgSource, MsgSourceType, MPERule, Network, User, GeneralValue, Entity, RootEntity, IP, IPRange, Identity. | Required | 
| name | The list name. | Required | 
| enabled | Whether the list auto import is enabled. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| use_patterns | Whether the auto import use patterns is enabled. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| replace_existing | Whether the auto import replace existing is enabled. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| read_access | The read permission level. Possible values: "Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin". Possible values are: Private, PublicAll, PublicGlobalAdmin, PublicGlobalAnalyst, PublicRestrictedAnalyst, PublicRestrictedAdmin. | Required | 
| write_access | The write permission level. Possible values: "Private", "PublicAll", "PublicGlobalAdmin", "PublicGlobalAnalyst", "PublicRestrictedAnalyst", "PublicRestrictedAdmin". Possible values are: Private, PublicAll, PublicGlobalAdmin, PublicGlobalAnalyst, PublicRestrictedAnalyst, PublicRestrictedAdmin. | Required | 
| restricted_read | Whether the list is read restricted. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| entity_name | The entity name. | Required | 
| need_to_notify | Whether the list need to notify. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| does_expire | Whether the list expires. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| owner | The ID of the owner. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.List.listType | String | The list type. | 
| LogRhythm.List.status | String | The list status. | 
| LogRhythm.List.name | String | The list name. | 
| LogRhythm.List.useContext | String | The use context type. | 
| LogRhythm.List.autoImportOption.enabled | Boolean | Whether the list auto import is enabled. | 
| LogRhythm.List.autoImportOption.usePatterns | Boolean | Whether the auto import use patterns is enabled. | 
| LogRhythm.List.autoImportOption.replaceExisting | Boolean | Whether the auto import replace existing is enabled. | 
| LogRhythm.List.id | Number | The list ID. | 
| LogRhythm.List.guid | String | The list GUID. | 
| LogRhythm.List.dateCreated | Date | The date the list was created. | 
| LogRhythm.List.dateUpdated | Date | The date the list was updated. | 
| LogRhythm.List.readAccess | String | The read permission level. | 
| LogRhythm.List.writeAccess | String | The write permission level. | 
| LogRhythm.List.restrictedRead | Boolean | Whether the list is read restricted. | 
| LogRhythm.List.entityName | String | The list entity name. | 
| LogRhythm.List.entryCount | Number | The list entry count. | 
| LogRhythm.List.needToNotify | Boolean | Whether the list will notify the user when updated. | 
| LogRhythm.List.doesExpire | Boolean | Whether the list expires. | 
| LogRhythm.List.owner | Number | The ID of the list owner. | 


#### Command Example
```!lr-list-summary-create-update does_expire=false enabled=true entity_name=`Global Entity` list_type=User name=test1 need_to_notify=false read_access=Private replace_existing=false restricted_read=false use_patterns=false write_access=Private owner=1```

#### Context Example
```json
{
    "LogRhythm": {
        "List": {
            "autoImportOption": {
                "enabled": true,
                "replaceExisting": false,
                "usePatterns": false
            },
            "dateCreated": "2021-10-30T20:17:42.433Z",
            "dateUpdated": "2021-10-30T20:17:42.433Z",
            "doesExpire": false,
            "entityName": "Global Entity",
            "entryCount": 0,
            "guid": "4BC51B20-640B-4F58-A448-A5C8A52161D2",
            "id": 2044,
            "listType": "User",
            "name": "test1",
            "needToNotify": false,
            "owner": 1,
            "readAccess": "Private",
            "restrictedRead": false,
            "status": "Active",
            "useContext": [
                "None"
            ],
            "writeAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### List created successfully
>|Guid|Name|List Type|Status|Short Description|Id|Entity Name|Date Created|Owner|Write Access|Read Access|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 4BC51B20-640B-4F58-A448-A5C8A52161D2 | test1 | User | Active |  | 2044 | Global Entity | 2021-10-30T20:17:42.433Z | 1 | Private | Private |


### lr-list-details-and-items-get
***
Returns list details and list items based on the list GUID.


#### Base Command

`lr-list-details-and-items-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_guid | The GUID stored in the database. | Required | 
| max_items | The maximum number of items that can be returned in a single request. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.ListDetails.listType | String | The list type. | 
| LogRhythm.ListDetails.status | String | The list status. | 
| LogRhythm.ListDetails.name | String | The list name. | 
| LogRhythm.ListDetails.useContext | String | The use context type. | 
| LogRhythm.ListDetails.autoImportOption.enabled | Boolean | Whether the list auto import is enabled. | 
| LogRhythm.ListDetails.autoImportOption.usePatterns | Boolean | Whether the auto import use patterns is enabled. | 
| LogRhythm.ListDetails.autoImportOption.replaceExisting | Boolean | Whether the auto import replace existing is enabled. | 
| LogRhythm.ListDetails.id | Number | The list ID. | 
| LogRhythm.ListDetails.guid | String | The list GUID. | 
| LogRhythm.ListDetails.dateCreated | Date | The date the list was created. | 
| LogRhythm.ListDetails.dateUpdated | Date | The date the list was updated. | 
| LogRhythm.ListDetails.revisitDate | Date | The date the list was revisited. | 
| LogRhythm.ListDetails.readAccess | String | The read permission level. | 
| LogRhythm.ListDetails.writeAccess | String | The write permission level. | 
| LogRhythm.ListDetails.restrictedRead | Boolean | Whether the list is read restricted. | 
| LogRhythm.ListDetails.entityName | String | The list entity name. | 
| LogRhythm.ListDetails.entryCount | Number | The list entry count. | 
| LogRhythm.ListDetails.needToNotify | Boolean | Whether the list will notify the user when updated. | 
| LogRhythm.ListDetails.doesExpire | Boolean | Whether the list expires. | 
| LogRhythm.ListDetails.owner | Number | The ID of the list owner. | 
| LogRhythm.ListDetails.listItemsCount | Number | The list items count. | 
| LogRhythm.ListDetails.items.displayValue | String | The list items value. | 
| LogRhythm.ListDetails.items.expirationDate | Unknown | The list item expiration date. | 
| LogRhythm.ListDetails.items.isExpired | Boolean | Whether the item is expired. | 
| LogRhythm.ListDetails.items.isListItem | Boolean | Whether the item is a list item. | 
| LogRhythm.ListDetails.items.isPattern | Boolean | Whether the item is a pattern. | 
| LogRhythm.ListDetails.items.listItemDataType | String | The item data type. | 
| LogRhythm.ListDetails.items.listItemType | String | The item type. | 
| LogRhythm.ListDetails.items.value | String | The item value. | 


#### Command Example
```!lr-list-details-and-items-get list_guid=EA778B8F-20CA-4413-9A2D-CF69FB536793```

#### Context Example
```json
{
    "LogRhythm": {
        "ListDetails": {
            "autoImportOption": {
                "enabled": false,
                "replaceExisting": false,
                "usePatterns": false
            },
            "dateCreated": "2021-08-09T05:41:30.443Z",
            "dateUpdated": "2021-10-27T16:27:32.467Z",
            "doesExpire": false,
            "entityName": "Primary Site",
            "entryCount": 2,
            "guid": "EA778B8F-20CA-4413-9A2D-CF69FB536793",
            "id": 2002,
            "items": [
                {
                    "displayValue": "8081,8085",
                    "expirationDate": null,
                    "isExpired": false,
                    "isListItem": false,
                    "isPattern": false,
                    "listItemDataType": "PortRange",
                    "listItemType": "PortRange",
                    "value": "8081,8085"
                },
                {
                    "displayValue": "1,100",
                    "expirationDate": null,
                    "isExpired": false,
                    "isListItem": false,
                    "isPattern": false,
                    "listItemDataType": "PortRange",
                    "listItemType": "PortRange",
                    "value": "1,100"
                }
            ],
            "listItemsCount": 0,
            "listType": "Application",
            "name": "test list 2",
            "needToNotify": false,
            "owner": -100,
            "readAccess": "Private",
            "restrictedRead": false,
            "revisitDate": "2031-10-27T16:27:32.467Z",
            "status": "Active",
            "useContext": [
                "None"
            ],
            "writeAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### List EA778B8F-20CA-4413-9A2D-CF69FB536793 details
>|Guid|Name|List Type|Status|Short Description|Id|Entity Name|Date Created|Owner|Write Access|Read Access|
>|---|---|---|---|---|---|---|---|---|---|---|
>| EA778B8F-20CA-4413-9A2D-CF69FB536793 | test list 2 | Application | Active |  | 2002 | Primary Site | 2021-08-09T05:41:30.443Z | -100 | Private | Private |
>### List items
>|Display Value|Expiration Date|Is Expired|Is List Item|Is Pattern|List Item Data Type|List Item Type|Value|
>|---|---|---|---|---|---|---|---|
>| 8081,8085 |  | false | false | false | PortRange | PortRange | 8081,8085 |
>| 1,100 |  | false | false | false | PortRange | PortRange | 1,100 |


### lr-list-items-add
***
Adds more items to an existing list.


#### Base Command

`lr-list-items-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_guid | The GUID stored in the database. | Required | 
| items | The body of the list item so that the list can be updated with new items (JSON format). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.ListItemsAdd.listType | String | The list type. | 
| LogRhythm.ListItemsAdd.status | String | The list status. | 
| LogRhythm.ListItemsAdd.name | String | The list name. | 
| LogRhythm.ListItemsAdd.useContext | String | The use context type. | 
| LogRhythm.ListItemsAdd.autoImportOption.enabled | Boolean | Whether the list auto import is enabled. | 
| LogRhythm.ListItemsAdd.autoImportOption.usePatterns | Boolean | Whether the auto import use patterns is enabled. | 
| LogRhythm.ListItemsAdd.autoImportOption.replaceExisting | Boolean | Whether the auto import replace existing is enabled. | 
| LogRhythm.ListItemsAdd.id | Number | The list ID. | 
| LogRhythm.ListItemsAdd.guid | String | The list GUID. | 
| LogRhythm.ListItemsAdd.dateCreated | Date | The date the list was created. | 
| LogRhythm.ListItemsAdd.dateUpdated | Date | The date the list was updated. | 
| LogRhythm.ListItemsAdd.revisitDate | Date | The list revisit date. | 
| LogRhythm.ListItemsAdd.readAccess | String | The read permission level. | 
| LogRhythm.ListItemsAdd.writeAccess | String | The write permission level. | 
| LogRhythm.ListItemsAdd.restrictedRead | Boolean | Whether the list is read restricted. | 
| LogRhythm.ListItemsAdd.entityName | String | The list entity name. | 
| LogRhythm.ListItemsAdd.entryCount | Number | The list entry count. | 
| LogRhythm.ListItemsAdd.needToNotify | Boolean | Whether the list will notify the user when updated. | 
| LogRhythm.ListItemsAdd.doesExpire | Boolean | Whether the list expires. | 
| LogRhythm.ListItemsAdd.owner | Number | The ID of the list owner. | 
| LogRhythm.ListItemsAdd.listItemsCount | Number | The list items count. | 


#### Command Example
```!lr-list-items-add list_guid=EA778B8F-20CA-4413-9A2D-CF69FB536793 items=`{"listItemDataType": "PortRange","listItemType": "PortRange","value": "200,300","valueAsListReference":{"listType": "Network"}}````

#### Context Example
```json
{
    "LogRhythm": {
        "ListItemsAdd": {
            "autoImportOption": {
                "enabled": false,
                "replaceExisting": false,
                "usePatterns": false
            },
            "dateCreated": "2021-08-09T05:41:30.443Z",
            "dateUpdated": "2021-10-30T20:33:48.12Z",
            "doesExpire": false,
            "entityName": "Primary Site",
            "entryCount": 3,
            "guid": "EA778B8F-20CA-4413-9A2D-CF69FB536793",
            "id": 2002,
            "listItemsCount": 0,
            "listType": "Application",
            "name": "test list 2",
            "needToNotify": false,
            "owner": -100,
            "readAccess": "Private",
            "restrictedRead": false,
            "revisitDate": "2031-10-30T20:33:48.12Z",
            "status": "Active",
            "useContext": [
                "None"
            ],
            "writeAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### The item added to the list EA778B8F-20CA-4413-9A2D-CF69FB536793.
>|Auto Import Option|Date Created|Date Updated|Does Expire|Entity Name|Entry Count|Guid|Id|List Items Count|List Type|Name|Need To Notify|Owner|Read Access|Restricted Read|Revisit Date|Status|Use Context|Write Access|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| enabled: false<br/>usePatterns: false<br/>replaceExisting: false | 2021-08-09T05:41:30.443Z | 2021-10-30T20:33:48.12Z | false | Primary Site | 3 | EA778B8F-20CA-4413-9A2D-CF69FB536793 | 2002 | 0 | Application | test list 2 | false | -100 | Private | false | 2031-10-30T20:33:48.12Z | Active | None | Private |


### lr-list-items-remove
***
Removes items from an existing list.


#### Base Command

`lr-list-items-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_guid | The GUID stored in the database. | Required | 
| items | Body of the list items to be removed from the list (JSON format). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.ListItemsRemove.listType | String | The list type. | 
| LogRhythm.ListItemsRemove.status | String | The list status. | 
| LogRhythm.ListItemsRemove.name | String | The list name. | 
| LogRhythm.ListItemsRemove.useContext | String | The use context type. | 
| LogRhythm.ListItemsRemove.autoImportOption.enabled | Boolean | Whether the list auto import is enabled. | 
| LogRhythm.ListItemsRemove.autoImportOption.usePatterns | Boolean | Whether the auto import use patterns is enabled. | 
| LogRhythm.ListItemsRemove.autoImportOption.replaceExisting | Boolean | Whether the auto import replace existing is enabled. | 
| LogRhythm.ListItemsRemove.id | Number | The list ID. | 
| LogRhythm.ListItemsRemove.guid | String | The list GUID. | 
| LogRhythm.ListItemsRemove.dateCreated | Date | The date the list was created. | 
| LogRhythm.ListItemsRemove.dateUpdated | Date | The date the list was updated. | 
| LogRhythm.ListItemsRemove.revisitDate | Date | The list revisit date. | 
| LogRhythm.ListItemsRemove.readAccess | String | The read permission level. | 
| LogRhythm.ListItemsRemove.writeAccess | String | The write permission level. | 
| LogRhythm.ListItemsRemove.restrictedRead | Boolean | Whether the list is read restricted. | 
| LogRhythm.ListItemsRemove.entityName | String | The list entity name. | 
| LogRhythm.ListItemsRemove.entryCount | Number | The list entry count. | 
| LogRhythm.ListItemsRemove.needToNotify | Boolean | Whether the list will notify the user when updated. | 
| LogRhythm.ListItemsRemove.doesExpire | Boolean | Whether the list expires. | 
| LogRhythm.ListItemsRemove.owner | Number | The ID of the list owner. | 
| LogRhythm.ListItemsRemove.listItemsCount | Number | The list items count. | 


#### Command Example
```!lr-list-items-remove list_guid=EA778B8F-20CA-4413-9A2D-CF69FB536793 items=`{"displayValue": "201,301","listItemType": "PortRange","value": "201,301"}````

#### Context Example
```json
{
    "LogRhythm": {
        "ListItemsRemove": {
            "autoImportOption": {
                "enabled": false,
                "replaceExisting": false,
                "usePatterns": false
            },
            "dateCreated": "2021-08-09T05:41:30.443Z",
            "dateUpdated": "2021-10-30T20:33:49.717Z",
            "doesExpire": false,
            "entityName": "Primary Site",
            "entryCount": 3,
            "guid": "EA778B8F-20CA-4413-9A2D-CF69FB536793",
            "id": 2002,
            "listItemsCount": 0,
            "listType": "Application",
            "name": "test list 2",
            "needToNotify": false,
            "owner": -100,
            "readAccess": "Private",
            "restrictedRead": false,
            "revisitDate": "2031-10-30T20:33:49.717Z",
            "status": "Active",
            "useContext": [
                "None"
            ],
            "writeAccess": "Private"
        }
    }
}
```

#### Human Readable Output

>### The item deleted from the list EA778B8F-20CA-4413-9A2D-CF69FB536793.
>|Auto Import Option|Date Created|Date Updated|Does Expire|Entity Name|Entry Count|Guid|Id|List Items Count|List Type|Name|Need To Notify|Owner|Read Access|Restricted Read|Revisit Date|Status|Use Context|Write Access|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| enabled: false<br/>usePatterns: false<br/>replaceExisting: false | 2021-08-09T05:41:30.443Z | 2021-10-30T20:33:49.717Z | false | Primary Site | 3 | EA778B8F-20CA-4413-9A2D-CF69FB536793 | 2002 | 0 | Application | test list 2 | false | -100 | Private | false | 2031-10-30T20:33:49.717Z | Active | None | Private |


### lr-execute-search-query
***
Execute a search query on the LogRhythm log database.


#### Base Command

`lr-execute-search-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| number_of_days | Number of days to search. | Required | 
| search_name | Name of the search. | Optional | 
| source_type | Log source type. Possible values are: all, API_-_AWS_CloudTrail, API_-_AWS_CloudWatch_Alarm, API_-_AWS_Config_Event, API_-_AWS_S3_Flat_File, API_-_AWS_S3_Server_Access_Event, API_-_BeyondTrust_Retina_Vulnerability_Management, API_-_Box_Event, API_-_Cisco_IDS/IPS, API_-_Cradlepoint_ECM, API_-_IP360_Vulnerability_Scanner, API_-_Metasploit_Penetration_Scanner, API_-_Nessus_Vulnerability_Scanner, API_-_NetApp_CIFS_Security_Audit_Event_Log, API_-_NeXpose_Vulnerability_Scanner, API_-_Office_365_Management_Activity, API_-_Office_365_Message_Tracking, API_-_Okta_Event, API_-_Qualys_Vulnerability_Scanner, API_-_Salesforce_EventLogFile, API_-_Sourcefire_eStreamer, API_-_Tenable_SecurityCenter, API_-_Tenable.io_Scanner, Flat_File_-_ActivIdentity_CMS, Flat_File_-_Airwatch_MDM, Flat_File_-_Alfresco, Flat_File_-_AllScripts, Flat_File_-_Apache_Access_Log, Flat_File_-_Apache_Error_Log, Flat_File_-_Apache_SSL_Access_Log, Flat_File_-_Apache_SSL_Error_Log, Flat_File_-_Apache_Tomcat_Access_Log, Flat_File_-_Apache_Tomcat_Console_Log, Flat_File_-_Avaya_Secure_Access_Link_Remote_Access_Log, Flat_File_-_Avaya_Voice_Mail_Log, Flat_File_-_Axway_SFTP, Flat_File_-_Beacon_Endpoint_Profiler, Flat_File_-_Bind_9, Flat_File_-_BlackBerry_Enterprise_Server, Flat_File_-_Blue_Coat_Proxy_BCREPORTERMAIN_Format, Flat_File_-_Blue_Coat_Proxy_CSV_Format, Flat_File_-_Blue_Coat_Proxy_SQUID-1_Format, Flat_File_-_Blue_Coat_Proxy_W3C_Format, Flat_File_-_Bro_IDS_Critical_Stack_Intel_Log, Flat_File_-_Broadcom_SiteMinder, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTDS, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTEL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTJL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTLL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTNV, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTOM, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTPW, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRL, Flat_File_-_CA_ACF2_for_z/OS_-_ACFRPTRV, Flat_File_-_CA_ControlMinder, Flat_File_-_Cerberus_FTP_Server, Flat_File_-_Cerner, Flat_File_-_Cisco_AMP_for_Endpoints, Flat_File_-_Cisco_Email_Security_Appliance, Flat_File_-_Cisco_LMS_(cwcli), Flat_File_-_Cisco_LMS_(Syslog), Flat_File_-_Cisco_NGFW, Flat_File_-_Cisco_Secure_ACS_CSV_File, Flat_File_-_Cisco_Security_Agent, Flat_File_-_Cisco_Umbrella_DNS, Flat_File_-_Cisco_Web_Security_aclog, Flat_File_-_Citrix_Access_Gateway_IIS_Format, Flat_File_-_Citrix_Access_Gateway_NCSA_Common_Format, Flat_File_-_Citrix_Access_Gateway_W3C_Format, Flat_File_-_Citrix_Presentation_Server, Flat_File_-_Citrix_Secure_Gateway, Flat_File_-_ClamAV_Anti-Virus, Flat_File_-_ColdFusion_Application_Log, Flat_File_-_ColdFusion_Exception_Log, Flat_File_-_ColdFusion_Mail_Log, Flat_File_-_ColdFusion_Mailsent_Log, Flat_File_-_ColdFusion_Server_Log, Flat_File_-_Cornerstone_Managed_File_Transfer, Flat_File_-_Coyote_Point_Equalizer, Flat_File_-_DB2_Audit_Log, Flat_File_-_DB2_via_BMC_Log_Master, Flat_File_-_Defender_Server, Flat_File_-_DocWorks, Flat_File_-_eClinicalWorks_Audit_Log, Flat_File_-_EMC_Isilon, Flat_File_-_Epicor_Coalition, Flat_File_-_FairWarning_Ready-For-Healthcare, Flat_File_-_FileZilla_System_Log, Flat_File_-_FireEye_Web_MPS, Flat_File_-_Forcepoint_Web_Security_CEF_Cloud_Format, Flat_File_-_Forescout_CounterACT, Flat_File_-_FoxT_BoKS_Server_Access_Control, Flat_File_-_FundsXpress, Flat_File_-_Gene6_FTP, Flat_File_-_GlobalSCAPE_EFT, Flat_File_-_Hadoop, Flat_File_-_HMC, Flat_File_-_HP-UX_Audit_Log, Flat_File_-_IBM_4690_POS, Flat_File_-_IBM_Informix_Application_Log, Flat_File_-_IBM_Informix_Audit_Log, Flat_File_-_IBM_Tivoli_Storage_Manager, Flat_File_-_IBM_WebSphere_App_Server_v7_Audit_Log, Flat_File_-_IBM_WebSphere_Cast_Iron_Cloud_Integration, Flat_File_-_IBM_ZOS_Batch_Decryption_Log, Flat_File_-_IBM_ZOS_CICS_Decryption_Log, Flat_File_-_IBM_ZOS_RACF_Access_Log, Flat_File_-_IBM_ZOS_RACF_SMF_Type_80, Flat_File_-_IPSwitch_WS_FTP, Flat_File_-_Irix_Audit_Logs, Flat_File_-_IT-CUBE_AgileSI, Flat_File_-_JBoss_Log_File, Flat_File_-_Juniper_Steel_Belted_Radius_Server, Flat_File_-_Kerio_Mail_Server, Flat_File_-_KERISYS_Doors_Event_Export_Format, Flat_File_-_Kippo_Honeypot, Flat_File_-_Linux_Audit_ASCII, Flat_File_-_Linux_Audit_Log, Flat_File_-_Linux_Host_Secure_Log, Flat_File_-_LOGbinder_EX, Flat_File_-_LogRhythm_Alarm_Reingest, Flat_File_-_LogRhythm_Data_Indexer_Monitor, Flat_File_-_LogRhythm_Oracle_Log, Flat_File_-_LogRhythm_System_Monitor, Flat_File_-_LogRhythm_System_Monitor_Log_File, Flat_File_-_LogRhythm_Trebek_Log, Flat_File_-_LogRhythm_Zeus_Log, Flat_File_-_Lotus_Domino_Client_Log, Flat_File_-_McAfee_Cloud_Proxy_do_not_use, Flat_File_-_McAfee_ePO_HIPS, Flat_File_-_McAfee_Foundstone, Flat_File_-_McAfee_Proxy_Cloud, Flat_File_-_McAfee_SaaS_Web_Protection, Flat_File_-_McAfee_Web_Gateway_Audit_Log, Flat_File_-_Merak, Flat_File_-_Meridian, Flat_File_-_Microsoft_ActiveSync_2010, Flat_File_-_Microsoft_CRM, Flat_File_-_Microsoft_DHCP_Server_Log, Flat_File_-_Microsoft_Forefront_TMG, Flat_File_-_Microsoft_Forefront_TMG_Web_Proxy, Flat_File_-_Microsoft_IIS_(IIS_Format)_File, Flat_File_-_Microsoft_IIS_7.x_W3C_Extended_Format, Flat_File_-_Microsoft_IIS_Error_Log_V6, Flat_File_-_Microsoft_IIS_FTP_IIS_Log_File_Format, Flat_File_-_Microsoft_IIS_FTP_W3C_Extended_Format, Flat_File_-_Microsoft_IIS_NCSA_Common_Format_File, Flat_File_-_Microsoft_IIS_SMTP_W3C_Format, Flat_File_-_Microsoft_IIS_URL_Scan_Log, Flat_File_-_Microsoft_IIS_W3C_File, Flat_File_-_Microsoft_ISA_Server_2004, Flat_File_-_Microsoft_ISA_Server_W3C_File, Flat_File_-_Microsoft_Netlogon, Flat_File_-_Microsoft_Port_Reporter_PR-PORTS_Log, Flat_File_-_Microsoft_Semantic_Logging, Flat_File_-_Microsoft_SQL_Server_2000_Error_Log, Flat_File_-_Microsoft_SQL_Server_2005_Error_Log, Flat_File_-_Microsoft_SQL_Server_2008_Error_Log, Flat_File_-_Microsoft_SQL_Server_2012_Error_Log, Flat_File_-_Microsoft_SQL_Server_2014_Error_Log, Flat_File_-_Microsoft_Windows_2003_DNS, Flat_File_-_Microsoft_Windows_2008_DNS, Flat_File_-_Microsoft_Windows_2012_DNS, Flat_File_-_Microsoft_Windows_Firewall, Flat_File_-_MicroStrategy, Flat_File_-_Mimecast_Audit, Flat_File_-_Mimecast_Email, Flat_File_-_Monetra, Flat_File_-_MongoDB, Flat_File_-_MS_Exchange_2003_Message_Tracking_Log, Flat_File_-_MS_Exchange_2007_Message_Tracking_Log, Flat_File_-_MS_Exchange_2010_Message_Tracking_Log, Flat_File_-_MS_Exchange_2013_Message_Tracking_Log, Flat_File_-_MS_Exchange_2016_Message_Tracking_Log, Flat_File_-_MS_Exchange_RPC_Client_Access, Flat_File_-_MS_IAS/RAS_Server_NPS_DB_Log_Format, Flat_File_-_MS_IAS/RAS_Server_Standard_Log_Format, Flat_File_-_MS_ISA_Server_2006_ISA_All_Fields, Flat_File_-_MS_ISA_Server_2006_W3C_All_Fields, Flat_File_-_MS_SQL_Server_Reporting_Services_2008, Flat_File_-_MySQL, Flat_File_-_MySQL_error.log, Flat_File_-_MySQL_mysql.log, Flat_File_-_MySQL_mysql-slow.log, Flat_File_-_Nessus_System_Log, Flat_File_-_NetApp_Cluster, Flat_File_-_Nginx_Log, Flat_File_-_Novell_Audit, Flat_File_-_Novell_GroupWise, Flat_File_-_Novell_LDAP, Flat_File_-_ObserveIT_Enterprise, Flat_File_-_Office_365_Message_Tracking, Flat_File_-_OpenDJ, Flat_File_-_OpenVMS, Flat_File_-_OpenVPN, Flat_File_-_Oracle_11g_Fine_Grained_Audit_Trail, Flat_File_-_Oracle_9i, Flat_File_-_Oracle_BRM_CM_Log, Flat_File_-_Oracle_BRM_DM_Log, Flat_File_-_Oracle_Listener_Audit_Trail, Flat_File_-_Oracle_SunOne_Directory_Server, Flat_File_-_Oracle_SunOne_Web_Server_Access_Log, Flat_File_-_Oracle_Virtual_Directory, Flat_File_-_Oracle_WebLogic_11g_Access_Log, Flat_File_-_Other, Flat_File_-_PeopleSoft, Flat_File_-_PhpMyAdmin_Honeypot, Flat_File_-_Postfix, Flat_File_-_PowerBroker_Servers, Flat_File_-_Princeton_Card_Secure, Flat_File_-_ProFTPD, Flat_File_-_PureMessage_For_Exchange_SMTP_Log, Flat_File_-_PureMessage_For_UNIX_Blocklist_Log, Flat_File_-_PureMessage_For_UNIX_Message_Log, Flat_File_-_RACF_(SMF), Flat_File_-_Radmin, Flat_File_-_Restic_Backup_Log, Flat_File_-_RL_Patient_Feedback, Flat_File_-_RSA_Adaptive_Authentication, Flat_File_-_RSA_Authentication_Manager_6.1, Flat_File_-_S2_Badge_Reader, Flat_File_-_Safenet, Flat_File_-_Sendmail_File, Flat_File_-_Sharepoint_ULS, Flat_File_-_ShoreTel_VOIP, Flat_File_-_Siemens_Radiology_Information_System, Flat_File_-_Snort_Fast_Alert_File, Flat_File_-_Solaris_-_Sulog, Flat_File_-_Solaris_Audit_Log, Flat_File_-_SpamAssassin, Flat_File_-_Squid_Proxy, Flat_File_-_Subversion, Flat_File_-_Sudo.Log, Flat_File_-_Swift_Alliance, Flat_File_-_Symantec_Antivirus_10.x_Corporate_Edtn, Flat_File_-_Symantec_Antivirus_12.x_Corporate_Edtn, Flat_File_-_Symitar_Episys_Console_Log, Flat_File_-_Symitar_Episys_Sysevent_Log, Flat_File_-_Tandem_EMSOUT_Log_File, Flat_File_-_Tandem_XYGATE, Flat_File_-_Tectia_SSH_Server, Flat_File_-_Trade_Innovations_CSCS, Flat_File_-_Trend_Micro_IMSS, Flat_File_-_Trend_Micro_Office_Scan, Flat_File_-_Tumbleweed_Mailgate_Server, Flat_File_-_Verint_Audit_Trail_File, Flat_File_-_VMWare_Virtual_Machine, Flat_File_-_Voltage_Securemail, Flat_File_-_Vormetric_Log_File, Flat_File_-_vsFTP_Daemon_Log, Flat_File_-_Vyatta_Firewall_Kernel_Log, Flat_File_-_WordPot_Honeypot, Flat_File_-_X-NetStat_Log, Flat_File_-_XPient_POS_CCA_Manager, Flat_File_-_XPIENT_POS_POSLOG, Flat_File_-_XPIENT_POS_Shell_Log, IPFIX_-_IP_Flow_Information_Export, J-Flow_-_Juniper_J-Flow_Version_5, J-Flow_-_Juniper_J-Flow_Version_9, LogRhythm_CloudAI, LogRhythm_Data_Loss_Defender, LogRhythm_Demo_File_-_Application_Server_Log, LogRhythm_Demo_File_-_Content_Inspection_Log, LogRhythm_Demo_File_-_Database_Audit_Log, LogRhythm_Demo_File_-_Ecom_Server_Log, LogRhythm_Demo_File_-_File_Server_Log, LogRhythm_Demo_File_-_Firewall_Log, LogRhythm_Demo_File_-_FTP_Log, LogRhythm_Demo_File_-_IDS_Alarms_Log, LogRhythm_Demo_File_-_Mail_Server_Log, LogRhythm_Demo_File_-_Netflow_Log, LogRhythm_Demo_File_-_Network_Device_Log, LogRhythm_Demo_File_-_Network_Server_Log, LogRhythm_Demo_File_-_VPN_Log, LogRhythm_Demo_File_-_Web_Access_Log, LogRhythm_File_Monitor_(AIX), LogRhythm_File_Monitor_(HP-UX), LogRhythm_File_Monitor_(Linux), LogRhythm_File_Monitor_(Solaris), LogRhythm_File_Monitor_(Windows), LogRhythm_Filter, LogRhythm_Network_Connection_Monitor_(AIX), LogRhythm_Network_Connection_Monitor_(HP-UX), LogRhythm_Network_Connection_Monitor_(Linux), LogRhythm_Network_Connection_Monitor_(Solaris), LogRhythm_Network_Connection_Monitor_(Windows), LogRhythm_Process_Monitor_(AIX), LogRhythm_Process_Monitor_(HP-UX), LogRhythm_Process_Monitor_(Linux), LogRhythm_Process_Monitor_(Solaris), LogRhythm_Process_Monitor_(Windows), LogRhythm_Registry_Integrity_Monitor, LogRhythm_SQL_Server_2000_C2_Audit_Log, LogRhythm_SQL_Server_2005_C2_Audit_Log, LogRhythm_SQL_Server_2008_C2_Audit_Log, LogRhythm_SQL_Server_2012+_C2_Audit_Log, LogRhythm_User_Activity_Monitor_(AIX), LogRhythm_User_Activity_Monitor_(HP-UX), LogRhythm_User_Activity_Monitor_(Linux), LogRhythm_User_Activity_Monitor_(Solaris), LogRhythm_User_Activity_Monitor_(Windows), MS_Event_Log_for_XP/2000/2003_-_Application, MS_Event_Log_for_XP/2000/2003_-_Application_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_BioPassword, MS_Event_Log_for_XP/2000/2003_-_DFS, MS_Event_Log_for_XP/2000/2003_-_Directory_Service, MS_Event_Log_for_XP/2000/2003_-_DNS, MS_Event_Log_for_XP/2000/2003_-_DotDefender, MS_Event_Log_for_XP/2000/2003_-_EMC_Celerra_NAS, MS_Event_Log_for_XP/2000/2003_-_File_Rep_Service, MS_Event_Log_for_XP/2000/2003_-_HA, MS_Event_Log_for_XP/2000/2003_-_Kaspersky, MS_Event_Log_for_XP/2000/2003_-_Micros_POS, MS_Event_Log_for_XP/2000/2003_-_PatchLink, MS_Event_Log_for_XP/2000/2003_-_SafeWord_2008, MS_Event_Log_for_XP/2000/2003_-_SCE, MS_Event_Log_for_XP/2000/2003_-_Security, MS_Event_Log_for_XP/2000/2003_-_Security_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_SMS_2003, MS_Event_Log_for_XP/2000/2003_-_System, MS_Event_Log_for_XP/2000/2003_-_System_-_Espaniol, MS_Event_Log_for_XP/2000/2003_-_Virtual_Server, MS_Windows_Event_Logging_-_ADFS_Admin, MS_Windows_Event_Logging_-_Application, MS_Windows_Event_Logging_-_AppLockerApp, MS_Windows_Event_Logging_-_Backup, MS_Windows_Event_Logging_-_Citrix_Delivery_Services, MS_Windows_Event_Logging_-_Citrix_XenApp, MS_Windows_Event_Logging_-_DFS, MS_Windows_Event_Logging_-_DHCP_Admin, MS_Windows_Event_Logging_-_DHCP_Operational, MS_Windows_Event_Logging_-_Diagnosis-PLA, MS_Windows_Event_Logging_-_Digital_Persona, MS_Windows_Event_Logging_-_Dir_Service, MS_Windows_Event_Logging_-_DNS, MS_Windows_Event_Logging_-_Dot_Defender, MS_Windows_Event_Logging_-_ESD_Data_Flow_Track, MS_Windows_Event_Logging_-_Exchange_Mailbox_DB_Failures, MS_Windows_Event_Logging_-_FailoverClustering/Operational, MS_Windows_Event_Logging_-_Firewall_With_Advanced_Security, MS_Windows_Event_Logging_-_Forefront_AV, MS_Windows_Event_Logging_-_Group_Policy_Operational, MS_Windows_Event_Logging_-_Hyper-V_Hvisor, MS_Windows_Event_Logging_-_Hyper-V_IMS, MS_Windows_Event_Logging_-_Hyper-V_Network, MS_Windows_Event_Logging_-_Hyper-V_SynthSt, MS_Windows_Event_Logging_-_Hyper-V_VMMS, MS_Windows_Event_Logging_-_Hyper-V_Worker, MS_Windows_Event_Logging_-_Kaspersky, MS_Windows_Event_Logging_-_Kernel_PnP_Configuration, MS_Windows_Event_Logging_-_Lync_Server, MS_Windows_Event_Logging_-_MSExchange_Management, MS_Windows_Event_Logging_-_Operations_Manager, MS_Windows_Event_Logging_-_PowerShell, MS_Windows_Event_Logging_-_Print_Services, MS_Windows_Event_Logging_-_Quest_ActiveRoles_EDM_Server, MS_Windows_Event_Logging_-_Replication, MS_Windows_Event_Logging_-_SafeWord_2008, MS_Windows_Event_Logging_-_Security, MS_Windows_Event_Logging_-_Setup, MS_Windows_Event_Logging_-_Sysmon, MS_Windows_Event_Logging_-_System, MS_Windows_Event_Logging_-_Task_Scheduler, MS_Windows_Event_Logging_-_TS_Gateway, MS_Windows_Event_Logging_-_TS_Licensing, MS_Windows_Event_Logging_-_TS_Local_Session_Manager, MS_Windows_Event_Logging_-_TS_Remote_Connection_Manager, MS_Windows_Event_Logging_-_TS_Session_Broker, MS_Windows_Event_Logging_-_TS_Session_Broker_Client, MS_Windows_Event_Logging_-_VisualSVN, MS_Windows_Event_Logging_:_Deutsch_-_Security, MS_Windows_Event_Logging_:_Espaniol_-_Application, MS_Windows_Event_Logging_:_Espaniol_-_Security, MS_Windows_Event_Logging_:_Espaniol_-_System, MS_Windows_Event_Logging_:_Francais_-_System, MS_Windows_Event_Logging_:_Francais_-_Security, MS_Windows_Event_Logging_XML_-_ADFS, MS_Windows_Event_Logging_XML_-_Application, MS_Windows_Event_Logging_XML_-_Forwarded_Events, MS_Windows_Event_Logging_XML_-_Generic, MS_Windows_Event_Logging_XML_-_Security, MS_Windows_Event_Logging_XML_-_Sysmon, MS_Windows_Event_Logging_XML_-_Sysmon_7.01, MS_Windows_Event_Logging_XML_-_Sysmon_8/9/10, MS_Windows_Event_Logging_XML_-_System, MS_Windows_Event_Logging_XML_-_Unisys_Stealth, MS_Windows_Event_Logging_XML_-_Windows_Defender, Netflow_-_Cisco_Netflow_Version_1, Netflow_-_Cisco_Netflow_Version_5, Netflow_-_Cisco_Netflow_Version_9, Netflow_-_Palo_Alto_Version_9, Netflow_-_SonicWALL_Version_5, Netflow_-_SonicWALL_Version_9, OPSEC_LEA_-_Checkpoint_Firewall, OPSEC_LEA_-_Checkpoint_Firewall_Audit_Log, OPSEC_LEA_-_Checkpoint_For_LR_7.4.1+, OPSEC_LEA_-_Checkpoint_Log_Server, sFlow_-_Version_5, SNMP_Trap_-_Audiolog, SNMP_Trap_-_Autoregistered, SNMP_Trap_-_Brocade_Switch, SNMP_Trap_-_Cisco_5508_Wireless_Controller, SNMP_Trap_-_Cisco_IP_SLA, SNMP_Trap_-_Cisco_Prime, SNMP_Trap_-_Cisco_Router-Switch, SNMP_Trap_-_CyberArk, SNMP_Trap_-_Dell_OpenManage, SNMP_Trap_-_HP_Network_Node_Manager, SNMP_Trap_-_IBM_TS3000_Series_Tape_Drive, SNMP_Trap_-_Riverbed_SteelCentral_NetShark, SNMP_Trap_-_RSA_Authentication_Manager, SNMP_Trap_-_Swift_Alliance, SNMP_Trap_-_Trend_Micro_Control_Manager, Syslog_-_3Com_Switch, Syslog_-_A10_Networks_AX1000_Load_Balancer, Syslog_-_A10_Networks_Web_Application_Firewall, Syslog_-_Accellion_Secure_File_Transfer_Application, Syslog_-_Active_Scout_IPS, Syslog_-_Adallom, Syslog_-_Adtran_Switch, Syslog_-_Aerohive_Access_Point, Syslog_-_Aerohive_Firewall, Syslog_-_AIMIA_Tomcat, Syslog_-_AirDefense_Enterprise, Syslog_-_Airmagnet_Wireless_IDS, Syslog_-_AirTight_IDS/IPS, Syslog_-_AirWatch_MDM, Syslog_-_Airwave_Management_System_Log, Syslog_-_AIX_Host, Syslog_-_Alcatel-Lucent_Switch, Syslog_-_Alcatel-Lucent_Wireless_Controller, Syslog_-_AlertLogic, Syslog_-_AMX_AV_Controller, Syslog_-_Apache_Access_Log, Syslog_-_Apache_Error_Log, Syslog_-_Apache_Tomcat_Request_Parameters, Syslog_-_Apache_Tomcat_Service_Clients_Log, Syslog_-_APC_ATS, Syslog_-_APC_NetBotz_Environmental_Monitoring, Syslog_-_APC_PDU, Syslog_-_APC_UPS, Syslog_-_Apcon_Network_Monitor, Syslog_-_Apex_One, Syslog_-_Arbor_Networks_Peakflow, Syslog_-_Arbor_Networks_Spectrum, Syslog_-_Arbor_Pravail_APS, Syslog_-_Arista_Switch, Syslog_-_Array_TMX_Load_Balancer, Syslog_-_Arris_CMTS, Syslog_-_Aruba_Clear_Pass, Syslog_-_Aruba_Mobility_Controller, Syslog_-_Aruba_Wireless_Access_Point, Syslog_-_AS/400_via_Powertech_Interact, Syslog_-_Asus_WRT_Router, Syslog_-_Avatier_Identity_Management_Suite_(AIMS), Syslog_-_Avaya_Communications_Manager, Syslog_-_Avaya_Ethernet_Routing_Switch, Syslog_-_Avaya_G450_Media_Gateway, Syslog_-_Avaya_Router, Syslog_-_Aventail_SSL/VPN, Syslog_-_Avocent_Cyclades_Terminal_Server, Syslog_-_Azul_Java_Appliance, Syslog_-_Barracuda_Load_Balancer, Syslog_-_Barracuda_Mail_Archiver, Syslog_-_Barracuda_NG_Firewall, Syslog_-_Barracuda_NG_Firewall_6.x, Syslog_-_Barracuda_Spam_Firewall, Syslog_-_Barracuda_Web_Application_Firewall, Syslog_-_Barracuda_Webfilter, Syslog_-_BeyondTrust_BeyondInsight_LEEF, Syslog_-_Bind_DNS, Syslog_-_Bit9_Parity_Suite, Syslog_-_Bit9_Security_Platform_CEF, Syslog_-_Bit9+Carbon_Black_(Deprecated), Syslog_-_BitDefender, Syslog_-_Black_Diamond_Switch, Syslog_-_Blue_Coat_CAS, Syslog_-_Blue_Coat_Forward_Proxy, Syslog_-_Blue_Coat_PacketShaper, Syslog_-_Blue_Coat_ProxyAV_ISA_W3C_Format, Syslog_-_Blue_Coat_ProxyAV_MS_Proxy_2.0_Format, Syslog_-_Blue_Coat_ProxySG, Syslog_-_Blue_Socket_Wireless_Controller, Syslog_-_Bluecat_Adonis, Syslog_-_BlueCedar, Syslog_-_BluVector, Syslog_-_Bomgar, Syslog_-_Bradford_Networks_NAC, Syslog_-_Bradford_Remediation_&amp;_Registration_Svr, Syslog_-_Bro_IDS, Syslog_-_Brocade_Switch, Syslog_-_Bromium_vSentry_CEF, Syslog_-_BSD_Host, Syslog_-_CA_Privileged_Access_Manager, Syslog_-_Cb_Defense_CEF, Syslog_-_Cb_Protection_CEF, Syslog_-_Cb_Response_LEEF, Syslog_-_Cell_Relay, Syslog_-_Certes_Networks_CEP, Syslog_-_Check_Point_Log_Exporter, Syslog_-_Checkpoint_Site-to-Site_VPN, Syslog_-_Cisco_ACS, Syslog_-_Cisco_Aironet_WAP, Syslog_-_Cisco_APIC, Syslog_-_Cisco_Application_Control_Engine, Syslog_-_Cisco_ASA, Syslog_-_Cisco_Clean_Access_(CCA)_Appliance, Syslog_-_Cisco_CSS_Load_Balancer, Syslog_-_Cisco_Email_Security_Appliance, Syslog_-_Cisco_FirePOWER, Syslog_-_Cisco_Firepower_Threat_Defense, Syslog_-_Cisco_FireSIGHT, Syslog_-_Cisco_FWSM, Syslog_-_Cisco_Global_Site_Selector, Syslog_-_Cisco_ISE, Syslog_-_Cisco_Meraki, Syslog_-_Cisco_Nexus_Switch, Syslog_-_Cisco_PIX, Syslog_-_Cisco_Prime_Infrastructure, Syslog_-_Cisco_Router, Syslog_-_Cisco_Secure_ACS_5, Syslog_-_Cisco_Session_Border_Controller, Syslog_-_Cisco_Switch, Syslog_-_Cisco_Telepresence_Video_Communications_Server, Syslog_-_Cisco_UCS, Syslog_-_Cisco_Unified_Comm_Mgr_(Call_Mgr), Syslog_-_Cisco_VPN_Concentrator, Syslog_-_Cisco_WAAS, Syslog_-_Cisco_Web_Security, Syslog_-_Cisco_Wireless_Access_Point, Syslog_-_Cisco_Wireless_Control_System, Syslog_-_CiscoWorks, Syslog_-_Citrix_Access_Gateway_Server, Syslog_-_Citrix_Netscaler, Syslog_-_Citrix_XenServer, Syslog_-_Claroty_CTD_CEF, Syslog_-_Clearswift_Secure_Email_Gateway, Syslog_-_CloudLock, Syslog_-_CodeGreen_Data_Loss_Prevention, Syslog_-_Cofense_Triage_CEF, Syslog_-_Consentry_NAC, Syslog_-_Corero_IPS, Syslog_-_Corero_SmartWall_DDoS, Syslog_-_CoyotePoint_Equalizer, Syslog_-_Crowdstrike_Falconhost_CEF, Syslog_-_CyberArk, Syslog_-_CyberArk_Privileged_Threat_Analytics, Syslog_-_Cylance_CEF, Syslog_-_CylancePROTECT, Syslog_-_DarkTrace_CEF, Syslog_-_Dell_Force_10, Syslog_-_Dell_PowerConnect_Switch, Syslog_-_Dell_Remote_Access_Controller, Syslog_-_Dell_SecureWorks_iSensor_IPS, Syslog_-_Dialogic_Media_Gateway, Syslog_-_Digital_Guardian_CEF, Syslog_-_D-Link_Switch, Syslog_-_Don_not_use, Syslog_-_Dragos_Platform_CEF, Syslog_-_Ecessa_ShieldLink, Syslog_-_EfficientIP, Syslog_-_EMC_Avamar, Syslog_-_EMC_Centera, Syslog_-_EMC_Data_Domain, Syslog_-_EMC_Isilon, Syslog_-_EMC_Unity_Array, Syslog_-_EMC_VNX, Syslog_-_Ensilo_NGAV, Syslog_-_Enterasys_Dragon_IDS, Syslog_-_Enterasys_Router, Syslog_-_Enterasys_Switch, Syslog_-_Entrust_Entelligence_Messaging_Server, Syslog_-_Entrust_IdentityGuard, Syslog_-_Epic_Hyperspace_CEF, Syslog_-_EqualLogic_SAN, Syslog_-_eSafe_Email_Security, Syslog_-_ESET_Remote_Administrator_(ERA)_LEEF, Syslog_-_Event_Reporter_(Win_2000/XP/2003), Syslog_-_Exabeam, Syslog_-_Exchange_Message_Tracking, Syslog_-_ExtraHop, Syslog_-_Extreme_Wireless_LAN, Syslog_-_ExtremeWare, Syslog_-_ExtremeXOS, Syslog_-_F5_BIG-IP_Access_Policy_Manager, Syslog_-_F5_BIG-IP_AFM, Syslog_-_F5_BIG-IP_ASM, Syslog_-_F5_BIG-IP_ASM_Key-Value_Pairs, Syslog_-_F5_BIG-IP_ASM_v12, Syslog_-_F5_Big-IP_GTM_&amp;_DNS, Syslog_-_F5_Big-IP_LTM, Syslog_-_F5_FirePass_Firewall, Syslog_-_F5_Silverline_DDoS_Protection, Syslog_-_Fargo_HDP_Card_Printer_and_Encoder, Syslog_-_Fat_Pipe_Load_Balancer, Syslog_-_Fidelis_XPS, Syslog_-_FireEye_E-Mail_MPS, Syslog_-_FireEye_EX, Syslog_-_FireEye_Web_MPS/CMS/ETP/HX, Syslog_-_Forcepoint_DLP, Syslog_-_Forcepoint_Email_Security_Gateway, Syslog_-_Forcepoint_Stonesoft_NGFW, Syslog_-_Forcepoint_SureView_Insider_Threat, Syslog_-_Forcepoint_Web_Security, Syslog_-_Forcepoint_Web_Security_CEF_Format, Syslog_-_Forescout_CounterACT_NAC, Syslog_-_Fortinet_FortiAnalyzer, Syslog_-_Fortinet_FortiAuthenticator, Syslog_-_Fortinet_FortiDDoS, Syslog_-_Fortinet_FortiGate, Syslog_-_Fortinet_FortiGate_v4.0, Syslog_-_Fortinet_FortiGate_v5.0, Syslog_-_Fortinet_FortiGate_v5.2, Syslog_-_Fortinet_FortiGate_v5.4/v5.6, Syslog_-_Fortinet_FortiGate_v5.6_CEF, Syslog_-_Fortinet_Fortigate_v6.0, Syslog_-_Fortinet_FortiMail, Syslog_-_Fortinet_FortiWeb, Syslog_-_Foundry_Switch, Syslog_-_Gene6_FTP, Syslog_-_Generic_CEF, Syslog_-_Generic_ISC_DHCP, Syslog_-_Generic_LEEF, Syslog_-_Guardium_Database_Activity_Monitor, Syslog_-_H3C_Router, Syslog_-_Hitachi_Universal_Storage_Platform, Syslog_-_HP_BladeSystem, Syslog_-_HP_iLO, Syslog_-_HP_Procurve_Switch, Syslog_-_HP_Router, Syslog_-_HP_Switch, Syslog_-_HP_Unix_Tru64, Syslog_-_HP_Virtual_Connect_Switch, Syslog_-_HP-UX_Host, Syslog_-_Huawei_Access_Router, Syslog_-_IBM_Blade_Center, Syslog_-_IBM_Security_Network_Protection, Syslog_-_IBM_Virtual_Tape_Library_Server, Syslog_-_IBM_WebSphere_DataPower_Integration, Syslog_-_IBM_zSecure_Alert_for_ACF2_2.1.0, Syslog_-_IceWarp_Server, Syslog_-_Imperva_Incapsula_CEF, Syslog_-_Imperva_SecureSphere, Syslog_-_Imprivata_OneSign_SSO, Syslog_-_InfoBlox, Syslog_-_Invincea_(LEEF), Syslog_-_iPrism_Proxy_Log, Syslog_-_IPSWITCH_MOVEit_Server, Syslog_-_IPTables, Syslog_-_IRIX_Host, Syslog_-_iSeries_via_Powertech_Interact, Syslog_-_Ivanti_FileDirector, Syslog_-_JetNexus_Load_Balancer, Syslog_-_Juniper_DX_Application_Accelerator, Syslog_-_Juniper_Firewall, Syslog_-_Juniper_Firewall_3400, Syslog_-_Juniper_Host_Checker, Syslog_-_Juniper_IDP, Syslog_-_Juniper_NSM, Syslog_-_Juniper_Router, Syslog_-_Juniper_SSL_VPN, Syslog_-_Juniper_SSL_VPN_WELF_Format, Syslog_-_Juniper_Switch, Syslog_-_Juniper_Trapeze, Syslog_-_Juniper_vGW_Virtual_Gateway, Syslog_-_Kaspersky_Security_Center, Syslog_-_Kea_DHCP_Server, Syslog_-_Kemp_Load_Balancer, Syslog_-_KFSensor_Honeypot, Syslog_-_KFSensor_Honeypot_CEF, Syslog_-_Lancope_StealthWatch, Syslog_-_Lancope_StealthWatch_CEF, Syslog_-_Layer_7_SecureSpan_SOA_Gateway, Syslog_-_Legacy_Checkpoint_Firewall_(Not_Log_Exporter), Syslog_-_Legacy_Checkpoint_IPS_(Not_Log_Exporter), Syslog_-_Lieberman_Enterprise_Random_Password_Manager, Syslog_-_Linux_Audit, Syslog_-_Linux_Host, Syslog_-_Linux_TACACS_Plus, Syslog_-_LOGbinder_EX, Syslog_-_LOGbinder_SP, Syslog_-_LOGbinder_SQL, Syslog_-_LogRhythm_Data_Indexer_Monitor, Syslog_-_LogRhythm_Inter_Deployment_Data_Sharing, Syslog_-_LogRhythm_Log_Distribution_Services, Syslog_-_LogRhythm_Network_Monitor, Syslog_-_LogRhythm_Syslog_Generator, Syslog_-_Lumension, Syslog_-_MacOS_X, Syslog_-_Malwarebytes_Endpoint_Security_CEF, Syslog_-_Mandiant_MIR, Syslog_-_McAfee_Advanced_Threat_Defense, Syslog_-_McAfee_Email_And_Web_Security, Syslog_-_McAfee_ePO, Syslog_-_McAfee_Firewall_Enterprise, Syslog_-_McAfee_Network_Security_Manager, Syslog_-_McAfee_Secure_Internet_Gateway, Syslog_-_McAfee_SecureMail, Syslog_-_McAfee_Skyhigh_for_Shadow_IT_LEEF, Syslog_-_McAfee_Web_Gateway, Syslog_-_mGuard_Firewall, Syslog_-_Microsoft_Advanced_Threat_Analytics_(ATA)_CEF, Syslog_-_Microsoft_Azure_Log_Integration, Syslog_-_Microsoft_Azure_MFA, Syslog_-_Microsoft_Forefront_UAG, Syslog_-_Mirapoint, Syslog_-_MobileIron, Syslog_-_Motorola_Access_Point, Syslog_-_MS_IIS_Web_Log_W3C_Format_(Snare), Syslog_-_MS_Windows_Event_Logging_XML_-_Application, Syslog_-_MS_Windows_Event_Logging_XML_-_Security, Syslog_-_MS_Windows_Event_Logging_XML_-_System, Syslog_-_Nagios, Syslog_-_nCircle_Configuration_Compliance_Manager, Syslog_-_NetApp_Filer, Syslog_-_NETASQ_Firewall, Syslog_-_NetGate_Router, Syslog_-_NetMotion_VPN, Syslog_-_Netscout_nGenius_InfiniStream, Syslog_-_NetScreen_Firewall, Syslog_-_Netskope, Syslog_-_Netskope_CEF, Syslog_-_Network_Chemistry_RFprotect, Syslog_-_Nginx_Web_Log, Syslog_-_Nimble_Storage, Syslog_-_Nortel_8600_Switch, Syslog_-_Nortel_BayStack_Switch, Syslog_-_Nortel_Contivity, Syslog_-_Nortel_Firewall, Syslog_-_Nortel_IP_1220, Syslog_-_Nortel_Passport_Switch, Syslog_-_Nozomi_Networks_Guardian_CEF, Syslog_-_NuSecure_Gateway, Syslog_-_Nutanix, Syslog_-_Open_Collector, Syslog_-_Open_Collector_-_AWS_CloudTrail, Syslog_-_Open_Collector_-_AWS_CloudWatch, Syslog_-_Open_Collector_-_AWS_Config_Events, Syslog_-_Open_Collector_-_AWS_Guard_Duty, Syslog_-_Open_Collector_-_AWS_S3, Syslog_-_Open_Collector_-_Azure_Event_Hub, Syslog_-_Open_Collector_-_Carbon_Black_Cloud, Syslog_-_Open_Collector_-_CarbonBlackBeat_Heartbeat, Syslog_-_Open_Collector_-_Cisco_AMP, Syslog_-_Open_Collector_-_Cisco_Umbrella, Syslog_-_Open_Collector_-_CiscoAMPBeat_Heartbeat, Syslog_-_Open_Collector_-_Duo_Authentication_Security, Syslog_-_Open_Collector_-_DuoBeat_Heartbeat, Syslog_-_Open_Collector_-_EventHubBeat_Heartbeat, Syslog_-_Open_Collector_-_GCP_Audit, Syslog_-_Open_Collector_-_GCP_Cloud_Key_Management_Service, Syslog_-_Open_Collector_-_GCP_Http_Load_Balancer, Syslog_-_Open_Collector_-_GCP_Pub_Sub, Syslog_-_Open_Collector_-_GCP_Security_Command_Center, Syslog_-_Open_Collector_-_GCP_Virtual_Private_Cloud, Syslog_-_Open_Collector_-_Gmail_Message_Tracking, Syslog_-_Open_Collector_-_GMTBeat_Heartbeat, Syslog_-_Open_Collector_-_GSuite, Syslog_-_Open_Collector_-_GSuiteBeat_Heartbeat, Syslog_-_Open_Collector_-_Metricbeat, Syslog_-_Open_Collector_-_Okta_System_Log, Syslog_-_Open_Collector_-_OktaSystemLogBeat_Heartbeat, Syslog_-_Open_Collector_-_PubSubBeat_Heartbeat, Syslog_-_Open_Collector_-_S3Beat_Heartbeat, Syslog_-_Open_Collector_-_Sophos_Central, Syslog_-_Open_Collector_-_SophosCentralBeat_Heartbeat, Syslog_-_Open_Collector_-_Webhook, Syslog_-_Open_Collector_-_Webhook_OneLogin, Syslog_-_Open_Collector_-_Webhook_Zoom, Syslog_-_Open_Collector_-_WebhookBeat_Heartbeat, Syslog_-_Opengear_Console, Syslog_-_OpenLDAP, Syslog_-_Oracle_10g_Audit_Trail, Syslog_-_Oracle_11g_Audit_Trail, Syslog_-_OSSEC_Alerts, Syslog_-_Other, Syslog_-_Outpost24, Syslog_-_Palo_Alto_Cortex_XDR, Syslog_-_Palo_Alto_Custom_Pipe, Syslog_-_Palo_Alto_Firewall, Syslog_-_Palo_Alto_Traps_CEF, Syslog_-_Palo_Alto_Traps_Management_Service, Syslog_-_Password_Manager_Pro, Syslog_-_pfSense_Firewall, Syslog_-_PingFederate_7.2, Syslog_-_PingFederate_CEF, Syslog_-_Polycom, Syslog_-_Postfix, Syslog_-_Procera_PacketLogic, Syslog_-_Proofpoint_Spam_Firewall, Syslog_-_Protegrity_Defiance_DPS, Syslog_-_QLogic_Infiniband_Switch, Syslog_-_Quest_Defender, Syslog_-_Radiator_Radius, Syslog_-_RADiFlow_3180_Switch, Syslog_-_Radware_Alteon_Load_Balancer, Syslog_-_Radware_DefensePro, Syslog_-_Radware_Web_Server_Director_Audit_Log, Syslog_-_Raritan_KVM, Syslog_-_Raz-Lee, Syslog_-_RedSeal, Syslog_-_Riverbed, Syslog_-_RSA_ACE, Syslog_-_RSA_Authentication_Manager_v7.1, Syslog_-_RSA_Authentication_Manager_v8.x, Syslog_-_RSA_Web_Threat_Detection, Syslog_-_RSA_Web_Threat_Detection_5.1, Syslog_-_RuggedRouter, Syslog_-_Safenet, Syslog_-_Sailpoint, Syslog_-_Sauce_Labs, Syslog_-_SecureAuth_IdP, Syslog_-_SecureAuth_IdP_v9, Syslog_-_SecureLink, Syslog_-_SecureTrack, Syslog_-_SEL_3610_Port_Switch, Syslog_-_SEL_3620_Ethernet_Security_Gateway, Syslog_-_Sentinel_IPS, Syslog_-_SentinelOne_CEF, Syslog_-_Sguil, Syslog_-_Siemens_Scalance_X400, Syslog_-_Smoothwall_Firewall, Syslog_-_SnapGear_Firewall, Syslog_-_Snare_Windows_2003_Event_Log, Syslog_-_Snare_Windows_2008_Event_Log, Syslog_-_Snort_IDS, Syslog_-_Solaris_(Snare), Syslog_-_Solaris_Host, Syslog_-_SonicWALL, Syslog_-_SonicWALL_SSL-VPN, Syslog_-_Sophos_Email_Encryption_Appliance, Syslog_-_Sophos_UTM, Syslog_-_Sophos_Web_Proxy, Syslog_-_Sophos_XG_Firewall, Syslog_-_Sourcefire_IDS_3D, Syslog_-_Sourcefire_RNA, Syslog_-_Spectracom_Network_Time_Server, Syslog_-_Splunk_API_-_Checkpoint_Firewall, Syslog_-_Splunk_API_-_Cisco_Netflow_V9, Syslog_-_Splunk_API_-_Nessus_Vulnerability_Scanner, Syslog_-_Squid_Proxy, Syslog_-_StealthBits_Activity_Monitor, Syslog_-_STEALTHbits_StealthINTERCEPT, Syslog_-_StoneGate_Firewall, Syslog_-_Stonesoft_IPS, Syslog_-_Stormshield_Network_Security_Firewall, Syslog_-_Sycamore_Networks_DNX-88, Syslog_-_Sygate_Firewall, Syslog_-_Symantec_Advanced_Threat_Protection_(ATP)_CEF, Syslog_-_Symantec_DLP_CEF, Syslog_-_Symantec_Endpoint_Server, Syslog_-_Symantec_Messaging_Gateway, Syslog_-_Symantec_PGP_Gateway, Syslog_-_Symbol_Wireless_Access_Point, Syslog_-_Tanium, Syslog_-_Temporary_LST-2, Syslog_-_Tenable_SecurityCenter, Syslog_-_Thycotic_Secret_Server, Syslog_-_Tipping_Point_IPS, Syslog_-_Tipping_Point_SSL_Reverse_Proxy, Syslog_-_Top_Layer_IPS, Syslog_-_Townsend_Alliance_LogAgent, Syslog_-_Trend_Micro_Control_Manager_CEF, Syslog_-_Trend_Micro_Deep_Discovery_Inspector, Syslog_-_Trend_Micro_Deep_Security_CEF, Syslog_-_Trend_Micro_Deep_Security_LEEF, Syslog_-_Trend_Micro_IWSVA, Syslog_-_Trend_Micro_Vulnerability_Protection_Manager, Syslog_-_Tripwire, Syslog_-_Trustwave_NAC, Syslog_-_Trustwave_Secure_Web_Gateway, Syslog_-_Trustwave_Web_Application_Firewall, Syslog_-_Tufin, Syslog_-_Tumbleweed_Mailgate_Server, Syslog_-_Ubiquiti_UniFi_Security_Gateway, Syslog_-_Ubiquiti_UniFi_Switch, Syslog_-_Ubiquiti_UniFi_WAP, Syslog_-_Untangle, Syslog_-_Vamsoft_ORF, Syslog_-_Vanguard_Active_Alerts, Syslog_-_Varonis_DatAlert, Syslog_-_Vasco_Digipass_Identikey_Server, Syslog_-_Vectra_Networks, Syslog_-_Versa_Networks_SD-WAN, Syslog_-_VMWare_ESX/ESXi_Server, Syslog_-_VMware_Horizon_View, Syslog_-_VMWare_NSX/NSX-T, Syslog_-_VMWare_Unified_Access_Gateway, Syslog_-_VMWare_vCenter_Server, Syslog_-_VMWare_vShield, Syslog_-_Voltage_Securemail, Syslog_-_Vormetric_CoreGuard, Syslog_-_Vormetric_Data_Security_Manager, Syslog_-_WALLIX_Bastion, Syslog_-_Watchguard_FireBox, Syslog_-_WS2000_Wireless_Access_Point, Syslog_-_Wurldtech_SmartFirewall, Syslog_-_Xirrus_Wireless_Array, Syslog_-_Zimbra_System_Log, Syslog_-_Zix_E-mail_Encryption, Syslog_-_Zscaler_Nano_Streaming_Service, Syslog_-_ZXT_Load_Balancer, Syslog_-_ZyWALL_VPN_Firewall, Syslog_Avaya_G450_Media_Gateway, Syslog_File_-_AIX_Host, Syslog_File_-_BSD_Format, Syslog_File_-_HP-UX_Host, Syslog_File_-_IRIX_Host, Syslog_File_-_Linux_Host, Syslog_File_-_LogRhythm_Syslog_Generator, Syslog_File_-_MS_2003_Event_Log_(Snare), Syslog_File_-_Oracle_10g_Audit_Trail, Syslog_File_-_Oracle_11g_Audit_Trail, Syslog_File_-_Solaris_Host, UDLA_-_CA_Single_Sign-On, UDLA_-_Deepnet_DualShield, UDLA_-_Drupal, UDLA_-_Finacle_Core, UDLA_-_Finacle_Treasury_Logs, UDLA_-_Forcepoint, UDLA_-_Gallagher_Command_Centre, UDLA_-_iManage_Worksite, UDLA_-_ISS_Proventia_SiteProtector_-_IPS, UDLA_-_LogRhythm_Enterprise_Monitoring_Solution, UDLA_-_LREnhancedAudit, UDLA_-_McAfee_ePolicy_Orchestrator_-_Universal_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_3.6_-_Events, UDLA_-_McAfee_ePolicy_Orchestrator_4.0_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_4.5_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.0_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.1_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.3_-_ePOEvents, UDLA_-_McAfee_ePolicy_Orchestrator_5.9_-_ePOEvents, UDLA_-_McAfee_Network_Access_Control, UDLA_-_McAfee_Network_Security_Manager, UDLA_-_Microsoft_System_Center_2012_Endpoint_Protection, UDLA_-_ObserveIT, UDLA_-_Oracle_10g_Audit_Trail, UDLA_-_Oracle_11g_Audit_Trail, UDLA_-_Oracle_12C_Unified_Auditing, UDLA_-_Oracle_9i_Audit_Trail, UDLA_-_Other, UDLA_-_SEL_3530_RTAC, UDLA_-_SharePoint_2007_AuditData, UDLA_-_SharePoint_2010_EventData, UDLA_-_SharePoint_2013_EventData, UDLA_-_Siemens_Invision, UDLA_-_Sophos_Anti-Virus, UDLA_-_Sophos_Endpoint_Security_and_Control, UDLA_-_Symantec_CSP, UDLA_-_Symantec_SEP, UDLA_-_Symmetry_Access_Control, UDLA_-_VMWare_vCenter_Server, UDLA_-_VMWare_vCloud, VLS_-_Syslog_-_Infoblox_-_DNS_RPZ, VLS_-_Syslog_-_Infoblox_-_Threat_Protection. | Optional | 
| host_name | Impacted host name. | Optional | 
| username | Username. | Optional | 
| subject | Email subject. | Optional | 
| sender | Email sender. | Optional | 
| recipient | Email recipient. | Optional | 
| hash | Hash code of the event. | Optional | 
| url | URL of the event. | Optional | 
| process_name | Process name. | Optional | 
| object | Log object. | Optional | 
| ip_address | IP address of the endpoint. | Optional | 
| max_message | Maximum number of log messages to query. Default is 100. | Optional | 
| query_timeout | The query timeout in seconds. Default is 60. | Optional | 
| entity_id | Entity ID. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| page_size | Page size. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Search.TaskId | String | The task ID returned from the database for the current search. This is actually the search GUID. | 
| LogRhythm.Search.StatusMessage | String | The task status returned from the database for the current search. | 
| LogRhythm.Search.SearchName | String | The name of the search query in Cortex XSOAR. | 
| LogRhythm.Search.TaskStatus | String | Task status. | 
| LogRhythm.Search.Results.originEntityId | Number | Entity ID. | 
| LogRhythm.Search.Results.impactedIp | String | Impacted IP address. | 
| LogRhythm.Search.Results.classificationTypeName | String | Classification name. | 
| LogRhythm.Search.Results.logSourceName | String | Log source name. | 
| LogRhythm.Search.Results.entityName | String | Entity name. | 
| LogRhythm.Search.Results.normalDate | Date | Date. | 
| LogRhythm.Search.Results.vendorMessageId | String | Vendor log message. | 
| LogRhythm.Search.Results.priority | Number | Log priority. | 
| LogRhythm.Search.Results.sequenceNumber | String | Sequence number. | 
| LogRhythm.Search.Results.originHostId | Number | Origin host ID. | 
| LogRhythm.Search.Results.mpeRuleId | Number | Logrhythm rule ID. | 
| LogRhythm.Search.Results.originIp | String | Origin IP address. | 
| LogRhythm.Search.Results.mpeRuleName | String | Logrhythm rule name. | 
| LogRhythm.Search.Results.logSourceHostId | Number | Log source host ID. | 
| LogRhythm.Search.Results.originHost | String | Origin host. | 
| LogRhythm.Search.Results.logDate | Date | Log date. | 
| LogRhythm.Search.Results.classificationName | String | Log classification name. | 


#### Command Example
```!lr-execute-search-query number_of_days=5 entity_id=1 host_name=HOSTNAME```

#### Context Example
```json
{
    "LogRhythm": {
        "Search": {
            "Task": {
                "StatusMessage": "Success",
                "TaskId": "9a5533c6-dc18-46dc-9d9a-3e7461b5ca7a"
            }
        }
    }
}
```

#### Human Readable Output

>New search query created, Task ID=9a5533c6-dc18-46dc-9d9a-3e7461b5ca7a

### lr-get-query-result
***
Get the search query result for the specified task ID. The task ID can be retrieved from the lr-execute-search-query command.


#### Base Command

`lr-get-query-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. The task ID can be retrieved from the lr-execute-search-query command. | Required | 
| page_size | Page size. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Search.TaskStatus | String | Task status. | 
| LogRhythm.Search.TaskId | String | Task ID. | 
| LogRhythm.Search.Results.originEntityId | Number | Entity ID. | 
| LogRhythm.Search.Results.impactedIp | String | Impacted IP address. | 
| LogRhythm.Search.Results.classificationTypeName | String | Classification name. | 
| LogRhythm.Search.Results.logSourceName | String | Log source name. | 
| LogRhythm.Search.Results.entityName | String | Entity name. | 
| LogRhythm.Search.Results.normalDate | Date | Date. | 
| LogRhythm.Search.Results.vendorMessageId | String | Vendor log message. | 
| LogRhythm.Search.Results.priority | Number | Log priority. | 
| LogRhythm.Search.Results.sequenceNumber | String | Sequence number. | 
| LogRhythm.Search.Results.originHostId | Number | Origin host ID. | 
| LogRhythm.Search.Results.mpeRuleId | Number | Logrhythm rule ID. | 
| LogRhythm.Search.Results.originIp | String | Origin IP address. | 
| LogRhythm.Search.Results.mpeRuleName | String | Logrhythm rule name. | 
| LogRhythm.Search.Results.logSourceHostId | Number | Log source host ID. | 
| LogRhythm.Search.Results.originHost | String | Origin host. | 
| LogRhythm.Search.Results.logDate | Date | Log date. | 
| LogRhythm.Search.Results.classificationName | String | Log classification name. | 


#### Command Example
```!lr-get-query-result task_id=88e1a446-b49d-4197-b599-26d4b3d1d1ac```

#### Context Example
```json
{
    "LogRhythm": {
        "Search": {
            "Results": {
                "Items": [
                    {
                        "action": "none",
                        "classificationId": 1020,
                        "classificationName": "Authentication Success",
                        "classificationTypeName": "Audit",
                        "command": "authorizationsuccess",
                        "commonEventId": -1100516,
                        "commonEventName": "LogRhythm DX Authorization Success",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635624765372,
                        "keyField": "messageId",
                        "logDate": 1635624757414,
                        "logMessage": "2021-10-30 20:12:37.414 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]]",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "209782fc-e20e-4fb1-ae24-834e8aba893f",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1490984,
                        "mpeRuleName": "Authorization Success",
                        "normalDate": 1635624757437,
                        "normalDateHour": 1635624000000,
                        "normalDateMin": 1635624757437,
                        "normalMsgDateMax": 1635624757437,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 22,
                        "process": "data indexer has granted access to a user or service",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "columbo",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000030"
                    },
                    {
                        "action": "none",
                        "classificationId": 1020,
                        "classificationName": "Authentication Success",
                        "classificationTypeName": "Audit",
                        "command": "authorizationsuccess",
                        "commonEventId": -1100516,
                        "commonEventName": "LogRhythm DX Authorization Success",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635344585283,
                        "keyField": "messageId",
                        "logDate": 1635344579793,
                        "logMessage": "2021-10-27 14:22:59.793 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]]",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "c820d31f-181f-49bc-95bf-f8017fe43b28",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1490984,
                        "mpeRuleName": "Authorization Success",
                        "normalDate": 1635344579837,
                        "normalDateHour": 1635343200000,
                        "normalDateMin": 1635344579837,
                        "normalMsgDateMax": 1635344579837,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 22,
                        "process": "data indexer has granted access to a user or service",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "columbo",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000030"
                    },
                    {
                        "action": "none",
                        "classificationId": 1020,
                        "classificationName": "Authentication Success",
                        "classificationTypeName": "Audit",
                        "command": "authorizationsuccess",
                        "commonEventId": -1100516,
                        "commonEventName": "LogRhythm DX Authorization Success",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635624765372,
                        "keyField": "messageId",
                        "logDate": 1635624757382,
                        "logMessage": "2021-10-30 20:12:37.382 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]]",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "69480e5e-75d4-43ee-9cb1-cbd7e1bbf6ac",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1490984,
                        "mpeRuleName": "Authorization Success",
                        "normalDate": 1635624757405,
                        "normalDateHour": 1635624000000,
                        "normalDateMin": 1635624757405,
                        "normalMsgDateMax": 1635624757405,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 22,
                        "process": "data indexer has granted access to a user or service",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "columbo",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000030"
                    },
                    {
                        "action": "none",
                        "classificationId": 1400,
                        "classificationName": "Startup and Shutdown",
                        "classificationTypeName": "Audit",
                        "command": "servicestarting",
                        "commonEventId": -1100490,
                        "commonEventName": "LogRhythm DX Starting",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635206479279,
                        "keyField": "messageId",
                        "logDate": 1635206477020,
                        "logMessage": "2021-10-26 00:01:17.020 CODE=000001 MESSAGE=ServiceStarting HOST=HOSTNAME SEVERITY=Low SERVICENAME=carpenter TRIGGEREDWHEN=Any service is requested to start SUGGESTEDACTION=None ADDITIONALINFO=",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "5ce64f92-430c-4d4c-9279-0606daedd670",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1349761,
                        "mpeRuleName": "Sevice Starting",
                        "normalDate": 1635206477049,
                        "normalDateHour": 1635206400000,
                        "normalDateMin": 1635206477049,
                        "normalMsgDateMax": 1635206477049,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 31,
                        "process": "any service is requested to start",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "carpenter",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000001"
                    },
                    {
                        "action": "none",
                        "classificationId": 1020,
                        "classificationName": "Authentication Success",
                        "classificationTypeName": "Audit",
                        "command": "authorizationsuccess",
                        "commonEventId": -1100516,
                        "commonEventName": "LogRhythm DX Authorization Success",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635352038849,
                        "keyField": "messageId",
                        "logDate": 1635352029023,
                        "logMessage": "2021-10-27 16:27:09.023 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]]",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "c6d33902-89d3-4395-a240-56569f4d17a0",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1490984,
                        "mpeRuleName": "Authorization Success",
                        "normalDate": 1635352029071,
                        "normalDateHour": 1635350400000,
                        "normalDateMin": 1635352029071,
                        "normalMsgDateMax": 1635352029071,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 22,
                        "process": "data indexer has granted access to a user or service",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "columbo",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000030"
                    },
                    {
                        "action": "none",
                        "classificationId": 1020,
                        "classificationName": "Authentication Success",
                        "classificationTypeName": "Audit",
                        "command": "authorizationsuccess",
                        "commonEventId": -1100516,
                        "commonEventName": "LogRhythm DX Authorization Success",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635624745374,
                        "keyField": "messageId",
                        "logDate": 1635624729847,
                        "logMessage": "2021-10-30 20:12:09.847 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]]",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "8641126b-db6a-437f-9e67-07b9f51ee3e9",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1490984,
                        "mpeRuleName": "Authorization Success",
                        "normalDate": 1635624729870,
                        "normalDateHour": 1635624000000,
                        "normalDateMin": 1635624729870,
                        "normalMsgDateMax": 1635624729870,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 22,
                        "process": "data indexer has granted access to a user or service",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "columbo",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000030"
                    },
                    {
                        "action": "none",
                        "classificationId": 1400,
                        "classificationName": "Startup and Shutdown",
                        "classificationTypeName": "Audit",
                        "command": "servicestarted",
                        "commonEventId": -1100491,
                        "commonEventName": "LogRhythm DX Started",
                        "count": 1,
                        "direction": 1,
                        "directionName": "Local",
                        "entityId": 1,
                        "entityName": "Primary Site",
                        "impactedEntityId": 1,
                        "impactedEntityName": "Primary Site",
                        "impactedHost": "HOSTNAME *",
                        "impactedHostId": 1,
                        "impactedHostName": "HOSTNAME",
                        "impactedZoneName": "Internal",
                        "indexedDate": 1635624839736,
                        "insertedDate": 1635206489338,
                        "keyField": "messageId",
                        "logDate": 1635206479386,
                        "logMessage": "2021-10-26 00:01:19.386 CODE=000002 MESSAGE=ServiceStarted HOST=HOSTNAME SEVERITY=Low SERVICENAME=carpenter TRIGGEREDWHEN=Any service completes startup SUGGESTEDACTION=None ADDITIONALINFO=",
                        "logSourceHost": "HOSTNAME",
                        "logSourceHostId": 1,
                        "logSourceHostName": "HOSTNAME",
                        "logSourceId": 16,
                        "logSourceName": "LogrhythmDXMonitor",
                        "logSourceType": 1000648,
                        "logSourceTypeName": "Flat File - LogRhythm Data Indexer Monitor",
                        "messageId": "88997979-edf6-4b1f-82ed-7ebbd7bcce46",
                        "messageTypeEnum": 1,
                        "mpeRuleId": 1349763,
                        "mpeRuleName": "Service Started",
                        "normalDate": 1635206479415,
                        "normalDateHour": 1635206400000,
                        "normalDateMin": 1635206479415,
                        "normalMsgDateMax": 1635206479415,
                        "originEntityId": 1,
                        "originEntityName": "Primary Site",
                        "originHost": "HOSTNAME *",
                        "originHostId": 1,
                        "originHostName": "HOSTNAME",
                        "originName": "HOSTNAME",
                        "originZone": 0,
                        "originZoneName": "Internal",
                        "priority": 31,
                        "process": "any service completes startup",
                        "protocolId": -1,
                        "rootEntityId": 1,
                        "rootEntityName": "Primary Site",
                        "serviceId": -1000012,
                        "serviceName": "LogRhythm Data Indexer",
                        "session": "carpenter",
                        "severity": "low",
                        "subject": "none",
                        "vendorMessageId": "000002"
                    }
                ],
                "TaskId": "88e1a446-b49d-4197-b599-26d4b3d1d1ac",
                "TaskStatus": "Completed: All Results"
            }
        }
    }
}
```

#### Human Readable Output

>### Search results for task 88e1a446-b49d-4197-b599-26d4b3d1d1ac
>|Action|Classification Id|Classification Name|Classification Type Name|Command|Common Event Id|Common Event Name|Count|Direction|Direction Name|Entity Id|Entity Name|Impacted Entity Id|Impacted Entity Name|Impacted Host|Impacted Host Id|Impacted Host Name|Impacted Zone Name|Indexed Date|Inserted Date|Key Field|Log Date|Log Message|Log Source Host|Log Source Host Id|Log Source Host Name|Log Source Id|Log Source Name|Log Source Type|Log Source Type Name|Message Id|Message Type Enum|Mpe Rule Id|Mpe Rule Name|Normal Date|Normal Date Hour|Normal Date Min|Normal Msg Date Max|Origin Entity Id|Origin Entity Name|Origin Host|Origin Host Id|Origin Host Name|Origin Name|Origin Zone|Origin Zone Name|Priority|Process|Protocol Id|Root Entity Id|Root Entity Name|Service Id|Service Name|Session|Severity|Subject|Vendor Message Id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| none | 1020 | Authentication Success | Audit | authorizationsuccess | -1100516 | LogRhythm DX Authorization Success | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635624765372 | messageId | 1635624757414 | 2021-10-30 20:12:37.414 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]] | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | 209782fc-e20e-4fb1-ae24-834e8aba893f | 1 | 1490984 | Authorization Success | 1635624757437 | 1635624000000 | 1635624757437 | 1635624757437 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 22 | data indexer has granted access to a user or service | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | columbo | low | none | 000030 |
>| none | 1020 | Authentication Success | Audit | authorizationsuccess | -1100516 | LogRhythm DX Authorization Success | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635344585283 | messageId | 1635344579793 | 2021-10-27 14:22:59.793 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]] | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | c820d31f-181f-49bc-95bf-f8017fe43b28 | 1 | 1490984 | Authorization Success | 1635344579837 | 1635343200000 | 1635344579837 | 1635344579837 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 22 | data indexer has granted access to a user or service | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | columbo | low | none | 000030 |
>| none | 1020 | Authentication Success | Audit | authorizationsuccess | -1100516 | LogRhythm DX Authorization Success | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635624765372 | messageId | 1635624757382 | 2021-10-30 20:12:37.382 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]] | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | 69480e5e-75d4-43ee-9cb1-cbd7e1bbf6ac | 1 | 1490984 | Authorization Success | 1635624757405 | 1635624000000 | 1635624757405 | 1635624757405 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 22 | data indexer has granted access to a user or service | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | columbo | low | none | 000030 |
>| none | 1400 | Startup and Shutdown | Audit | servicestarting | -1100490 | LogRhythm DX Starting | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635206479279 | messageId | 1635206477020 | 2021-10-26 00:01:17.020 CODE=000001 MESSAGE=ServiceStarting HOST=HOSTNAME SEVERITY=Low SERVICENAME=carpenter TRIGGEREDWHEN=Any service is requested to start SUGGESTEDACTION=None ADDITIONALINFO= | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | 5ce64f92-430c-4d4c-9279-0606daedd670 | 1 | 1349761 | Sevice Starting | 1635206477049 | 1635206400000 | 1635206477049 | 1635206477049 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 31 | any service is requested to start | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | carpenter | low | none | 000001 |
>| none | 1020 | Authentication Success | Audit | authorizationsuccess | -1100516 | LogRhythm DX Authorization Success | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635352038849 | messageId | 1635352029023 | 2021-10-27 16:27:09.023 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]] | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | c6d33902-89d3-4395-a240-56569f4d17a0 | 1 | 1490984 | Authorization Success | 1635352029071 | 1635350400000 | 1635352029071 | 1635352029071 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 22 | data indexer has granted access to a user or service | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | columbo | low | none | 000030 |
>| none | 1020 | Authentication Success | Audit | authorizationsuccess | -1100516 | LogRhythm DX Authorization Success | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635624745374 | messageId | 1635624729847 | 2021-10-30 20:12:09.847 CODE=000030 MESSAGE=AuthorizationSuccess HOST=HOSTNAME SEVERITY=Low SERVICENAME=columbo TRIGGEREDWHEN=Data Indexer has granted access to a user or service SUGGESTEDACTION=None ADDITIONALINFO=[Name:[lr-soap-api]][Role:[globalAdmin]][PersonID:[1]][ID:[1af934a9-4a1e-46ac-9201-63d33f884347]][Action:[search]] | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | 8641126b-db6a-437f-9e67-07b9f51ee3e9 | 1 | 1490984 | Authorization Success | 1635624729870 | 1635624000000 | 1635624729870 | 1635624729870 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 22 | data indexer has granted access to a user or service | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | columbo | low | none | 000030 |
>| none | 1400 | Startup and Shutdown | Audit | servicestarted | -1100491 | LogRhythm DX Started | 1 | 1 | Local | 1 | Primary Site | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | Internal | 1635624839736 | 1635206489338 | messageId | 1635206479386 | 2021-10-26 00:01:19.386 CODE=000002 MESSAGE=ServiceStarted HOST=HOSTNAME SEVERITY=Low SERVICENAME=carpenter TRIGGEREDWHEN=Any service completes startup SUGGESTEDACTION=None ADDITIONALINFO= | HOSTNAME | 1 | HOSTNAME | 16 | LogrhythmDXMonitor | 1000648 | Flat File - LogRhythm Data Indexer Monitor | 88997979-edf6-4b1f-82ed-7ebbd7bcce46 | 1 | 1349763 | Service Started | 1635206479415 | 1635206400000 | 1635206479415 | 1635206479415 | 1 | Primary Site | HOSTNAME * | 1 | HOSTNAME | HOSTNAME | 0 | Internal | 31 | any service completes startup | -1 | 1 | Primary Site | -1000012 | LogRhythm Data Indexer | carpenter | low | none | 000002 |


### lr-add-host
***
Add a new host to an entity.


#### Base Command

`lr-add-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity-id | The entity ID for the host. | Optional | 
| entity-name | The entity name for the host. | Required | 
| name | The name of the host. | Required | 
| short-description | A brief description of the component. | Optional | 
| long-description | A full description of the component. | Optional | 
| risk-level | The host risk level. Possible values: "None", "Low-Low", "Low-Medium", "Low-High", "Medium-Low", "Medium-Medium", "Medium-High", "High-Low", "High-Medium", and "High-High". Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. | Required | 
| threat-level | The host threat level. Possible values: "None", "Low-Low", "Low-Medium", "Low-High", "Medium-Low", "Medium-Medium", "Medium-High", "High-Low", "High-Medium", and "High-High". Possible values are: None, Low-Low, Low-Medium, Low-High, Medium-Low, Medium-Medium, Medium-High, High-Low, High-Medium, High-High. | Optional | 
| threat-level-comments | Comments for the host threat level. | Optional | 
| host-status | The host status. Possible values: "Retired" and "Active". Possible values are: Retired, Active. | Required | 
| host-zone | The host zone. Possible values: "External", "DMZ", and "Internal". Possible values are: External, DMZ, Internal. | Required | 
| use-eventlog-credentials | Whether to use the event log credentials. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| os-type | The Agent server type on which the operating system is installed. Possible values: "None", "Server", and "Desktop". Possible values are: None, Server, Desktop. | Optional | 
| os | The operating system type supported by LogRhythm. Possible values: "Unknown", "Other", "WindowsNT4","Windows2000Professional", "Windows2000Server", "Windows2003Standard", "Windows2003Enterprise", "Windows95", "WindowsXP", "WindowsVista", "Linux", "Solaris", "AIX", "HPUX", and "Windows". Possible values are: Unknown, Other, WindowsNT4, Windows2000Professional, Windows2000Server, Windows2003Standard, Windows2003Enterprise, Windows95, WindowsXP, WindowsVista, Linux, Solaris, AIX, HPUX, Windows. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Host.id | Number | The host ID. | 
| LogRhythm.Host.entity.id | Number | The host entity ID. | 
| LogRhythm.Host.entity.name | String | The host entity name. | 
| LogRhythm.Host.name | String | The host name. | 
| LogRhythm.Host.riskLevel | String | The host risk level | 
| LogRhythm.Host.threatLevel | String | The host threat level. | 
| LogRhythm.Host.threatLevelComments | String | The threat level comments. | 
| LogRhythm.Host.recordStatusName | String | The host record status name. | 
| LogRhythm.Host.hostZone | String | The host zone. | 
| LogRhythm.Host.location.id | Number | The host location ID. | 
| LogRhythm.Host.os | String | The operating system type supported by LogRhythm. | 
| LogRhythm.Host.useEventlogCredentials | Boolean | Whether to use the event log credentials. | 
| LogRhythm.Host.osType | String | The agent server type on which the operating system is installed. | 
| LogRhythm.Host.dateUpdated | Date | The date the host was updated. | 


#### Command Example
```!lr-add-host entity-name=`Global Entity` host-status=Retired host-zone=DMZ name=test_host223322 os=AIX risk-level="High-High" use-eventlog-credentials=false```

#### Context Example
```json
{
    "LogRhythm": {
        "Host": {
            "dateUpdated": "2021-10-30T20:33:51.01Z",
            "entity": {
                "id": -100,
                "name": "Global Entity"
            },
            "hostZone": "DMZ",
            "id": 9,
            "location": {
                "id": -1
            },
            "name": "test_host223322",
            "os": "AIX",
            "osType": "Server",
            "recordStatusName": "Retired",
            "riskLevel": "High-High",
            "threatLevel": "None",
            "threatLevelComments": "",
            "useEventlogCredentials": false
        }
    }
}
```

#### Human Readable Output

>### Host added successfully
>|Date Updated|Entity|Host Zone|Id|Location|Name|Os|Os Type|Record Status Name|Risk Level|Threat Level|Threat Level Comments|Use Eventlog Credentials|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-10-30T20:33:51.01Z | id: -100<br/>name: Global Entity | DMZ | 9 | id: -1 | test_host223322 | AIX | Server | Retired | High-High | None |  | false |


### endpoint
***
Returns information about an endpoint.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 

#### Command Example
```!endpoint hostname=HOSTNAME```

#### Context Example
```json
{
    "Endpoint": {
        "Hostname": "HOSTNAME",
        "ID": 1,
        "OS": "Windows",
        "OSVersion": "Microsoft Windows NT 10.0.17763.0",
        "Status": "Online"
    }
}
```

#### Human Readable Output

>### Logrhythm endpoint
>|Date Updated|Entity|Host Identifiers|Host Roles|Host Zone|Id|Location|Name|Os|Os Type|Os Version|Record Status Name|Risk Level|Short Desc|Threat Level|Threat Level Comments|Use Eventlog Credentials|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-07-29T14:55:16.427Z | id: 1<br/>name: Primary Site | {'type': 'WindowsName', 'value': 'HOSTNAME', 'dateAssigned': '2021-07-27T15:55:40.717Z'},<br/>{'type': 'IPAddress', 'value': '127.0.0.1', 'dateAssigned': '2021-07-27T15:55:40.717Z'} |  | Internal | 1 | id: -1 | HOSTNAME | Windows | Server | Microsoft Windows NT 10.0.17763.0 | Active | Medium-Medium | This is the LogRhythm Platform Manager host. | None |  | false |


### lr-hosts-status-update
***
Updates the status of a host to retire or active.


#### Base Command

`lr-hosts-status-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID. | Required | 
| host_status | The host status. Possible values: "Retired" and "Active". Possible values are: Retired, Active. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!lr-hosts-status-update host_id=7 host_status=Active```

#### Human Readable Output

>Host status updated successfully to Active.

### lr-networks-list
***
Returns all networks that match the specified criteria.


#### Base Command

`lr-networks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | Filter by network ID. | Optional | 
| name | Filter by name. | Optional | 
| record_status | Filter by object record status. Possible values: "all", "retired", "active". Possible values are: all, retired, active. | Optional | 
| bip | The starting IP address to allow records to be filtered on a specified IP address, e.g., 127.0.0.1. | Optional | 
| eip | The ending IP address to allow records to be filtered on a specified IP address, e.g., 127.0.0.1. | Optional | 
| count | The numbers of networks to return. Default is 50. | Optional | 
| offset | The number of networks to skip before starting to collect the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LogRhythm.Network.entity.id | Number | The network entity ID. | 
| LogRhythm.Network.entity.name | String | The network entity name. | 
| LogRhythm.Network.name | String | The network name. | 
| LogRhythm.Network.shortDesc | String | The network short description. | 
| LogRhythm.Network.longDesc | String | The network long description. | 
| LogRhythm.Network.riskLevel | String | The network risk level. | 
| LogRhythm.Network.threatLevel | String | The network threat level. | 
| LogRhythm.Network.threatLevelComment | String | The threat level comments | 
| LogRhythm.Network.recordStatusName | String | The network record status name. | 
| LogRhythm.Network.hostZone | String | The network zone. | 
| LogRhythm.Network.location.id | Number | The network location ID. | 
| LogRhythm.Network.location.name | String | The network location name. | 
| LogRhythm.Network.bip | String | Starting IP address. | 
| LogRhythm.Network.eip | String | Ending IP address. | 
| LogRhythm.Network.dateUpdated | Date | The date the network was last updated. | 
| LogRhythm.Network.id | Number | The network ID. | 


#### Command Example
```!lr-networks-list count=2```

#### Context Example
```json
{
    "LogRhythm": {
        "Network": [
            {
                "bip": "1.1.1.1",
                "dateUpdated": "2021-10-12T13:48:43.133Z",
                "eip": "2.2.2.2",
                "entity": {
                    "id": -100,
                    "name": "Global Entity"
                },
                "hostZone": "Internal",
                "id": 1,
                "location": {
                    "id": 1,
                    "name": "Andorra"
                },
                "longDesc": "This is a test network",
                "name": "Test network",
                "recordStatusName": "Active",
                "riskLevel": "None",
                "shortDesc": "This is a test network",
                "threatLevel": "None",
                "threatLevelComment": "string"
            },
            {
                "bip": "127.0.0.1",
                "dateUpdated": "2021-10-12T14:01:21.54Z",
                "eip": "127.0.0.2",
                "entity": {
                    "id": -100,
                    "name": "Global Entity"
                },
                "hostZone": "Internal",
                "id": 2,
                "location": {
                    "id": 1,
                    "name": "Andorra"
                },
                "longDesc": "This is a test network",
                "name": "Test network2",
                "recordStatusName": "Active",
                "riskLevel": "None",
                "shortDesc": "This is a test network",
                "threatLevel": "None",
                "threatLevelComment": "string"
            }
        ]
    }
}
```

#### Human Readable Output

>### Networks
>|Id|Name|Short Desc|Long Desc|Record Status Name|Bip|Eip|Entity|Risk Level|Date Updated|Threat Level|Threat Level Comment|Host Zone|Location|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | Test network | This is a test network | This is a test network | Active | 1.1.1.1 | 2.2.2.2 | id: -100<br/>name: Global Entity | None | 2021-10-12T13:48:43.133Z | None | string | Internal | id: 1<br/>name: Andorra |
>| 2 | Test network2 | This is a test network | This is a test network | Active | 127.0.0.1 | 127.0.0.2 | id: -100<br/>name: Global Entity | None | 2021-10-12T14:01:21.54Z | None | string | Internal | id: 1<br/>name: Andorra |


## Breaking changes from the previous version of this integration - LogRhythmRest v2
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *lr-execute-query*
* *lr-get-persons*
* *lr-get-logins*
* *lr-get-privileges*
* *lr-get-profiles*
* *lr-add-login*
* *lr-add-user*
* *lr-get-hosts-by-entity* - this command was replaced by *lr-hosts-list*.
* *lr-update-host-status* - this command was replaced by *lr-hosts-status-update*.
* *lr-get-networks* - this command was replaced by *lr-networks-list*.
* *lr-get-hosts* - this command was replaced by *lr-hosts-list*.
* *lr-get-alarm-data* - this command was replaced by *lr-alarms-list*.
* *lr-get-alarm-events* - this command was replaced by *lr-alarm-events-list*.
* *lr-get-case-evidence* - this command was replaced by *lr-case-evidence-list*.
* *lr-get-users* - this command was replaced by *lr-users-list*.


### Arguments
#### The following arguments were removed in this version:

In the *lr-execute-search-query* command:
* *max_massage* - this argument was replaced by *max_message*.

### Outputs
#### The following outputs were removed in this version:

In the *lr-add-host* command:
* *Logrhythm.Host.EntityId* - this output was replaced by *LogRhythm.Host.entity.id*.
* *Logrhythm.Host.EntityName* - this output was replaced by *LogRhythm.Host.entity.name*.
* *Logrhythm.Host.Status* - this output was replaced by *LogRhythm.Host.recordStatusName*.

In the *lr-get-query-result* command:
* *Logrhythm.Search.Results.TaskStatus* - this output was replaced by *LogRhythm.Search.TaskStatus*.
* *Logrhythm.Search.Results.TaskID* - this output was replaced by *LogRhythm.Search.TaskId*.
* *Logrhythm.Search.Results.Items.originEntityId* - this output was replaced by *LogRhythm.Search.Results.originEntityId*.
* *Logrhythm.Search.Results.Items.impactedIp* - this output was replaced by *LogRhythm.Search.Results.impactedIp*.
* *Logrhythm.Search.Results.Items.classificationTypeName* - this output was replaced by *LogRhythm.Search.Results.classificationTypeName*.
* *Logrhythm.Search.Results.Items.logSourceName* - this output was replaced by *LogRhythm.Search.Results.logSourceName*.
* *Logrhythm.Search.Results.Items.entityName* - this output was replaced by *LogRhythm.Search.Results.entityName*.
* *Logrhythm.Search.Results.Items.normalDate* - this output was replaced by *LogRhythm.Search.Results.normalDate*.
* *Logrhythm.Search.Results.Items.vendorMessageId* - this output was replaced by *LogRhythm.Search.Results.vendorMessageId*.
* *Logrhythm.Search.Results.Items.priority* - this output was replaced by *LogRhythm.Search.Results.priority*.
* *Logrhythm.Search.Results.Items.sequenceNumber* - this output was replaced by *LogRhythm.Search.Results.sequenceNumber*.
* *Logrhythm.Search.Results.Items.originHostId* - this output was replaced by *LogRhythm.Search.Results.originHostId*.
* *Logrhythm.Search.Results.Items.mpeRuleId* - this output was replaced by *LogRhythm.Search.Results.mpeRuleId*.
* *Logrhythm.Search.Results.Items.originIp* - this output was replaced by *LogRhythm.Search.Results.originIp*.
* *Logrhythm.Search.Results.Items.mpeRuleName* - this output was replaced by *LogRhythm.Search.Results.mpeRuleName*.
* *Logrhythm.Search.Results.Items.logSourceHostId* - this output was replaced by *LogRhythm.Search.Results.logSourceHostId*.
* *Logrhythm.Search.Results.Items.originHost* - this output was replaced by *LogRhythm.Search.Results.originHost*.
* *Logrhythm.Search.Results.Items.logDate* - this output was replaced by *LogRhythm.Search.Results.logDate*.
* *Logrhythm.Search.Results.Items.classificationName* - this output was replaced by *LogRhythm.Search.Results.classificationName*.

In the *lr-execute-search-query* command:
* *Logrhythm.Search.Task.TaskID* - this output was replaced by *LogRhythm.Search.TaskId*.