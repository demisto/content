The SolarWinds integration interacts with the SWIS API to allow users to fetch alerts and events. It also provides commands to retrieve lists of alerts and events.
This integration was integrated and tested with version 3.0.0 of SolarWinds Information Service (SWIS API).

## SolarWinds Help

The SolarWinds integration requires installation of SolarWinds Orion Platform which consolidates the full suite of monitoring capabilities into one platform. The following products used in this integration are managed under Orion

- Network Performance Manager
- Netflow Traffic Analyzer
- Network Configuration Manager
- IP Address Manager
- Log Analyzer
- Server and Application Monitor

## How to install SolarWinds Orion Platform

Follow this [link](https://documentation.solarwinds.com/en/success_center/orionplatform/content/install-new-deployment.htm) to view a comprehensive guide on how to install Orion and the managed products.

## Configure SolarWinds in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name or IP address of the Orion server | Name or IP address of the Orion server you want to connect to. Do not specify the port number. Examples: myorigin.mydomain.local, 12.153.24.2 | True |
| Username of the account | Admin can create users such as guests from the Orion platform and provide access permission according to need. | True |
| Type of incident to be fetched | Note: 'Type of incident to be fetched' and 'Incident type' should be the same to fetch similar types of incidents. | False |
| Maximum number of incidents per fetch | The maximum limit is 1000. | False |
| First fetch time interval | Date or relative timestamp to start fetching incidents from. For Alert, incidents will be fetched based on triggered date. For Event, the incidents will be fetched based on event time. \( Formats accepted:  2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc.\). | False |
| Severity levels | Fetch list of alerts as per the severity level. If not specified, it fetches all the incidents.<br/>Note: Severity level is only available for alerts. | False |
| Object Types | Filter alerts based on the type of property to monitor. If not specified, it will fetch all types of alerts. To list additional object types, use the query 'SELECT DISTINCT ObjectType FROM Orion.AlertConfigurations' in the swis-query command. | False |
| Event Types | Filter events based on the type. If not specified, it will fetch all types of events. To list additional event types, use query 'SELECT Name FROM Orion.EventTypes' in swis-query command. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### swis-event-list
***
Retrieves a list of events on the filter values provided in the command arguments.


#### Base Command

`swis-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acknowledged | Whether to retrieve events that are acknowledged. If true, then retrieves all acknowledged events.<br/>Possible values: true and false. | Optional | 
| event_id | A comma-separated ist of event IDs.<br/>Note: event_id supports integer values (int64). | Optional | 
| event_type | A comma-separated list of event types. For example: Warning, Informational, Node Up, etc. | Optional | 
| node | To retrieve events of specific nodes. | Optional | 
| sort_key | Key by which the response will be sorted.<br/>For example: EventID, EventTime, Message, TimeStamp, EventTypeName, Node, etc. Default is EventID. | Optional | 
| sort_order | Order by which the response will be sorted. Possible values: ascending and descending. Default is ascending. | Optional | 
| page | The page number from which retrieve events. By default, the per-page limit is 50 events. You can change this value in the limit argument. Default is 0. | Optional | 
| limit | The maximum number of records to be retrieved.<br/>Note: The maximum value supported by the limit is maxValue int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SolarWinds.Event.EventID | Number | Event ID of the triggered event. | 
| SolarWinds.Event.EventTime | Date | Timestamp at which the event is triggered. | 
| SolarWinds.Event.NetworkNode | Number | Network node ID of a triggered event. | 
| SolarWinds.Event.Node | String | Network node of a triggered event. | 
| SolarWinds.Event.NetObjectID | Number | NetObject ID of a triggered event. | 
| SolarWinds.Event.NetObjectValue | String | NetObject value of a triggered event. | 
| SolarWinds.Event.EngineID | Number | Engine ID of a triggered event. | 
| SolarWinds.Event.EventType | Number | Type of a triggered event. | 
| SolarWinds.Event.EventTypeName | String | Name of the type of a triggered event. | 
| SolarWinds.Event.Message | String | Message of a triggered event. | 
| SolarWinds.Event.Acknowledged | Boolean | Whether the event is acknowledged. | 
| SolarWinds.Event.NetObjectType | String | NetObject type of a triggered event. | 
| SolarWinds.Event.Timestamp | String | Last modified time of an event. It is a counter that SQL server automatically increments when the event is updated. | 
| SolarWinds.Event.DisplayName | String | Display name of an event. | 
| SolarWinds.Event.Description | String | Description of an event. | 
| SolarWinds.Event.InstanceType | String | Instance type of an event. | 
| SolarWinds.Event.Uri | String | URI of a triggered event. | 
| SolarWinds.Event.InstanceSiteID | Number | ID of an instance site of which event is triggered. | 


#### Command Example
```!swis-event-list sort_key="EventID" sort_order="Ascending" page="1" limit="2"```

#### Context Example
```json
{
    "SolarWinds": {
        "Event": [
            {
                "Acknowledged": false,
                "EngineID": 1,
                "EventID": 3,
                "EventTime": "2021-03-31T12:02:05.6830000",
                "EventType": 315,
                "EventTypeName": "Notification Reset",
                "InstanceSiteId": 0,
                "InstanceType": "Orion.Events",
                "Message": "Resetting unknown traffic notification events.",
                "NetObjectID": 0,
                "NetObjectType": "N",
                "NetworkNode": 1,
                "Node": "WIN-MV956AU5BSN",
                "TimeStamp": [
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                    "7",
                    "211"
                ],
                "Uri": "swis://WIN-MV956AU5BSN./Orion/Orion.Events/EventID=3"
            },
            {
                "Acknowledged": false,
                "EngineID": 1,
                "EventID": 4,
                "EventTime": "2021-03-31T12:02:08.5570000",
                "EventType": 300,
                "EventTypeName": "The NetFlow Receiver Service Started",
                "InstanceSiteId": 0,
                "InstanceType": "Orion.Events",
                "Message": "The NetFlow Receiver Service [WIN-MV956AU5BSN] started - listening on port(s) [2055]",
                "NetObjectID": 0,
                "NetObjectType": "N",
                "NetworkNode": 1,
                "Node": "WIN-MV956AU5BSN",
                "TimeStamp": [
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                    "7",
                    "212"
                ],
                "Uri": "swis://WIN-MV956AU5BSN./Orion/Orion.Events/EventID=4"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events
>|ID|Message|Type|Node|Acknowledged|Triggered At|
>|---|---|---|---|---|---|
>| 3 | Resetting unknown traffic notification events. | Notification Reset | WIN-MV956AU5BSN | false | 31/03/2021 12:02 PM |
>| 4 | The NetFlow Receiver Service [WIN-MV956AU5BSN] started - listening on port(s) [2055] | The NetFlow Receiver Service Started | WIN-MV956AU5BSN | false | 31/03/2021 12:02 PM |


### swis-alert-list
***
Retrieves a list of alerts based on the filter values provided in the command arguments.


#### Base Command

`swis-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | A comma-separated list of alert IDs.<br/>Note: alert_id supports integer values (int64). | Optional | 
| type | A comma-separated list of the type of property to monitor. For example: Node, IPAM.IPRequests, Orion.DiscoveryLogs, APM: Component, IPAM Networks, Orion.NodesForecastCapacity, APM: Application, Orion.VolumesForecastCapacity, Orion.NodesForecastCapacity, etc. | Optional | 
| severity | A comma-separated list of severity levels.<br/>Possible values: Information, Warning, Critical, Serious, and Notice. | Optional | 
| sort_key | Key by which the response will be sorted.<br/>For example: AlertID, AlertActiveID, AlertObjectID, TriggeredDateTime, TriggeredMessage, AcknowledgedDateTime, EngineID, Name, ObjectType, etc. Default is AlertActiveID. | Optional | 
| sort_order | Order by which the response will be sorted. Possible values: ascending and descending. Default is ascending. | Optional | 
| page | The page number from which to retrieve alerts. By default, the per-page limit is 50 alerts. You can change change this value in the limit argument. Default is 0. | Optional | 
| limit | The number of records to be retrieved.<br/>Note: The maximum value supported by the limit is maxValue int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SolarWinds.Alert.AlertActiveID | Number | Active ID of the triggered alert. | 
| SolarWinds.Alert.AlertObjectID | Number | Object ID of the triggered alert. | 
| SolarWinds.Alert.Acknowledged | Boolean | Whether the alert is acknowledged. | 
| SolarWinds.Alert.AcknowledgedBy | String | Name of the person who acknowledged the alert. | 
| SolarWinds.Alert.AcknowledgedDateTime | Date | Timestamp when the alert was acknowledged. | 
| SolarWinds.Alert.AcknowledgedNote | String | Acknowledge note of the alert. | 
| SolarWinds.Alert.TriggeredDateTime | Date | Timestamp when the alert was triggered. | 
| SolarWinds.Alert.TriggeredMessage | String | Message of the triggered alert. | 
| SolarWinds.Alert.NumberOfNotes | Number | Number of notes of the alert. | 
| SolarWinds.Alert.LastExecutedEscalationLevel | Number | Last executed escalation level for the alert.  | 
| SolarWinds.Alert.DisplayName | String | Display name of the alert. | 
| SolarWinds.Alert.AlertDescription | String | Description of the alert. | 
| SolarWinds.Alert.InstanceType | String | Type of instance of the alert. | 
| SolarWinds.Alert.Uri | String | URI of the alert. | 
| SolarWinds.Alert.InstanceSiteId | Number | Site ID of the instance. | 
| SolarWinds.Alert.AlertID | Number | ID of the alert. | 
| SolarWinds.Alert.EntityUri | String | URI for the object that triggered the alert. | 
| SolarWinds.Alert.EntityType | String | Type of the object that triggered the alert. | 
| SolarWinds.Alert.EntityCaption | String | The display name for the triggering object. | 
| SolarWinds.Alert.EntityDetailsUrl | String | Relative URL for the details view for the triggering object. | 
| SolarWinds.Alert.EntityNetObjectId | String | NetObject ID of the entity. | 
| SolarWinds.Alert.RelatedNodeUri | String | URI of the related node | 
| SolarWinds.Alert.RelatedNodeId | Number | ID of the related node. | 
| SolarWinds.Alert.RelatedNodeDetailsUrl | String | URL which contains node details. | 
| SolarWinds.Alert.RelatedNodeCaption | String | Caption of the related node. | 
| SolarWinds.Alert.RealEntityUri | String | URI of the real entity. | 
| SolarWinds.Alert.RealEntityType | String | Type of the real entity. | 
| SolarWinds.Alert.TriggeredCount | Number | Number of times the alert was triggered. | 
| SolarWinds.Alert.LastTriggeredDateTime | Date | Timestamp when the alert was last triggered. | 
| SolarWinds.Alert.Context | String | Context of the alert. | 
| SolarWinds.Alert.AlertNote | String | Note of the alert. | 
| SolarWinds.Alert.AlertMessage | String | Message of the alert. | 
| SolarWinds.Alert.AlertRefID | String | Unique identifier of the alert. | 
| SolarWinds.Alert.Name | String | Name of the alert. | 
| SolarWinds.Alert.ConfigurationDescription | String | Configuration description of the alert. | 
| SolarWinds.Alert.ObjectType | String | Object type of the alert. | 
| SolarWinds.Alert.Enabled | Boolean | Whether the alert is enabled. | 
| SolarWinds.Alert.Frequency | Number | Frequency of the alert. | 
| SolarWinds.Alert.Trigger | String | Condition due to which the alert was triggered. | 
| SolarWinds.Alert.Reset | String | Reset condition for the alert. When the condition is met, the alert is removed from active alerts. | 
| SolarWinds.Alert.Severity | Number | Severity of the alert. | 
| SolarWinds.Alert.NotifyEnabled | Boolean | Whether it is notified enabled. | 
| SolarWinds.Alert.NotificationSettings | String | Settings of the notifications for the alerts. | 
| SolarWinds.Alert.LastEdit | Date | Timestamp when the alert was last edited. | 
| SolarWinds.Alert.CreatedBy | String | Name of the person who created the alert. | 
| SolarWinds.Alert.Category | String | Category of the alert. | 
| SolarWinds.Alert.Canned | Boolean | Whether the alert is canned. | 
| SolarWinds.Alert.ResponsibleTeam | String | Team that is responsible for the alert. | 


#### Command Example
```!swis-alert-list sort_key="AlertActiveID" sort_order="ascending" page="1" limit="2"```

#### Context Example
```json
{
    "SolarWinds": {
        "Alert": [
            {
                "AlertActiveID": 4,
                "AlertID": 91,
                "AlertMessage": "${N=SwisEntity;M=FirstName} ${N=SwisEntity;M=LastName} has requested ${N=SwisEntity;M=RequestAddressCount} IP address(es) at ${N=SwisEntity;M=RequestDate}\n      Contact details: ${N=SwisEntity;M=Phone}, ${N=SwisEntity;M=Email}\n      Comments: ${N=SwisEntity;M=Comment}",
                "AlertObjectID": 3,
                "AlertRefID": "227c01da-1e64-44f2-807b-e6c7d2898ae5",
                "Canned": true,
                "ConfigurationDescription": "This alert writes to the event log when Request IP Address is created.",
                "Context": "null",
                "Enabled": true,
                "EntityCaption": "IP Request (test test)",
                "EntityNetObjectId": "IPAMIPREQ:2",
                "EntityType": "IPAM.IPRequests",
                "EntityUri": "swis://WIN-MV956AU5BSN./Orion/IPAM.IPRequests/IPRequestId=2",
                "Frequency": 60,
                "InstanceSiteId": 0,
                "InstanceType": "Orion.AlertActive",
                "LastEdit": "2021-03-31T12:03:59.7466667Z",
                "LastTriggeredDateTime": "2021-04-06T12:53:07.9200000Z",
                "Name": "IP Address Request",
                "NotifyEnabled": true,
                "ObjectType": "IPAM.IPRequests",
                "RealEntityType": "IPAM.IPRequests",
                "RealEntityUri": "swis://WIN-MV956AU5BSN./Orion/IPAM.IPRequests/IPRequestId=2",
                "Reset": "<ArrayOfAlertConditionShelve xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><AlertConditionShelve><AndThenTimeInterval i:nil=\"true\"/><ChainType>ResetCustom</ChainType><ConditionTypeID>Core.Dynamic</ConditionTypeID><Configuration>&lt;AlertConditionDynamic xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Alerting.Plugins.Conditions.Dynamic\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"&gt;&lt;ExprTree xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Field&lt;/a:NodeType&gt;&lt;a:Value&gt;IPAM.IPRequests|State&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;3&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;=&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;AND&lt;/a:Value&gt;&lt;/ExprTree&gt;&lt;Scope i:nil=\"true\" xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"/&gt;&lt;TimeWindow i:nil=\"true\"/&gt;&lt;/AlertConditionDynamic&gt;</Configuration><ConjunctionOperator>None</ConjunctionOperator><IsInvertedMinCountThreshold>false</IsInvertedMinCountThreshold><NetObjectsMinCountThreshold i:nil=\"true\"/><ObjectType>IPAM IP Requests</ObjectType><SustainTime i:nil=\"true\"/></AlertConditionShelve></ArrayOfAlertConditionShelve>",
                "Severity": 2,
                "Trigger": "<ArrayOfAlertConditionShelve xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><AlertConditionShelve><AndThenTimeInterval i:nil=\"true\"/><ChainType>Trigger</ChainType><ConditionTypeID>Core.Dynamic</ConditionTypeID><Configuration>&lt;AlertConditionDynamic xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Alerting.Plugins.Conditions.Dynamic\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"&gt;&lt;ExprTree xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Field&lt;/a:NodeType&gt;&lt;a:Value&gt;IPAM.IPRequests|State&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;2&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;=&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;AND&lt;/a:Value&gt;&lt;/ExprTree&gt;&lt;Scope i:nil=\"true\" xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"/&gt;&lt;TimeWindow i:nil=\"true\"/&gt;&lt;/AlertConditionDynamic&gt;</Configuration><ConjunctionOperator>None</ConjunctionOperator><IsInvertedMinCountThreshold>false</IsInvertedMinCountThreshold><NetObjectsMinCountThreshold i:nil=\"true\"/><ObjectType>IPAM IP Requests</ObjectType><SustainTime i:nil=\"true\"/></AlertConditionShelve></ArrayOfAlertConditionShelve>",
                "TriggeredCount": 2,
                "TriggeredDateTime": "2021-04-06T12:53:07.2300000Z",
                "TriggeredMessage": "test test has requested 1 IP address(es) at 4/6/2021 4:54:24 PM\n      Contact details: , dummy@dummy.com\n      Comments: ",
                "Uri": "swis://WIN-MV956AU5BSN./Orion/Orion.AlertActive/AlertActiveID=4,AlertObjectID=3"
            },
            {
                "AlertActiveID": 7,
                "AlertID": 112,
                "AlertMessage": "Network Discovery Failed",
                "AlertObjectID": 5,
                "AlertRefID": "eac27bca-77f7-40a5-a359-4069e96bc88e",
                "Canned": true,
                "ConfigurationDescription": "This alert will send an email if Network Discovery fails.",
                "Context": "{\"PropertiesValues\":{\".DiscoveryLogID\":5,\".FinishedTimeStamp\":\"2021-04-06T14:44:14Z\",\".ProfileID\":2,\".AutoImport\":true,\".Result\":3,\".ResultDescription\":\"Import Failed\",\".BatchID\":\"20881db3-ed49-4f4e-8356-e50f0ac5e4e0\",\".ErrorMessage\":\"Unknown Error\",\".InstanceType\":\"Orion.DiscoveryLogs\",\"Uri\":\"swis://WIN-MV956AU5BSN./Orion/Orion.DiscoveryLogs/DiscoveryLogID=5\",\"DisplayName\":\"Import Failed\"}}",
                "Enabled": true,
                "EntityCaption": "Import Failed",
                "EntityNetObjectId": ":",
                "EntityType": "Orion.DiscoveryLogs",
                "EntityUri": "swis://WIN-MV956AU5BSN./Orion/Orion.DiscoveryLogs/DiscoveryLogID=5",
                "Frequency": 60,
                "InstanceSiteId": 0,
                "InstanceType": "Orion.AlertActive",
                "LastEdit": "2021-03-31T12:04:06.0133333Z",
                "LastTriggeredDateTime": "2021-04-06T15:01:22.3570000Z",
                "Name": "Network Discovery Failed",
                "NotificationSettings": "<AlertNotificationSetting xmlns=\"http://schemas.solarwinds.com/2008/Core\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><Enabled>true</Enabled><NetObjectType>Orion.DiscoveryLogs</NetObjectType><Severity>Informational</Severity><Subject>Network Discovery Failed</Subject><_properties xmlns:a=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\"/></AlertNotificationSetting>",
                "NotifyEnabled": true,
                "ObjectType": "Orion.DiscoveryLogs",
                "RealEntityType": "Orion.DiscoveryLogs",
                "RealEntityUri": "swis://WIN-MV956AU5BSN./Orion/Orion.DiscoveryLogs/DiscoveryLogID=5",
                "Reset": "<ArrayOfAlertConditionShelve xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><AlertConditionShelve><AndThenTimeInterval i:nil=\"true\"/><ChainType>ResetWhenTriggered</ChainType><ConditionTypeID i:nil=\"true\"/><Configuration i:nil=\"true\"/><ConjunctionOperator>None</ConjunctionOperator><IsInvertedMinCountThreshold>false</IsInvertedMinCountThreshold><NetObjectsMinCountThreshold i:nil=\"true\"/><ObjectType i:nil=\"true\"/><SustainTime i:nil=\"true\"/></AlertConditionShelve></ArrayOfAlertConditionShelve>",
                "Severity": 0,
                "Trigger": "<ArrayOfAlertConditionShelve xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><AlertConditionShelve><AndThenTimeInterval i:nil=\"true\"/><ChainType>Trigger</ChainType><ConditionTypeID>Core.Dynamic</ConditionTypeID><Configuration>&lt;AlertConditionDynamic xmlns=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Alerting.Plugins.Conditions.Dynamic\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"&gt;&lt;ExprTree xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;True&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;0&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;0&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Field&lt;/a:NodeType&gt;&lt;a:Value&gt;Orion.DiscoveryLogs|Result&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;1&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;=&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Field&lt;/a:NodeType&gt;&lt;a:Value&gt;Orion.DiscoveryLogs|Result&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;3&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;=&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Field&lt;/a:NodeType&gt;&lt;a:Value&gt;Orion.DiscoveryLogs|Result&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;a:Expr&gt;&lt;a:Child i:nil=\"true\"/&gt;&lt;a:NodeType&gt;Constant&lt;/a:NodeType&gt;&lt;a:Value&gt;4&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;=&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;OR&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Event&lt;/a:NodeType&gt;&lt;a:Value&gt;[createEvent].Orion.DiscoveryLogs|event&lt;/a:Value&gt;&lt;/a:Expr&gt;&lt;/a:Child&gt;&lt;a:NodeType&gt;Operator&lt;/a:NodeType&gt;&lt;a:Value&gt;AND&lt;/a:Value&gt;&lt;/ExprTree&gt;&lt;Scope i:nil=\"true\" xmlns:a=\"http://schemas.datacontract.org/2004/07/SolarWinds.Orion.Core.Models.Alerting\"/&gt;&lt;TimeWindow i:nil=\"true\"/&gt;&lt;/AlertConditionDynamic&gt;</Configuration><ConjunctionOperator>None</ConjunctionOperator><IsInvertedMinCountThreshold>false</IsInvertedMinCountThreshold><NetObjectsMinCountThreshold i:nil=\"true\"/><ObjectType>Orion.DiscoveryLogs</ObjectType><SustainTime i:nil=\"true\"/></AlertConditionShelve></ArrayOfAlertConditionShelve>",
                "TriggeredCount": 1,
                "TriggeredDateTime": "2021-04-06T15:01:22.2170000Z",
                "TriggeredMessage": "Network Discovery Failed",
                "Uri": "swis://WIN-MV956AU5BSN./Orion/Orion.AlertActive/AlertActiveID=7,AlertObjectID=5"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|Active Alert ID|Alert Name|Triggered Message|Entity Caption|Triggered At|Severity|Type|Configuration Description|
>|---|---|---|---|---|---|---|---|
>| 4 | IP Address Request | test test has requested 1 IP address(es) at 4/6/2021 4:54:24 PM<br/>      Contact details: , dummy@dummy.com<br/>      Comments:  | IP Request (test test) | 06/04/2021 12:53 PM | CRITICAL | IPAM.IPRequests | This alert writes to the event log when Request IP Address is created. |
>| 7 | Network Discovery Failed | Network Discovery Failed | Import Failed | 06/04/2021 03:01 PM | INFORMATION | Orion.DiscoveryLogs | This alert will send an email if Network Discovery fails. |


### swis-query
***
Executes a query request.<br/>
Click [here](https://support.solarwinds.com/SuccessCenter/s/article/Use-SolarWinds-Query-Language-SWQL) to navigate to the guidelines to generate a query. SolarWinds Information Service schema can be found [here](http://solarwinds.github.io/OrionSDK/2020.2/schema/index.html).


#### Base Command

`swis-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The SWQL query to be executed. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!swis-query query="SELECT AlertActiveID, TriggeredDateTime FROM Orion.AlertActive ORDER BY AlertActiveID DESC WITH ROWS 1 To 3"```

#### Context Example
```json
{
    "SolarWinds": {
        "Query": [
            {
                "AlertActiveID": 18543,
                "TriggeredDateTime": "2021-04-20T06:39:32.4330000Z"
            },
            {
                "AlertActiveID": 18542,
                "TriggeredDateTime": "2021-04-19T18:45:11.7730000Z"
            },
            {
                "AlertActiveID": 18541,
                "TriggeredDateTime": "2021-04-19T18:44:10.5730000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Result
>|Alert Active ID|Triggered Date Time|
>|---|---|
>| 18543 | 2021-04-20T06:39:32.4330000Z |
>| 18542 | 2021-04-19T18:45:11.7730000Z |
>| 18541 | 2021-04-19T18:44:10.5730000Z |
