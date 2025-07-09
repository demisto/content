This API queries alerts and alert data from the MS-ISAC API to enrich and query alerts from the platform
This integration was integrated and tested with version 1.2 (7/1/25) of the MS-ISAC API.

## Configure MS-ISAC in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Key provided by MS-ISAC according to the detailed Instructions | True |
| Server URL | This is the URL provided by MS-ISAC for the base of all endpoints | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msisac-get-alert

***
Retrieve alert data by its ID

#### Base Command

`msisac-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the MS-ISAC alert. | True |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSISAC.Alert.alertId | string | The id for this alert |
| MSISAC.Alert.affectedIp | string | The internal IP that is associated with the traffic |
| MSISAC.Alert.alertedAt | string | The timestamp when the alert happened |
| MSISAC.Alert.applicationProtocol | string | The protocol associated with the traffic |
| MSISAC.Alert.category | string | The category of the alert |
| MSISAC.Alert.createdAt | string | The timestamp when the alert was created |
| MSISAC.Alert.destinationIp | string | The destination IP of the traffic |
| MSISAC.Alert.destinationPort | number | The destination port number of the traffic |
| MSISAC.Alert.encodedPayload | string | The encoded payload of the traffic |
| MSISAC.Alert.httpHostname | string | The HTTP hostname of the traffic |
| MSISAC.Alert.httpMethod | string | The HTTP method of the traffic |
| MSISAC.Alert.httpStatus | number | The HTTP status code of the traffic |
| MSISAC.Alert.httpUrl | string | The HTTP url of the traffic |
| MSISAC.Alert.logicalSensor | string | The name for the sensor that triggered the event |
| MSISAC.Alert.mitreTactic | string | The mitre tactic associated with the traffic |
| MSISAC.Alert.mitreTechnique | string | The mitre technique associated with the traffic |
| MSISAC.Alert.signatureDirection | string | The direction of the traffic flow |
| MSISAC.Alert.signatureId | number | The signature id of the traffic |
| MSISAC.Alert.signatureName | string | The signature name of the traffic |
| MSISAC.Alert.sourceIp | string | The source IP of the traffic |
| MSISAC.Alert.sourcePort | number | The source port number of the traffic |
| MSISAC.Alert.transportProtocol | string | The transport protocol of the traffic |

### msisac-retrieve-cases

***
Retrieves a list of MS-ISAC cases created since the given timestamp.

#### Base Command

`msisac-retrieve-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timestamp | Needs to be in "2025-07-01T00:00:00" format, in UTC. If no timestamp is given, command will return cases from the last 72 hours. | False |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSISAC.RetrievedCases.caseId | string | ID for the retrieved MS-ISAC case |
| MSISAC.RetrievedCases.affectedIp | string | The internal IP that is associated with the traffic |
| MSISAC.RetrievedCases.alertIds | list | The MSISAC alert ids associated with the case |
| MSISAC.RetrievedCases.createdAt | string | The timestamp when the case was created. This is associated with the timestamp input parameter |
| MSISAC.RetrievedCases.logicalSensorName | string | The name for the sensor that triggered the event |
| MSISAC.RetrievedCases.modifiedAt | string | The timestamp for when the case was last modified |
| MSISAC.RetrievedCases.severity | string | The severity of the case |
