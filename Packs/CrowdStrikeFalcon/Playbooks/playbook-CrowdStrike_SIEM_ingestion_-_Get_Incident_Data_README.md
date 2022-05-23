The playbook handles when the incident ingestion was done from the SIEM. The user provides which incident fields contain the incident or detection ID, also which fields differentiates if this is an incident or detection. In addition it also allows to change the severity according to a user defined scale to override the default assigned severity as well as grab the CrowdStrike detections based on the CrowdStrike incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CrowdStrikeFalcon

### Scripts
This playbook does not use any scripts.

### Commands
* cs-falcon-search-detection
* endpoint
* cs-falcon-list-incident-summaries
* setIncident
* cs-falcon-get-detections-for-incident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SIEMincidentFieldForType | The incident field that contains if this is a detection or incident. Default value is incident.externalcategoryname | ${incident.externalcategoryname} | Optional |
| SIEMincidentFieldForID | The name of the incident field that contains the detection or incident ID. Default value is incident.externalid | ${incident.externalsystemid} | Optional |
| ScaleToSetSeverity | The severity scale as represented in the EDR<br/>For example in CrowdStrike uses values from 0 to 100<br/>So the scale can be divided in ranges such as<br/>0-20,21-40,41-60,61-80,81-100 | 0-20,21-40,41-60,61-80,81-100 | Optional |
| SeverityValuesMapping | This will provide the mapping to XSOAR severity for the ScaleToSetSeverity inputs<br/>For example<br/>0.5, 1, 2, 3,4<br/>Possible values to use are 0,0.5, 1, 2, 3,4<br/>Which represent Unknown, Informational, Low, Medium, High, Critical | 0.5, 1, 2, 3,4 | Optional |
| OverrideSIEMSeverity | Indicates if to set the severity according to the  ScaleToSetSeverity and SeverityValuesMapping settings \(True\) or keep the original severity as mapped by the SIEM \(False\) <br/>True/False | False | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CrowdStrike.Detection.Behavior.FileName | The file name of the behavior. | string |
| CrowdStrike.Detection.Behavior.Scenario | The scenario name of the behavior. | string |
| CrowdStrike.Detection.Behavior.MD5 | The MD5 hash of the IOC of the behavior. | string |
| CrowdStrike.Detection.Behavior.SHA256 | The SHA256 hash of the IOC of the behavior. | string |
| CrowdStrike.Detection.Behavior.IOCType | The type of the IOC. | string |
| CrowdStrike.Detection.Behavior.IOCValue | The value of the IOC. | string |
| CrowdStrike.Detection.Behavior.CommandLine | The command line executed in the behavior. | string |
| CrowdStrike.Detection.Behavior.UserName | The user name related to the behavior. | string |
| CrowdStrike.Detection.Behavior.SensorID | The sensor ID related to the behavior. | string |
| CrowdStrike.Detection.Behavior.ParentProcessID | The ID of the parent process. | string |
| CrowdStrike.Detection.Behavior.ProcessID | The process ID of the behavior. | string |
| CrowdStrike.Detection.Behavior.ID | The ID of the behavior. | string |
| CrowdStrike.Detection.System | The system name of the detection. | string |
| CrowdStrike.Detection.CustomerID | The ID of the customer \(CID\). | string |
| CrowdStrike.Detection.MachineDomain | The name of the domain of the detection machine. | string |
| CrowdStrike.Detection.ID | The detection ID. | string |
| CrowdStrike.Detection.ProcessStartTime | The start time of the process that generated the detection. | string |
| Endpoint | The details of the endpoint. | string |

## Playbook Image
---
![CrowdStrike Falcon - SIEM ingestion Get Incident Data](../doc_files/CrowdStrike_Falcon_-_SIEM_ingestion_-_Get_Incident_Data.png)