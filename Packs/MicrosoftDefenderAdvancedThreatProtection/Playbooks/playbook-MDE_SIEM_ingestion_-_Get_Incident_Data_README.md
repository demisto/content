This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook handles incident ingestion from a SIEM. The user provides the incident fields containing the alert ID. This playbook also enables changing the severity according to a user-defined scale to override the default assigned severity.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
MicrosoftDefenderAdvancedThreatProtection

### Scripts
This playbook does not use any scripts.

### Commands
* setIncident
* microsoft-atp-get-alert-by-id

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SIEMincidentFieldForID | The name of the incident field that contains the detection ID or incident ID. | ${incident.externalsystemid} | Optional |
| ScaleToSetSeverity |The severity scale as represented in the EDR.<br/>For example, in Microsoft Defender for Endpoint the severity scale is Informational, Low, Medium, High. | Informational,Low,Medium,High | Optional |
| SeverityValuesMapping | The mapping to Cortex XSOAR severity from the severity scale in the EDR (the ScaleToSetSeverity inputs).<br/>For example<br/>0.5, 1, 2, 3, 4<br/>Possible values to use are 0, 0.5, 1, 2, 3, 4<br/>Which represent Unknown, Informational, Low, Medium, High, Critical | 0.5, 1, 2, 3 | Optional |
| OverrideSIEMSeverity | Whether to set the severity according to the ScaleToSetSeverity and SeverityValuesMapping settings (True) or keep the original severity as mapped by the SIEM (False). | False | Optional |

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
![MDE SIEM ingestion - Get Incident Data](../doc_files/MDE_SIEM_ingestion_-_Get_Incident_Data.png)
