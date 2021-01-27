This playbook provides a response for endpoint exfiltration incidents by retrieving data about the source and destination of the alert, assessing the severity of the incident and allowing remediation of the incident with host isolation, breach notification and blocking of malicious destination indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Entity Enrichment - Generic v3
* Retrieve File from Endpoint - Generic V2
* Calculate Severity - Generic v2
* Detonate File - Generic
* Block Indicators - Generic v2
* Block File - Generic v2
* Code42 File Download
* Isolate Endpoint - Generic
* Cortex XDR - Retrieve File Playbook
* Active Directory - Get User Manager Details

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty

### Commands
* setIncident
* closeInvestigation
* extractIndicators
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileMD5 | The MD5 hash of the file that was exfiltrated. |  | Optional |
| Hostname | The name of the endpoint from which the exfiltration originated. |  | Optional |
| FilePath | The path on the endpoint to the file that was associated with the exfiltration \(the tool used for exfiltration\). |  | Optional |
| AgentID | The ID of the agent/sensor that detected the file exfiltration. |  | Optional |
| Username | The username of the user that executed the exfiltration. |  | Optional |
| UserEmail | The email of the user that executed the exfiltration. |  | Optional |
| FileSHA256 | The SHA256 hash of the file that was associated with the exfiltration \(the tool used for exfiltration\). |  | Optional |
| FileName | The name of the file that was associated with the exfiltration \(the tool used for exfiltration\). |  | Optional |
| IsolateHostsAutomatically | Determines whether endpoints where alerts occurred will be isolated automatically. Can be either "True" or "False". | False | Optional |
| SourceIP | The IP address of the endpoint from which the exfiltration originated. |  | Optional |
| BreachRegulation | The regulation to which the company is subject. Can be GDPR, HIPAA or US.<br/>If no value is specified, the user will be asked to notify about the breach using the method practiced in your organization. |  | Optional |
| ExfiltrationDestination | The destination of the exfiltration of data. This could be for example a domain to which DNS tunneling was executed, or a URLto which an HTTP POST request was sent to exfiltrate data. |  | Optional |
| BlockDestinationAutomatically | Whether to block the destination \(IP/URL\) to which data was exfiltrated automatically. If set to "True" - the destination will be blocked automatically if found to be malicious. Otherwise, an analyst review will be required to block the destination. | False | Optional |
| EndpointID | The Cortex XDR endpoint ID. Used to retrieve the file that made the exfiltration from the endpoint. |  | Optional |
| DestinationPort | The destination port through which data was exfiltrated. |  | Optional |
| BlockFileAutomatically | Whether to block the file used for exfiltration automatically. If set to true - the file will be blocked automatically. Otherwise, an analyst review will be required to block the file. | False | Optional |
| NotifyManager | Whether to notify the offensive user's manager about the exfiltration. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Data Exfiltration - Generic](Insert the link to your image here)