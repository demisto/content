Palo Alto Networks Best Practice Assessment (BPA) analyzes NGFW and Panorama configurations and compares them to the best practices.
This integration was integrated and tested with version 1.0 of BPA.
Supported Cortex XSOAR versions: 5.0.0 and later.

## Configure BPA on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BPA.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | server | Panorama Server URL \(e.g., https://192.168.0.1\) | True |
    | key | Panorama API Key | True |
    | token | BPA Access Token | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-os-get-documentation
***
Gets the documentation of all BPA checks.


#### Base Command

`pan-os-get-documentation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| doc_ids | A comma-separated list of IDs of the documents to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAN-OS-BPA.Documentation.Document.DocId | Number | The ID of the document. | 
| PAN-OS-BPA.Documentation.Document.TopNav | String | The TopNav field of the document. | 
| PAN-OS-BPA.Documentation.Document.LeftNav | String | The LeftNav of the document. | 
| PAN-OS-BPA.Documentation.Document.Title | String | The title of the document. | 
| PAN-OS-BPA.Documentation.Document.DocType | String | The type of the document. | 
| PAN-OS-BPA.Documentation.Document.Description | String | The description of the document. | 
| PAN-OS-BPA.Documentation.Document.Rationale | String | The rationale of the document. | 
| PAN-OS-BPA.Documentation.Document.References | String | The references for the document. | 
| PAN-OS-BPA.Documentation.Document.Active | Boolean | Whether the document is active or not. | 
| PAN-OS-BPA.Documentation.Document.LastUpdatedDate | String | The date the document was last updated. | 
| PAN-OS-BPA.Documentation.Document.CapabilityLabel | Unknown | The capability label of the document. | 
| PAN-OS-BPA.Documentation.Document.ClassLabel | Unknown | The class label of the document. | 
| PAN-OS-BPA.Documentation.Document.ControlCategory | Unknown | The control category of the document. | 
| PAN-OS-BPA.Documentation.Document.Cscv6Control | Unknown | The CSCv6 control of the document. | 
| PAN-OS-BPA.Documentation.Document.Cscv7Control | Unknown | The CSCv7 control of the document. | 
| PAN-OS-BPA.Documentation | Unknown | The list of BPA checks. | 


#### Command Example
```!pan-os-get-documentation doc_ids=4,6,7```

#### Context Example
```json
{
    "PAN-OS-BPA": {
        "Documentation": [
            {
                "Document": [
                    {
                        "Active": true,
                        "CapabilityLabel": [
                            "Preventative",
                            "Corrective"
                        ],
                        "ClassLabel": [
                            "Technical"
                        ],
                        "Complexity": "Advanced",
                        "ControlCategory": [
                            "Access Control"
                        ],
                        "Cscv6Control": [
                            "11.1",
                            "12.1"
                        ],
                        "Cscv7Control": [
                            "11.1",
                            "12.3"
                        ],
                        "Description": "Do not specify both the source and destination zones as \"any\" on the rule.",
                        "DocId": 4,
                        "DocType": "Warning",
                        "Effort": 60,
                        "LastUpdatedDate": "2020-10-05T22:46:57.585179Z",
                        "LeftNav": "Security",
                        "Rationale": "Use Security policy settings to create rules that exactly define the traffic to which the rules apply (zones, IP addresses, users, applications). Policies that are too general may match traffic you don\u2019t want the policy to match and either permit undesirable traffic or deny legitimate traffic. Defining the source, destination, or both zones prevents potentially malicious traffic that uses evasive or deceptive techniques to avoid detection or appear benign from traversing the entire network, which reduces the attack surface and the threat scope. The exception to this best practice is when the Security policy needs to protect the entire network. For example, a rule that blocks traffic to malware or phishing URL categories can apply to all zones (and all traffic) because the URL Category clearly defines the traffic to block. Another example is blocking all unknown traffic with a block rule that applies to all traffic in all zones and defining the blocked applications as \u201cunknown-tcp\u201d, \u201cunknown-udp\u201d, and \u201cunknown-p2p\u201d.",
                        "References": "['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-internet-gateway/best-practice-internet-gateway-security-policy/define-the-initial-internet-gateway-security-policy']",
                        "Title": "Source/Destination = any/any",
                        "TopNav": "Policies"
                    },
                    {
                        "Active": true,
                        "CapabilityLabel": [
                            "Performance"
                        ],
                        "ClassLabel": [
                            "Technical"
                        ],
                        "Complexity": "Advanced",
                        "ControlCategory": [
                            "Audit and Accountability"
                        ],
                        "Cscv6Control": [],
                        "Cscv7Control": [],
                        "Description": "Don't enable \"Log at Session Start\" in a rule except for troubleshooting purposes.",
                        "DocId": 6,
                        "DocType": "Warning",
                        "Effort": 60,
                        "LastUpdatedDate": "2020-10-05T22:46:57.596239Z",
                        "LeftNav": "Security",
                        "Rationale": "By default, the firewall creates logs at the end of the session for all sessions that match a Security policy rule because the application identification is likely to change as the firewall identifies the specific application and because logging at the session end consumes fewer resources than logging the session start. For example, at the start of a session, the firewall identifies Facebook traffic as web-browsing traffic, but after examining a few packets, the firewall refines the application to Facebook-base. Use \u201cLog at Session Start\u201d only to troubleshoot packet flow and related issues, or for tunnel session logs (only logging at session start shows active GRE tunnels in the Application Command Center).",
                        "References": "['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-data-center/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor']",
                        "Title": "Log at Start of Session",
                        "TopNav": "Policies"
                    },
                    {
                        "Active": true,
                        "CapabilityLabel": [
                            "Recovery",
                            "Detective"
                        ],
                        "ClassLabel": [
                            "Operational",
                            "Technical"
                        ],
                        "Complexity": "Advanced",
                        "ControlCategory": [
                            "Contingency Planning",
                            "Audit and Accountability"
                        ],
                        "Cscv6Control": [
                            "6.2",
                            "6.6",
                            "10.1"
                        ],
                        "Cscv7Control": [
                            "6.3",
                            "6.6",
                            "10.1"
                        ],
                        "Description": "Create and enable a Log Forwarding profile on the rule.",
                        "DocId": 7,
                        "DocType": "Warning",
                        "Effort": 60,
                        "LastUpdatedDate": "2020-10-05T22:46:57.601517Z",
                        "LeftNav": "Security",
                        "Rationale": "The firewall has limited log storage space and when the space fills up, the firewall purges the oldest logs. Configure Log Forwarding for the traffic that matches each Security policy rule. You can create profiles that send logs to a dedicated storage device such as Panorama in Log Collector mode, a syslog or SNMP server, or to an email profile, to provide redundant storage for the logs on the firewall and a long-term repository for older logs. You can create profiles to forward logs to one or more external storage devices to remain in compliance, run analytics, and review abnormal activity, threat behaviors, and long-term patterns.",
                        "References": "['https://www.paloaltonetworks.com/documentation/81/pan-os/pan-os/monitoring/configure-log-forwarding']",
                        "Title": "Log Forwarding",
                        "TopNav": "Policies"
                    }
                ]
            },
            {
                "active": true,
                "capability_label": [
                    "Preventative",
                    "Corrective"
                ],
                "class_label": [
                    "Technical"
                ],
                "complexity": "Advanced",
                "control_category": [
                    "Access Control"
                ],
                "cscv6_control": [
                    "11.1",
                    "12.1"
                ],
                "cscv7_control": [
                    "11.1",
                    "12.3"
                ],
                "description": "Do not specify both the source and destination zones as \"any\" on the rule.",
                "doc_id": 4,
                "doc_type": "Warning",
                "effort": 60,
                "last_updated_date": "2020-10-05T22:46:57.585179Z",
                "left_nav": "Security",
                "rationale": "Use Security policy settings to create rules that exactly define the traffic to which the rules apply (zones, IP addresses, users, applications). Policies that are too general may match traffic you don\u2019t want the policy to match and either permit undesirable traffic or deny legitimate traffic. Defining the source, destination, or both zones prevents potentially malicious traffic that uses evasive or deceptive techniques to avoid detection or appear benign from traversing the entire network, which reduces the attack surface and the threat scope. The exception to this best practice is when the Security policy needs to protect the entire network. For example, a rule that blocks traffic to malware or phishing URL categories can apply to all zones (and all traffic) because the URL Category clearly defines the traffic to block. Another example is blocking all unknown traffic with a block rule that applies to all traffic in all zones and defining the blocked applications as \u201cunknown-tcp\u201d, \u201cunknown-udp\u201d, and \u201cunknown-p2p\u201d.",
                "references": "['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-internet-gateway/best-practice-internet-gateway-security-policy/define-the-initial-internet-gateway-security-policy']",
                "title": "Source/Destination = any/any",
                "top_nav": "Policies"
            },
            {
                "active": true,
                "capability_label": [
                    "Performance"
                ],
                "class_label": [
                    "Technical"
                ],
                "complexity": "Advanced",
                "control_category": [
                    "Audit and Accountability"
                ],
                "cscv6_control": [],
                "cscv7_control": [],
                "description": "Don't enable \"Log at Session Start\" in a rule except for troubleshooting purposes.",
                "doc_id": 6,
                "doc_type": "Warning",
                "effort": 60,
                "last_updated_date": "2020-10-05T22:46:57.596239Z",
                "left_nav": "Security",
                "rationale": "By default, the firewall creates logs at the end of the session for all sessions that match a Security policy rule because the application identification is likely to change as the firewall identifies the specific application and because logging at the session end consumes fewer resources than logging the session start. For example, at the start of a session, the firewall identifies Facebook traffic as web-browsing traffic, but after examining a few packets, the firewall refines the application to Facebook-base. Use \u201cLog at Session Start\u201d only to troubleshoot packet flow and related issues, or for tunnel session logs (only logging at session start shows active GRE tunnels in the Application Command Center).",
                "references": "['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-data-center/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor']",
                "title": "Log at Start of Session",
                "top_nav": "Policies"
            },
            {
                "active": true,
                "capability_label": [
                    "Recovery",
                    "Detective"
                ],
                "class_label": [
                    "Operational",
                    "Technical"
                ],
                "complexity": "Advanced",
                "control_category": [
                    "Contingency Planning",
                    "Audit and Accountability"
                ],
                "cscv6_control": [
                    "6.2",
                    "6.6",
                    "10.1"
                ],
                "cscv7_control": [
                    "6.3",
                    "6.6",
                    "10.1"
                ],
                "description": "Create and enable a Log Forwarding profile on the rule.",
                "doc_id": 7,
                "doc_type": "Warning",
                "effort": 60,
                "last_updated_date": "2020-10-05T22:46:57.601517Z",
                "left_nav": "Security",
                "rationale": "The firewall has limited log storage space and when the space fills up, the firewall purges the oldest logs. Configure Log Forwarding for the traffic that matches each Security policy rule. You can create profiles that send logs to a dedicated storage device such as Panorama in Log Collector mode, a syslog or SNMP server, or to an email profile, to provide redundant storage for the logs on the firewall and a long-term repository for older logs. You can create profiles to forward logs to one or more external storage devices to remain in compliance, run analytics, and review abnormal activity, threat behaviors, and long-term patterns.",
                "references": "['https://www.paloaltonetworks.com/documentation/81/pan-os/pan-os/monitoring/configure-log-forwarding']",
                "title": "Log Forwarding",
                "top_nav": "Policies"
            }
        ]
    }
}
```

#### Human Readable Output

>### BPA documentation
>|Active|CapabilityLabel|ClassLabel|Complexity|ControlCategory|Cscv6Control|Cscv7Control|Description|DocId|DocType|Effort|LastUpdatedDate|LeftNav|Rationale|References|Title|TopNav|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | Preventative,<br/>Corrective | Technical | Advanced | Access Control | 11.1,<br/>12.1 | 11.1,<br/>12.3 | Do not specify both the source and destination zones as "any" on the rule. | 4 | Warning | 60 | 2020-10-05T22:46:57.585179Z | Security | Use Security policy settings to create rules that exactly define the traffic to which the rules apply (zones, IP addresses, users, applications). Policies that are too general may match traffic you don’t want the policy to match and either permit undesirable traffic or deny legitimate traffic. Defining the source, destination, or both zones prevents potentially malicious traffic that uses evasive or deceptive techniques to avoid detection or appear benign from traversing the entire network, which reduces the attack surface and the threat scope. The exception to this best practice is when the Security policy needs to protect the entire network. For example, a rule that blocks traffic to malware or phishing URL categories can apply to all zones (and all traffic) because the URL Category clearly defines the traffic to block. Another example is blocking all unknown traffic with a block rule that applies to all traffic in all zones and defining the blocked applications as “unknown-tcp”, “unknown-udp”, and “unknown-p2p”. | ['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-internet-gateway/best-practice-internet-gateway-security-policy/define-the-initial-internet-gateway-security-policy'] | Source/Destination = any/any | Policies |
>| true | Performance | Technical | Advanced | Audit and Accountability |  |  | Don't enable "Log at Session Start" in a rule except for troubleshooting purposes. | 6 | Warning | 60 | 2020-10-05T22:46:57.596239Z | Security | By default, the firewall creates logs at the end of the session for all sessions that match a Security policy rule because the application identification is likely to change as the firewall identifies the specific application and because logging at the session end consumes fewer resources than logging the session start. For example, at the start of a session, the firewall identifies Facebook traffic as web-browsing traffic, but after examining a few packets, the firewall refines the application to Facebook-base. Use “Log at Session Start” only to troubleshoot packet flow and related issues, or for tunnel session logs (only logging at session start shows active GRE tunnels in the Application Command Center). | ['https://www.paloaltonetworks.com/documentation/81/best-practices/best-practices-data-center/data-center-best-practice-security-policy/log-and-monitor-data-center-traffic/what-data-center-traffic-to-log-and-monitor'] | Log at Start of Session | Policies |
>| true | Recovery,<br/>Detective | Operational,<br/>Technical | Advanced | Contingency Planning,<br/>Audit and Accountability | 6.2,<br/>6.6,<br/>10.1 | 6.3,<br/>6.6,<br/>10.1 | Create and enable a Log Forwarding profile on the rule. | 7 | Warning | 60 | 2020-10-05T22:46:57.601517Z | Security | The firewall has limited log storage space and when the space fills up, the firewall purges the oldest logs. Configure Log Forwarding for the traffic that matches each Security policy rule. You can create profiles that send logs to a dedicated storage device such as Panorama in Log Collector mode, a syslog or SNMP server, or to an email profile, to provide redundant storage for the logs on the firewall and a long-term repository for older logs. You can create profiles to forward logs to one or more external storage devices to remain in compliance, run analytics, and review abnormal activity, threat behaviors, and long-term patterns. | ['https://www.paloaltonetworks.com/documentation/81/pan-os/pan-os/monitoring/configure-log-forwarding'] | Log Forwarding | Policies |


### pan-os-bpa-submit-job
***
Submits a job to the BPA job queue.


#### Base Command

`pan-os-bpa-submit-job`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| generate_zip_bundle | Whether to download the Panorama report. Can be "true" or "false". Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAN-OS-BPA.SubmittedJob.JobID | String | Submitted Job ID, used to query results when the job is done. | 


#### Command Example
```!pan-os-bpa-submit-job```

#### Context Example
```json
{
    "PAN-OS-BPA": {
        "SubmittedJob": {
            "JobID": "ca5dc5a7-c3e5-474a-8d04-e3129c1b0edf"
        }
    }
}
```

#### Human Readable Output

>Submitted BPA job ID: ca5dc5a7-c3e5-474a-8d04-e3129c1b0edf

### pan-os-bpa-get-job-results
***
Returns results of BPA job.


#### Base Command

`pan-os-bpa-get-job-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The job ID for which to return results. | Required | 
| exclude_passed_checks | Whether to exclude passed checks. Can be "true" or "false". Default is "false". | Optional | 
| check_id | A comma-separated list of the BPA IDs of the results to return. | Optional | 
| check_name | A comma-separated list of the name of the results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAN-OS-BPA.JobResults.JobID | String | The submitted job ID. | 
| PAN-OS-BPA.JobResults.Status | String | The job status in the queue \(in progress or completed\). | 
| PAN-OS-BPA.JobResults.Checks | Unknown | The list of checks. | 
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | File entry ID. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE" | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 


#### Command Example
```!pan-os-bpa-get-job-results task_id=b0539068-e1c1-496c-9dfd-a1274947f76e check_id=104,105 check_name="Accelerated Aging"```

#### Context Example
```json
{
    "PAN-OS-BPA": {
        "JobResults": {
            "Checks": [
                {
                    "check_category": "device",
                    "check_feature": "device_setup_services",
                    "check_id": 105,
                    "check_message": "It is recommended to configure a primary and secondary NTP Server Address",
                    "check_name": "NTP Server Address",
                    "check_passed": false,
                    "check_type": "Warning"
                },
                {
                    "check_category": "device",
                    "check_feature": "device_setup_services",
                    "check_id": 104,
                    "check_message": null,
                    "check_name": "Verify Update Server Identity",
                    "check_passed": true,
                    "check_type": "Warning"
                },
                {
                    "check_category": "device",
                    "check_feature": "device_setup_session",
                    "check_id": 121,
                    "check_message": null,
                    "check_name": "Accelerated Aging",
                    "check_passed": true,
                    "check_type": "Warning"
                }
            ],
            "JobID": "b0539068-e1c1-496c-9dfd-a1274947f76e",
            "Status": "complete"
        }
    }
}
```

#### Human Readable Output

>### BPA Results
>|check_category|check_feature|check_id|check_message|check_name|check_passed|check_type|
>|---|---|---|---|---|---|---|
>| device | device_setup_services | 105 | It is recommended to configure a primary and secondary NTP Server Address | NTP Server Address | false | Warning |
>| device | device_setup_services | 104 |  | Verify Update Server Identity | true | Warning |
>| device | device_setup_session | 121 |  | Accelerated Aging | true | Warning |

