Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Configure Vision One on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for vision_one.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base API URL | Base url for Vision One API | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | API Key | API token for authentication  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### Base Command

1. `trendmicro-visionone-add-to-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| valueType | block item value type | Required | 
| targetValue | item value info | Required | 
| productId | target product | optional |
| description | action description | optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.BlockList.action_id | String | The action id | 
| VisionOne.BlockList.task_status | String | Status of existing task |

2. `trendmicro-visionone-remove-from-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| valueType | block item value type | Required | 
| targetValue | item value info | Required | 
| productId | target product | optional |
| description | action description | optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.BlockList.action_id | String | The action id | 
| VisionOne.BlockList.task_status | String | Status of existing task |

3. `trendmicro-visionone-quarantine-email-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messageId | email message id | Required | 
| mailBox | email message's mailbox | Required | 
| messageDeliveryTime | email message's delivery time | Required |
| productId | target product | optional |
| description | action description | optional 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Email.action_id | String | The action id | 
| VisionOne.Email.task_status | String | Status of existing task |

4. `trendmicro-visionone-delete-email-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messageId | email message id | Required | 
| mailBox | email message's mailbox | Required | 
| messageDeliveryTime | email message's delivery time | Required |
| productId | target product | optional |
| description | action description | optional 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Email.action_id | String | The action id | 
| VisionOne.Email.task_status | String | Status of existing task |

5. `trendmicro-visionone-isolate-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | which field would like to search for agent info, acceptable value: hostname/macaddr/ip | Required | 
| value | value of above field | Required | 
| productId | target product | optional |
| description | action description | optional 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Endpoint_Connection.actionId | String | The action id | 
| VisionOne.Endpoint_Connection.taskStatus | String | Status of existing task |

Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

6. `trendmicro-visionone-restore-endpoint-connection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | which field would like to search for agent info, acceptable value: hostname/macaddr/ip |Required| 
| value | value of above field type entered | Required | 
| productId | target product Default: "sao", Enum: "sao" "sds" | optional |
| description | action description | optional 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Endpoint_Connection.actionId | String | The action id | 
| VisionOne.Endpoint_Connection.taskStatus | String | Status of existing task |

Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

7. `trendmicro-visionone-add-objects-to-exception-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Object record type. Enum: "domain" "ip" "sha1" "url" | Required | 
| value | The object value. Full and partial matches supported. DOMAIN partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL Partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , https://.example.com/path1/) SHA1 Only full match" | Required | 
| description | action description | optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Exception_List.message | String | Status message of existing task | 
| VisionOne.Exception_List.status_code | String | Response code of existing task |
| VisionOne.Exception_List.total_items | String | Number of items present in the exception list. |

8. `trendmicro-visionone-delete-objects-from-exception-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Object record type. Enum: "domain" "ip" "sha1" "url" |Required| 
| value | The object value. Full and partial matches supported. DOMAIN partial match, (with a wildcard as the subdomain example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL Partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , https://.example.com/path1/) SHA1 Only full match" | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Exception_List.message | String | Status message of existing task | 
| VisionOne.Exception_List.status_code | String | Response code of existing task |
| VisionOne.Exception_List.total_items | String | Number of items present in the exception list. |

9. `trendmicro-visionone-add-objects-to-suspicious-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The Suspicious Object type. Enum: "domain" "ip" "sha1" "url" |Required| 
| value | The Suspicious Object value.  | Required | 
| description | The Suspicious Object description info | optional |
| scanAction | The Suspicious Object scan action. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. Enum: "block" "log" | optional |
| riskLevel | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. Enum: "high" "medium" "low" | optional |
| expiredDay |The Suspicious Object expiry day. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead. | optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Suspicious_List.message | String | Status message of existing task | 
| VisionOne.Suspicious_List.status_code | String | Response code of existing task |
| VisionOne.Suspicious_List.total_items | String | Number of items present in the exception list. |

10. `trendmicro-visionone-delete-objects-from-suspicious-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The Suspicious Object type. Enum: "domain" "ip" "sha1" "url" |Required| 
| value | The value of the Suspicious Object to be deleted from the Suspicious Object List.  | Required |  


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Suspicious_List.message | String | Status message of existing task | 
| VisionOne.Suspicious_List.status_code | String | Response code of existing task |
| VisionOne.Suspicious_List.total_items | String | Number of items present in the exception list. |

11. `trendmicro-visionone-terminate-process`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | which field would like to search for agent info, acceptable value: hostname/macaddr/ip. Used to get computerId |Required| 
| value | value of above field | Required | 
| fileSha1 | sha value of the file | Required |
| productId | target product Default: "sao" | optional |
| description | action description | optional 
| filename | optional file name list for log | optional

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Terminate_Process.actionId | String | The action id | 
| VisionOne.Terminate_Process.taskStatus | String | Status of existing task |

Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

12. `trendmicro-visionone-get-file-analysis-status`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| taskId | Id of the task to get the status |Required| 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.File_Analysis_Status.message | String | Message status | 
| VisionOne.File_Analysis_Status.code | String | Code status of the task |
| VisionOne.File_Analysis_Status.task_id | String | Task id |
| VisionOne.File_Analysis_Status.task_status | String | Task status |
| VisionOne.File_Analysis_Status.digest | String | Hash value of task |
| VisionOne.File_Analysis_Status.analysis_completion_time | String | Task completion time |
| VisionOne.File_Analysis_Status.risk_level | String | Risk level of task |
| VisionOne.File_Analysis_Status.description | String | Description of task |
| VisionOne.File_Analysis_Status.detection_name_list | String | List of task detected |
| VisionOne.File_Analysis_Status.threat_type_list | String | Threat type list |
| VisionOne.File_Analysis_Status.file_type | String | Type of file |
| VisionOne.File_Analysis_Status.report_id | String | Report ID of task. |

13. `trendmicro-visionone-get-file-analysis-report`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportId | file reportId |Required| 
| type | type of report Enum: "vaReport" "investigationPackage" "suspiciousObject" |Required|

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.File_Analysis_Report.message | String | Message status |
| VisionOne.File_Analysis_Report.code | String | Code status of task |
| VisionOne.File_Analysis_Report.type | String | type of report |
| VisionOne.File_Analysis_Report.value | String | value of the above type |
| VisionOne.File_Analysis_Report.risklevel | String | risk level of the file |
| VisionOne.File_Analysis_Report.analysisCompletionTime | String | Final analysed time of report |
| VisionOne.File_Analysis_Report.expiredTime | String | Expiry time of report |
| VisionOne.File_Analysis_Report.rootFileSha1 | String | sha value of the root file | 

14. `trendmicro-visionone-collect-forensic-file`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Description of file collected |optional| 
| productId | Enum: "sao" "xes" "sds" |Required|
| computerId | Id of the machine |Required|
| filePath | Path of the file to get collected |Required|
| os | Enum: "windows" "mac" "linux" |Required|

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Collect_Forensic_File.actionId | String | Action id of the running task |
| VisionOne.Collect_Forensic_File.taskStatus | String | Status of the running task |

Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

15. `trendmicro-visionone-download-information-for-collected-forensic-file`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actionId | Action Id to get the download information for collected file |Required| 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Download_Information_For_Collected_Forensic_File.url | String | Url to the file to download |
| VisionOne.Download_Information_For_Collected_Forensic_File.expires | String | Expire date to the file |
| VisionOne.Download_Information_For_Collected_Forensic_File.password | String | Password to the archive file |
| VisionOne.Download_Information_For_Collected_Forensic_File.filename | String | Name of the file |

Note: The url value received from the 'trendmicro-visionone-download-information-for-collected-forensic-file' will be valid for only ``60 seconds``

16. `trendmicro-visionone-submit-file-to-sandbox`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File content to be upload. |Required| 
| documentPassword | Indicate the password for decrypting the submitted document-type1 sample. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | Optional |
| archivePassword | Indicate the password for decrypting the submitted archive-type1 sample. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.SUbmit_File_to_Sandbox.message | String | Message status of the sandbox file |
| VisionOne.SUbmit_File_to_Sandbox.code | String | Code status of the sandbox file |
| VisionOne.SUbmit_File_to_Sandbox.task_id | String | Task ID of the running task |
| VisionOne.SUbmit_File_to_Sandbox.digest | Object | Sha value of the file |