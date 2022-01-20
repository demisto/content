#### Integration Author: Trend Micro
Support and maintenance for this integration are provided by the author. Please use the following contact details:
- **Email**: [integrations@trendmicro.com](mailto:integrations@trendmicro.com)
***
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Configure Vision One on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Vision One.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | Unique name for this Vision One instance | True |
| Fetch Incidents | Choose if the integration should sync incidents | True |
| API URL | Base URL for Vision One API | True |
| API Key | API token for authentication  | True |
| Incidents Fetch Interval (minutes) | How often do you want to check for new incidents | False |
| Sync On First Run (days) | How many days to go back during first sync | False |
| Max Incidents | Maximum Number of Workbenches to Retrieve | False |
4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.

#### Base Command

1. `trendmicro-visionone-add-to-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value_type | "file_sha1", "ip", "domain", "url" or "mailbox" | Required | 
| target_value | The object you would like to add that matches the value-type | Required | 
| product_id | Target product | Optional |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.BlockList.actionId | String | The action id | 
| VisionOne.BlockList.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

2. `trendmicro-visionone-remove-from-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value_type | "file_sha1", "ip", "domain", "url" or "mailbox" | Required | 
| target_value | The object you would like to add that matches the value-type | Required | 
| product_id | Target product | Optional |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.BlockList.actionId | String | The action id | 
| VisionOne.BlockList.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

3. `trendmicro-visionone-quarantine-email-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Email Message ID from Vision One message activity data | Required | 
| mail_box | Email mailbox where the message will be quarantied from | Required | 
| message_delivery_time | Email message's original delivery time | Required |
| product_id | Target product | Optional |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Email.actionId | String | The action id | 
| VisionOne.Email.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

4. `trendmicro-visionone-delete-email-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Email Message ID from Vision One message activity data | Required | 
| mail_box | Email mailbox where the message will be deleted from | Required | 
| message_delivery_time | Email message's original delivery time | Required |
| product_id | Target product | Optional |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Email.actionId | String | The action id | 
| VisionOne.Email.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

5. `trendmicro-visionone-isolate-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field to use to lookup computer_id. "hostname", "macaddr" or "ip" | Required | 
| value | Value to lookup | Required | 
| product_id | Target product: "sao" or "sds". Default: "sao". | Required |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Endpoint_Connection.actionId | String | The action id | 
| VisionOne.Endpoint_Connection.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

6. `trendmicro-visionone-restore-endpoint-connection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field to use to lookup computer_id. "hostname", "macaddr" or "ip" |Required| 
| value | Value to lookup | Required | 
| product_id | Target product: "sao" or "sds". Default: "sao". | Required |
| description | Description | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Endpoint_Connection.actionId | String | The action id | 
| VisionOne.Endpoint_Connection.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

7. `trendmicro-visionone-add-objects-to-exception-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The object type: "domain", "ip", "sha1", or "url" | Required | 
| value | Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , https://.example.com/path1/) SHA1 only full match" | Required | 
| description | Description | Optional |

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
| type | The object type: "domain", "ip", "sha1", or "url" |Required| 
| value | The object value | Required | 

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
| type | The object type: "domain", "ip", "sha1", or "url" |Required| 
| value | The object value  | Required | 
| description | Description | Optional |
| scan_action | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. "block" or "log" | Optional |
| risk_level | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. "high", "medium", or "low" | Optional |
| expiry_days | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead. | Optional |


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
| type | The object type: "domain", "ip", "sha1", or "url" |Required| 
| value | The object value  | Required |  


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Suspicious_List.message | String | Status message of existing task | 
| VisionOne.Suspicious_List.status_code | String | Response code of existing task |
| VisionOne.Suspicious_List.total_items | String | Number of items present in the exception list. |

11. `trendmicro-visionone-terminate-process`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field to use to lookup computer_id. "hostname", "macaddr" or "ip" |Required| 
| value | Value to lookup | Required | 
| file_sha1 | SHA1 hash of the process to terminate | Required |
| product_id | Target product. Default: "sao" | Optional |
| description | Description | Optional |
| filename | Optional file name list for log | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Terminate_Process.actionId | String | The action id | 
| VisionOne.Terminate_Process.taskStatus | String | Status of existing task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout is ``20 minutes``.

12. `trendmicro-visionone-get-file-analysis-status`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | task_id from the trendmicro-visionone-submit-file-to-sandbox command output |Required| 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.File_Analysis_Status.message | String | Message status | 
| VisionOne.File_Analysis_Status.code | String | Code status of the task |
| VisionOne.File_Analysis_Status.task_id | String | Task id |
| VisionOne.File_Analysis_Status.taskStatus | String | Task status |
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
| report_id | report_id of the sandbox submission retrieved from the trendmicro-visionone-get-file-analysis-status command |Required| 
| type | Type of report to retrieve: "vaReport", "investigationPackage", or "suspiciousObject" |Required|

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.File_Analysis_Report.message | String | Message status |
| VisionOne.File_Analysis_Report.code | String | Code status of task |
| VisionOne.File_Analysis_Report.type | String | type of report |
| VisionOne.File_Analysis_Report.value | String | value of the above type |
| VisionOne.File_Analysis_Report.risk_level | String | risk level of the file |
| VisionOne.File_Analysis_Report.analysis_completion_time | String | Final analysed time of report |
| VisionOne.File_Analysis_Report.expired_time | String | Expiry time of report |
| VisionOne.File_Analysis_Report.root_file_sha1 | String | sha value of the root file | 

14. `trendmicro-visionone-collect-forensic-file`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field to use to lookup computer_id. "hostname", "macaddr" or "ip" |Required|
| value | Value to lookup | Required | 
| product_id | Product: "sao" "xes" "sds" |Required|
| file_path | Path of the file to collect |Required|
| os | "windows", "mac" or "linux" |Required|
| description | Description of file collected |Optional| 
#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Collect_Forensic_File.actionId | String | Action id of the running task |
| VisionOne.Collect_Forensic_File.taskStatus | String | Status of the running task |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

15. `trendmicro-visionone-download-information-for-collected-forensic-file`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actionId | actionId output from the collect command used to collect the file |Required| 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Download_Information_For_Collected_Forensic_File.url | String | URL of the collected file |
| VisionOne.Download_Information_For_Collected_Forensic_File.expires | String | URL expiration date |
| VisionOne.Download_Information_For_Collected_Forensic_File.password | String | Archive password for the protected forensic file |
| VisionOne.Download_Information_For_Collected_Forensic_File.filename | String | Name of the collected file |

Note: The URL received from the 'trendmicro-visionone-download-information-for-collected-forensic-file' will be valid for only ``60 seconds``

16. `trendmicro-visionone-submit-file-to-sandbox`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_url | URL pointing to the location of the file to be submitted. |Required| 
| filename | Name of the file to be analyzed. |Required| 
| document_password | The password for decrypting the submitted document. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | Optional |
| archive_password | The password for decrypting the submitted archive. The value must be Base64-encoded. The maximum password length is 128 bytes prior to encoding. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Submit_File_to_Sandbox.message | String | Message status of the sandbox file |
| VisionOne.Submit_File_to_Sandbox.code | String | Code status of the sandbox file |
| VisionOne.Submit_File_to_Sandbox.task_id | String | Task ID of the running task |
| VisionOne.Submit_File_to_Sandbox.digest | Object | Sha value of the file |

17. `trendmicro-visionone-check-task-status`

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | If the command is to run at the polling interval. | Optional | 
| actionId | Action ID of the task you would like to get the status of. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VisionOne.Task_Status.taskStatus | String | Status of the task queried. |
---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/trend-micro-vision-one)