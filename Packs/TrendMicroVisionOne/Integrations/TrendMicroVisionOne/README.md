# Integration Author: Trend Micro

Support and maintenance for this integration are provided by the author. Please use the following contact details:

- **Email**: [integrations@trendmicro.com](mailto:integrations@trendmicro.com)

***
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Configure Trend Micro Vision One on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Vision One.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                   | **Description**                                 | **Required** |
    | ----------------------------------------------- | ----------------------------------------------- | ------------ |
    | API URL (e.g. <https://api.xdr.trendmicro.com>) | The base url for the Trend Micro Vision One API | True         |
    | API Key                                         | The API token to access data                    | True         |
    | Fetch incidents                                 |                                                 | False        |
    | Incidents Fetch Interval                        |                                                 | False        |
    | Incident type                                   |                                                 | False        |
    | Sync On First Run (days)                        |                                                 | False        |
    | Max Incidents                                   |                                                 | False        |
    | Use system proxy settings                       |                                                 | False        |
    | Trust any certificate (not secure)              |                                                 | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### trendmicro-visionone-add-to-block-list

***
Adds a file SHA-1, IP address, domain, or URL object to the User-Defined Suspicious Objects List, which blocks the objects on subsequent detections

#### Base Command

1. `trendmicro-visionone-add-to-block-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| value_type        | The type of object you would like to add to the block list: "file_sha1", "ip", "domain", "url" or "mailbox". Possible values are: file_sha1, domain, ip, url, mailbox. | Required     |
| target_value      | The object you would like to add that matches the value-type.                                                                                                          | Required     |
| product_id        | Target product.                                                                                                                                                        | Optional     |
| description       | Optional description for reference.                                                                                                                                    | Optional     |

#### Context Output

| **Path**                       | **Type** | **Description**                                                                                                 |
| ------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------- |
| VisionOne.BlockList.actionId   | string   | Action ID of task adding file SHA-1, IP address, domain, or URL to the User-Defined Suspicious Objects List     |
| VisionOne.BlockList.taskStatus | string   | Task status of adding file SHA-1, IP address, domain, or URL object to the User-Defined Suspicious Objects List |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

### trendmicro-visionone-remove-from-block-list

***
Removes a file SHA-1, IP address, domain, or URL from the User-Defined Suspicious Objects List

#### Base Command

2. `trendmicro-visionone-remove-from-block-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                             | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| value_type        | The type of object you would like to remove from the block list: "file_sha1", "ip", "domain", "url" or "mailbox". Possible values are: file_sha1, domain, ip, url, mailbox. | Required     |
| target_value      | The object you would like to add that matches the value-type.                                                                                                               | Required     |
| product_id        | Target product.                                                                                                                                                             | Optional     |
| description       | Optional description for reference.                                                                                                                                         | Optional     |

#### Context Output

| **Path**                       | **Type** | **Description**                                                                                                                                  |
| ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| VisionOne.BlockList.actionId   | string   | Action ID of task removing file SHA-1, IP address, domain, or URL object from the User-Defined Suspicious Objects List                           |
| VisionOne.BlockList.taskStatus | string   | Task Status of removing file SHA-1, IP address, domain, or URL object that was added to the User-Defined Suspicious Objects List from block list |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

### trendmicro-visionone-quarantine-email-message

***
Moves a message from a mailbox to the quarantine folder

#### Base Command

3. `trendmicro-visionone-quarantine-email-message`

#### Input

| **Argument Name**     | **Description**                                                     | **Required** |
| --------------------- | ------------------------------------------------------------------- | ------------ |
| message_id            | Email Message ID from Trend Micro Vision One message activity data. | Required     |
| mailbox               | Email mailbox where the message will be quarantined from.           | Required     |
| message_delivery_time | Email message's original delivery time.                             | Required     |
| product_id            | Target product. Default is sca.                                     | Optional     |
| description           | Optional description for reference.                                 | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**                                                           |
| -------------------------- | -------- | ------------------------------------------------------------------------- |
| VisionOne.Email.actionId   | string   | The Action Id of moving a message from a mailbox to the quarantine folder |
| VisionOne.Email.taskStatus | string   | The status of moving a message from a mailbox to the quarantine folder    |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

### trendmicro-visionone-delete-email-message

***
Deletes a message from a mailbox

#### Base Command

4. `trendmicro-visionone-delete-email-message`

#### Input

| **Argument Name**     | **Description**                                                     | **Required** |
| --------------------- | ------------------------------------------------------------------- | ------------ |
| message_id            | Email Message ID from Trend Micro Vision One message activity data. | Required     |
| mailbox               | Email mailbox where the message will be quarantined from.           | Required     |
| message_delivery_time | Email message's delivery time.                                      | Required     |
| product_id            | Target product. Default is sca.                                     | Optional     |
| description           | Optional description for reference.                                 | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**                                      |
| -------------------------- | -------- | ---------------------------------------------------- |
| VisionOne.Email.actionId   | string   | The action id of deleting a message from a mailbox   |
| VisionOne.Email.taskStatus | string   | The task status of deleting a message from a mailbox |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.

### trendmicro-visionone-isolate-endpoint

***
Disconnects an endpoint from the network (but allows communication with the managing Trend Micro product)

#### Base Command

5. `trendmicro-visionone-isolate-endpoint`

#### Input

| **Argument Name** | **Description**                                                                             | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to isolate.                                   | Required     |
| product_id        | Target product: "sao", "sds", or "xes". Possible values are: sao, sds, xes. Default is sao. | Required     |
| description       | Description.                                                                                | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                        |
| ---------------------------------------- | -------- | -------------------------------------- |
| VisionOne.Endpoint_Connection.actionId   | string   | The action ID of isolate endpoint task |
| VisionOne.Endpoint_Connection.taskStatus | string   | The task status of isolate endpoint    |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-restore-endpoint-connection

***
Restores network connectivity to an endpoint that applied the "isolate endpoint" action

#### Base Command

6. `trendmicro-visionone-restore-endpoint-connection`

#### Input

| **Argument Name** | **Description**                                                                             | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to restore.                                   | Required     |
| product_id        | Target product: "sao", "sds", or "xes". Possible values are: sao, sds, xes. Default is sao. | Required     |
| description       | Description.                                                                                | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                                  |
| ---------------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Endpoint_Connection.actionId   | string   | The action ID of the restore endpoint connection |
| VisionOne.Endpoint_Connection.taskStatus | string   | The task status of restore endpoint connection   |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-add-objects-to-exception-list

***
Adds domains, file SHA-1 values, IP addresses, or URLs to the Exception List and prevents these objects from being added to the Suspicious Object List

#### Base Command

7. `trendmicro-visionone-add-objects-to-exception-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                              | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "sha1", or "url". Possible values are: domain, ip, sha1, url.                                                                                                                                                                                                                                                                                                                                                   | Required     |
| value             | The object value. Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL Partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , <https://.example.com/path1/>) SHA1 Only full match". | Required     |
| description       | Exception description.                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                              |
| ------------------------------------ | -------- | -------------------------------------------- |
| VisionOne.Exception_List.message     | string   | status message success after task completion |
| VisionOne.Exception_List.status_code | string   | status code of response                      |
| VisionOne.Exception_List.total_items | string   | count of item present in exception list      |

### trendmicro-visionone-delete-objects-from-exception-list

***
Deletes domains, file SHA-1 values, IP addresses, or URLs from the Exception List.

#### Base Command

8. `trendmicro-visionone-delete-objects-from-exception-list`

#### Input

| **Argument Name** | **Description**                                                                            | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------ | ------------ |
| type              | Object type: "domain", "ip", "sha1", or "url". Possible values are: domain, ip, sha1, url. | Required     |
| value             | The object value.                                                                          | Required     |

#### Context Output

| **Path**                             | **Type** | **Description**                              |
| ------------------------------------ | -------- | -------------------------------------------- |
| VisionOne.Exception_List.message     | string   | status message success after task completion |
| VisionOne.Exception_List.status_code | number   | status code of response                      |
| VisionOne.Exception_List.total_items | string   | count of item present in exception list      |

### trendmicro-visionone-add-objects-to-suspicious-list

***
Adds domains, file SHA-1 values, IP addresses, or URLs to the Suspicious Object List.

#### Base Command

9. `trendmicro-visionone-add-objects-to-suspicious-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "sha1", or "url". Possible values are: domain, ip, sha1, url.                                                                                                                    | Required     |
| value             | The object value.                                                                                                                                                                                             | Required     |
| description       | Description.                                                                                                                                                                                                  | Optional     |
| scan_action       | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. "block" or "log". Possible values are: block, log. | Optional     |
| risk_level        | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. "high", "medium" or "low". Possible values are: high, medium, low.                                              | Optional     |
| expiry_days       | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead.                                       | Optional     |

#### Context Output

| **Path**                              | **Type** | **Description**                                         |
| ------------------------------------- | -------- | ------------------------------------------------------- |
| VisionOne.Suspicious_List.message     | string   | Status message of adding item to suspicious object list |
| VisionOne.Suspicious_List.status_code | number   | Response code of adding item to suspicious object list  |
| VisionOne.Suspicious_List.total_items | number   | Number of items present in suspicious object list       |

### trendmicro-visionone-delete-objects-from-suspicious-list

***
Deletes domains, file SHA-1 values, IP addresses, or URLs from the Suspicious Object List

#### Base Command

10. `trendmicro-visionone-delete-objects-from-suspicious-list`

#### Input

| **Argument Name** | **Description**                                                                            | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------ | ------------ |
| type              | Object type: "domain", "ip", "sha1", or "url". Possible values are: domain, ip, sha1, url. | Required     |
| value             | The object value.                                                                          | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                             |
| ------------------------------------- | -------- | ----------------------------------------------------------- |
| VisionOne.Suspicious_List.message     | string   | Status message of removing item from suspicious object list |
| VisionOne.Suspicious_List.status_code | number   | Response code of removing item from suspicious object list  |
| VisionOne.Suspicious_List.total_items | number   | Number of items present in suspicious object list           |

### trendmicro-visionone-get-endpoint-info

***
Retrieves information about a specific endpoint

#### Base Command

11. `trendmicro-visionone-get-endpoint-info`

#### Input

| **Argument Name** | **Description**                                         | **Required** |
| ----------------- | ------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to query. | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                                 |
| ------------------------------------- | -------- | --------------------------------------------------------------- |
| VisionOne.Endpoint_Info.message       | string   | Message information from the request                            |
| VisionOne.Endpoint_Info.errorCode     | integer  | Error code                                                      |
| VisionOne.Endpoint_Info.status        | string   | Status of the request                                           |
| VisionOne.Endpoint_Info.logonAccount  | string   | Account currently logged on to the endpoint                     |
| VisionOne.Endpoint_Info.hostname      | string   | Hostname                                                        |
| VisionOne.Endpoint_Info.macAddr       | string   | MAC address                                                     |
| VisionOne.Endpoint_Info.ip            | string   | IP address                                                      |
| VisionOne.Endpoint_Info.osName        | string   | Operating System name                                           |
| VisionOne.Endpoint_Info.osVersion     | string   | Operating System nersion                                        |
| VisionOne.Endpoint_Info.osDescription | string   | Description of the Operating System                             |
| VisionOne.Endpoint_Info.productCode   | string   | Product code of the Trend Micro product running on the endpoint |

### trendmicro-visionone-terminate-process

***
Terminates a process that is running on an endpoint

#### Base Command

12. `trendmicro-visionone-terminate-process`

#### Input

| **Argument Name** | **Description**                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to terminate process on. | Required     |
| file_sha1         | SHA1 hash of the process to terminate.                                 | Required     |
| product_id        | Target product. Possible values are: sao. Default is sao.              | Optional     |
| description       | Description.                                                           | Optional     |
| filename          | Optional file name list for log.                                       | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**                       |
| -------------------------------------- | -------- | ------------------------------------- |
| VisionOne.Terminate_Process.actionId   | string   | Action Id of the current running task |
| VisionOne.Terminate_Process.taskStatus | string   | Status of current running task        |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout is ``20 minutes``.

### trendmicro-visionone-get-file-analysis-status

***
Retrieves the status of a sandbox analysis submission

#### Base Command

13. `trendmicro-visionone-get-file-analysis-status`

#### Input

| **Argument Name** | **Description**                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------- | ------------ |
| task_id           | task_id from the trendmicro-visionone-submit-file-to-sandbox command output. | Required     |

#### Context Output

| **Path**                                                | **Type** | **Description**                                                         |
| ------------------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| VisionOne.File_Analysis_Status.message                  | string   | Status of the sandbox analysis                                          |
| VisionOne.File_Analysis_Status.code                     | string   | Response code                                                           |
| VisionOne.File_Analysis_Status.task_id                  | string   | task_id of the task queried                                             |
| VisionOne.File_Analysis_Status.taskStatus               | string   | Sandbox analysis status                                                 |
| VisionOne.File_Analysis_Status.digest                   | string   | The hash values of file analyzed                                        |
| VisionOne.File_Analysis_Status.analysis_completion_time | string   | Sample analysis completed time.                                         |
| VisionOne.File_Analysis_Status.risk_level               | string   | Risk Level of the analyzed file.                                        |
| VisionOne.File_Analysis_Status.descritption             | string   | Scan result description for NotAnalyzed.                                |
| VisionOne.File_Analysis_Status.detection_name_list      | unknown  | Detection name of this sample, if applicable.                           |
| VisionOne.File_Analysis_Status.threat_type_list         | unknown  | Threat type of this sample.                                             |
| VisionOne.File_Analysis_Status.file_type                | string   | File type of this sample.                                               |
| VisionOne.File_Analysis_Status.report_id                | string   | ID used to get the report and suspicious object. Empty means no report. |
| VisionOne.File_Analysis_Status.DBotScore.score          | number   | The DBot score.                                                         |
| VisionOne.File_Analysis_Status.DBotScore.Vendor         | string   | The Vendor name.                                                        |
| VisionOne.File_Analysis_Status.DBotScore.Reliability    | string   | The reliability level.                                                  |

### trendmicro-visionone-get-file-analysis-report

***
Retrieves the analysis report, investigation package, or Suspicious Object List of a submitted file

#### Base Command

14. `trendmicro-visionone-get-file-analysis-report`

#### Input

| **Argument Name** | **Description**                                                                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| report_id         | report_id of the sandbox submission retrieved from the trendmicro-visionone-get-file-analysis-status command.                                                 | Required     |
| type              | Type of report to retrieve: "vaReport", "investigationPackage", or "suspiciousObject". Possible values are: vaReport, investigationPackage, suspiciousObject. | Required     |

#### Context Output

| **Path**                                                | **Type** | **Description**                             |
| ------------------------------------------------------- | -------- | ------------------------------------------- |
| VisionOne.File_Analysis_Report.message                  | string   | Status message of file report               |
| VisionOne.File_Analysis_Report.code                     | string   | status code of file report                  |
| VisionOne.File_Analysis_Report.type                     | string   | Suspicious object type                      |
| VisionOne.File_Analysis_Report.value                    | string   | Suspicious object value                     |
| VisionOne.File_Analysis_Report.risk_level               | string   | Risk Level of suspicious object             |
| VisionOne.File_Analysis_Report.analysis_completion_time | string   | Analyze time of suspicious object           |
| VisionOne.File_Analysis_Report.expired_time             | string   | Expire time of suspicious object            |
| VisionOne.File_Analysis_Report.root_file_sha1           | string   | Sample sha1 generate this suspicious object |

### trendmicro-visionone-collect-forensic-file

***
Compresses a file on an endpoint in a password-protected archive and then sends the archive to the XDR service platform

#### Base Command

15. `trendmicro-visionone-collect-forensic-file`

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macaddr" or "ip" of the endpoint to collect file from. | Required     |
| product_id        | Product: "sao", "sds" or "xes". Possible values are: sao, xes, sds. | Required     |
| file_path         | Path to the file to collect.                                        | Required     |
| os                | Type of OS. "windows", "mac" or "linux".                            | Required     |
| description       | Description of the file.                                            | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**                   |
| ------------------------------------------ | -------- | --------------------------------- |
| VisionOne.Collect_Forensic_File.actionId   | string   | Action ID of the particular file. |
| VisionOne.Collect_Forensic_File.taskStatus | string   | Task status of collected file     |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `actionId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-download-information-for-collected-forensic-file

***
Retrieves a URL and other information required to download a collected file via the trendmicro-visionone-collect-forensic-file command

#### Base Command

16. `trendmicro-visionone-download-information-for-collected-forensic-file`

#### Input

| **Argument Name** | **Description**                                                    | **Required** |
| ----------------- | ------------------------------------------------------------------ | ------------ |
| actionId          | actionId output from the collect command used to collect the file. | Required     |

#### Context Output

| **Path**                                                            | **Type** | **Description**                                  |
| ------------------------------------------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Download_Information_For_Collected_Forensic_File.url      | string   | URL of the collected file                        |
| VisionOne.Download_Information_For_Collected_Forensic_File.expires  | string   | URL expiration date                              |
| VisionOne.Download_Information_For_Collected_Forensic_File.password | string   | Archive password for the protected forensic file |
| VisionOne.Download_Information_For_Collected_Forensic_File.filename | string   | Name of the collected file                       |

Note: The URL received from the `trendmicro-visionone-download-information-for-collected-forensic-file` will be valid for only ``60 seconds``

### trendmicro-visionone-submit-file-to-sandbox

***
Submits a file to the sandbox for analysis (Note. For more information about the supported file types, see [the Trend Micro Vision One Online Help](https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx). Submissions require credits. Does not require credits in regions where Sandbox Analysis has not been officially released.)

#### Base Command

17. `trendmicro-visionone-submit-file-to-sandbox`

#### Input

| **Argument Name** | **Description**                                                            | **Required** |
| ----------------- | -------------------------------------------------------------------------- | ------------ |
| file_url          | URL pointing to the location of the file to be submitted.                  | Required     |
| filename          | Name of the file to be analyzed.                                           | Required     |
| document_password | The Base64 encoded password for decrypting the submitted document. sample. | Optional     |
| archive_password  | The Base64 encoded password for decrypting the submitted archive.          | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                                  |
| ---------------------------------------- | -------- | ------------------------------------------------ |
| VisionOne.Submit_File_to_Sandbox.message | string   | Status message of the file submitted to sandbox. |
| VisionOne.Submit_File_to_Sandbox.code    | string   | status code of the file submitted to sandbox     |
| VisionOne.Submit_File_to_Sandbox.task_id | string   | Task ID of the submitted file                    |
| VisionOne.Submit_File_to_Sandbox.digest  | unknown  | The hash value of the file                       |

### trendmicro-visionone-submit-file-entry-to-sandbox

***
Submits the file corresponding to EntryID to the sandbox for analysis (Note. For more information about the supported file types, see [the Trend Micro Vision One Online Help](https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx). Submissions require credits. Does not require credits in regions where Sandbox Analysis has not been officially released.)

#### Base Command

18. `trendmicro-visionone-submit-file-entry-to-sandbox`

#### Input

| **Argument Name** | **Description**                                                            | **Required** |
| ----------------- | -------------------------------------------------------------------------- | ------------ |
| entry_id          | Entry ID of the file to be submitted.                                      | Required     |
| document_password | The Base64 encoded password for decrypting the submitted document. sample. | Optional     |
| archive_password  | The Base64 encoded password for decrypting the submitted archive.          | Optional     |

#### Context Output

| **Path**                                         | **Type** | **Description**                                  |
| ------------------------------------------------ | -------- | ------------------------------------------------ |
| VisionOne.Submit_File_Entry_to_Sandbox.message   | string   | Status message of the file submitted to sandbox. |
| VisionOne.Submit_File_Entry_to_Sandbox.code      | string   | status code of the file submitted to sandbox     |
| VisionOne.Submit_File_Entry_to_Sandbox.task_id   | string   | Task ID of the submitted file                    |
| VisionOne.Submit_File_Entry_to_Sandbox.digest    | string   | The hash value of the file                       |
| VisionOne.Submit_File_Entry_to_Sandbox.filename  | string   | The name of the file submitted                   |
| VisionOne.Submit_File_Entry_to_Sandbox.file_path | string   | The path to the file associated to incident      |
| VisionOne.Submit_File_Entry_to_Sandbox.entryId   | string   | The Entry ID for the file                        |

### trendmicro-visionone-run-sandbox-submission-polling

***
Runs a polling command to retrieve the status of a sandbox analysis submission

#### Base Command

19. `trendmicro-visionone-run-sandbox-submission-polling`

#### Input

| **Argument Name** | **Description**                                                                                                                   | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| polling           | polling the task for 30 seconds interval. Default is true.                                                                        | Optional     |
| task_id           | task_id from the trendmicro-visionone-submit-file-to-sandbox or trendmicro-visionone-submit-file-entry-to-sandbox command output. | Required     |

#### Context Output

| **Path**                                                      | **Type** | **Description**                                                         |
| ------------------------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| VisionOne.Sandbox_Submission_Polling.message                  | string   | Status of the sandbox analysis                                          |
| VisionOne.Sandbox_Submission_Polling.code                     | string   | Response code                                                           |
| VisionOne.Sandbox_Submission_Polling.task_id                  | string   | task_id of the task queried                                             |
| VisionOne.Sandbox_Submission_Polling.taskStatus               | string   | Sandbox analysis status                                                 |
| VisionOne.Sandbox_Submission_Polling.digest                   | string   | The hash values of file analyzed                                        |
| VisionOne.Sandbox_Submission_Polling.analysis_completion_time | string   | Sample analysis completed time.                                         |
| VisionOne.Sandbox_Submission_Polling.risk_level               | string   | Risk Level of the analyzed file.                                        |
| VisionOne.Sandbox_Submission_Polling.description              | string   | Scan result description for NotAnalyzed.                                |
| VisionOne.Sandbox_Submission_Polling.detection_name_list      | unknown  | Detection name of this sample, if applicable.                           |
| VisionOne.Sandbox_Submission_Polling.threat_type_list         | unknown  | Threat type of this sample.                                             |
| VisionOne.Sandbox_Submission_Polling.file_type                | string   | File type of this sample.                                               |
| VisionOne.Sandbox_Submission_Polling.report_id                | string   | ID used to get the report and suspicious object. Empty means no report. |
| VisionOne.Sandbox_Submission_Polling.DBotScore.score          | number   | The DBot score.                                                         |
| VisionOne.Sandbox_Submission_Polling.DBotScore.Vendor         | string   | The Vendor name.                                                        |
| VisionOne.Sandbox_Submission_Polling.DBotScore.Reliability    | string   | The reliability level.                                                  |

### trendmicro-visionone-check-task-status

***
Command gives the status of the running task based on the action id.

#### Base Command

20. `trendmicro-visionone-check-task-status`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| polling           | polling the task for 30 seconds interval. Default is true. | Optional     |
| actionId          | Action id of the task you would like to check.             | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**                |
| -------------------------------- | -------- | ------------------------------ |
| VisionOne.Task_Status.actionId   | unknown  | Action ID of the task queried. |
| VisionOne.Task_Status.taskStatus | unknown  | Status of the task.            |

### trendmicro-visionone-add-note

***
Attaches a note to a workbench alert

#### Base Command

21. `trendmicro-visionone-add-note`

#### Input

| **Argument Name** | **Description**                                           | **Required** |
| ----------------- | --------------------------------------------------------- | ------------ |
| workbench_id      | ID of the workbench you would like to attach the note to. | Required     |
| content           | Contents of the note to be attached.                      | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**                                     |
| -------------------------------- | -------- | --------------------------------------------------- |
| VisionOne.Add_Note.Workbench_Id  | string   | The ID of the workbench that the note was added to. |
| VisionOne.Add_Note.Note_Id       | string   | The ID of the note that was added.                  |
| VisionOne.Add_Note.Response_Code | string   | The response code from the command                  |
| VisionOne.Add_Note.Response_Msg  | string   | The response message from the command               |

### trendmicro-visionone-update-status

***
Updates the status of a workbench alert

#### Base Command

22. `trendmicro-visionone-update-status`

#### Input

| **Argument Name** | **Description**                                                                                                                  | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| workbench_id      | ID of the workbench you would like to update the status for.                                                                     | Required     |
| status            | Status to assign to the workbench alert. Possible values are: new, in_progress, resolved_true_positive, resolved_false_positive. | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                      |
| ------------------------------------- | -------- | ---------------------------------------------------- |
| VisionOne.Update_Status.Workbench_Id  | string   | The ID of the workbench that had the status updated. |
| VisionOne.Update_Status.Response_Code | string   | The response code from the command                   |
| VisionOne.Update_Status.Response_Msg  | string   | The response message from the command                |
