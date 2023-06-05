# Integration Author: Trend Micro

Support and maintenance for this integration are provided by the author. Please use the following contact details:

- **Email**: [integrations@trendmicro.com](mailto:integrations@trendmicro.com)

***
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Configure Trend Micro Vision One V3. on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Vision One V3.
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

### trendmicro-visionone-enable-user-account

***
Allows the user to sign in to new application and browser sessions. Supported IAM systems -> Azure AD and Active Directory (on-premises)

#### Base Command

`trendmicro-visionone-enable-user-account`

#### Input

| **Argument Name** | **Description**                            | **Required** |
| ----------------- | ------------------------------------------ | ------------ |
| accountName       | The User account that needs to be enabled. | Required     |
| description       | Description of a response task.            | Optional     |

#### Context Output

| **Path**                           | **Type** | **Description**                                    |
| ---------------------------------- | -------- | -------------------------------------------------- |
| VisionOne.User_Account.status_code | number   | Task status code of request to enable user account |
| VisionOne.User_Account.taskId      | string   | Task ID of enabling user account                   |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-disable-user-account

***
Signs the user out of all active application and browser sessions, and prevents the user from signing in any new session. Supported IAM systems -> Azure AD and Active Directory (on-premises)

#### Base Command

`trendmicro-visionone-disable-user-account`

#### Input

| **Argument Name** | **Description**                             | **Required** |
| ----------------- | ------------------------------------------- | ------------ |
| accountName       | The User account that needs to be disabled. | Required     |
| description       | Description of a response task.             | Optional     |

#### Context Output

| **Path**                           | **Type** | **Description**                                     |
| ---------------------------------- | -------- | --------------------------------------------------- |
| VisionOne.User_Account.status_code | number   | Task status code of request to disable user account |
| VisionOne.User_Account.taskId      | string   | Task ID of disabling user account                   |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-force-signout

***
Signs the user out of all active application and browser sessions. Supported IAM systems -> Azure AD

#### Base Command

`trendmicro-visionone-force-signout`

#### Input

| **Argument Name** | **Description**                 | **Required** |
| ----------------- | ------------------------------- | ------------ |
| accountName       | The User account to sign out.   | Required     |
| description       | Description of a response task. | Optional     |

#### Context Output

| **Path**                           | **Type** | **Description**                              |
| ---------------------------------- | -------- | -------------------------------------------- |
| VisionOne.User_Account.status_code | number   | Task status code of request to sign out user |
| VisionOne.User_Account.taskId      | string   | Task ID of signing out user                  |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-force-password-reset

***
Signs the user out of all active application and browser sessions, and forces the user to create a new password during the next sign-in attempt. Supported IAM systems -> Azure AD and Active Directory (on-premises)

#### Base Command

`trendmicro-visionone-force-password-reset`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| accountName       | The User account for which the password needs to be reset. | Required     |
| description       | Description of a response task.                            | Optional     |

#### Context Output

| **Path**                           | **Type** | **Description**                                    |
| ---------------------------------- | -------- | -------------------------------------------------- |
| VisionOne.User_Account.status_code | number   | Task status code of request to reset user password |
| VisionOne.User_Account.taskId      | string   | Task ID of resetting user password                 |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-add-to-block-list

***
Adds a file SHA-1, IP address, domain, or URL object to the User-Defined Suspicious Objects List, which blocks the objects on subsequent detections

#### Base Command

`trendmicro-visionone-add-to-block-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| value_type        | The type of object you would like to add to the block list: "file_sha1", "ip", "domain", "url" or "mailbox". Possible values are: file_sha1, domain, ip, url, mailbox. | Required     |
| target_value      | The object you would like to add that matches the value-type.                                                                                                          | Required     |
| description       | Optional description for reference.                                                                                                                                    | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**                                                                                                 |
| -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| VisionOne.BlockList.taskId | string   | Task ID of action of adding file SHA-1, IP address, domain, or URL to the User-Defined Suspicious Objects List  |
| VisionOne.BlockList.status | number   | Task status of adding file SHA-1, IP address, domain, or URL object to the User-Defined Suspicious Objects List |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-remove-from-block-list

***
Removes a file SHA-1, IP address, domain, or URL from the User-Defined Suspicious Objects List

#### Base Command

`trendmicro-visionone-remove-from-block-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                             | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| value_type        | The type of object you would like to remove from the block list: "file_sha1", "ip", "domain", "url" or "mailbox". Possible values are: file_sha1, domain, ip, url, mailbox. | Required     |
| target_value      | The object you would like to add that matches the value-type.                                                                                                               | Required     |
| description       | Optional description for reference.                                                                                                                                         | Optional     |

#### Context Output

| **Path**                   | **Type** | **Description**                                                                                                                                  |
| -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| VisionOne.BlockList.taskId | string   | Task ID of action of removing file SHA-1, IP address, domain, or URL object from the User-Defined Suspicious Objects List                        |
| VisionOne.BlockList.status | number   | Task Status of removing file SHA-1, IP address, domain, or URL object that was added to the User-Defined Suspicious Objects List from block list |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-quarantine-email-message

***
Moves a message from a mailbox to the quarantine folder

#### Base Command

`trendmicro-visionone-quarantine-email-message`

#### Input

| **Argument Name** | **Description**                                                                 | **Required** |
| ----------------- | ------------------------------------------------------------------------------- | ------------ |
| message_id        | Email Message ID from Trend Micro Vision One message activity data.             | Required     |
| uniqueId          | Unique alphanumeric string that identifies an email message within one mailbox. | Required     |
| mailbox           | Email mailbox where the message will be quarantined from.                       | Optional     |
| description       | Optional description for reference.                                             | Optional     |

#### Context Output

| **Path**               | **Type** | **Description**                                                         |
| ---------------------- | -------- | ----------------------------------------------------------------------- |
| VisionOne.Email.taskId | string   | The Task Id of moving a message from a mailbox to the quarantine folder |
| VisionOne.Email.status | number   | The status of moving a message from a mailbox to the quarantine folder  |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-delete-email-message

***
Deletes a message from a mailbox

#### Base Command

`trendmicro-visionone-delete-email-message`

#### Input

| **Argument Name** | **Description**                                                                 | **Required** |
| ----------------- | ------------------------------------------------------------------------------- | ------------ |
| message_id        | Email Message ID from Trend Micro Vision One message activity data.             | Required     |
| uniqueId          | Unique alphanumeric string that identifies an email message within one mailbox. | Required     |
| mailbox           | Email mailbox where the message will be quarantined from.                       | Optional     |
| description       | Optional description for reference.                                             | Optional     |

#### Context Output

| **Path**               | **Type** | **Description**                                      |
| ---------------------- | -------- | ---------------------------------------------------- |
| VisionOne.Email.taskId | string   | The Task id of deleting a message from a mailbox     |
| VisionOne.Email.status | number   | The task status of deleting a message from a mailbox |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.

### trendmicro-visionone-isolate-endpoint

***
Disconnects an endpoint from the network (but allows communication with the managing Trend Micro product)

#### Base Command

`trendmicro-visionone-isolate-endpoint`

#### Input

| **Argument Name** | **Description**                                       | **Required** |
| ----------------- | ----------------------------------------------------- | ------------ |
| endpoint          | "hostname" or "agentGuid" of the endpoint to isolate. | Required     |
| description       | Description.                                          | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                      |
| ---------------------------------------- | -------- | ------------------------------------ |
| VisionOne.Endpoint_Connection.taskId     | string   | The task ID of isolate endpoint task |
| VisionOne.Endpoint_Connection.taskStatus | number   | The task status of isolate endpoint  |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-restore-endpoint-connection

***
Restores network connectivity to an endpoint that applied the "isolate endpoint" action

#### Base Command

`trendmicro-visionone-restore-endpoint-connection`

#### Input

| **Argument Name** | **Description**                                       | **Required** |
| ----------------- | ----------------------------------------------------- | ------------ |
| endpoint          | "hostname" or "agentGuid" of the endpoint to restore. | Required     |
| description       | Description.                                          | Optional     |

#### Context Output

| **Path**                                 | **Type** | **Description**                                |
| ---------------------------------------- | -------- | ---------------------------------------------- |
| VisionOne.Endpoint_Connection.taskId     | string   | The task ID of the restore endpoint connection |
| VisionOne.Endpoint_Connection.taskStatus | number   | The task status of restore endpoint connection |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-add-objects-to-exception-list

***
Adds domains, file SHA-1 values, IP addresses, or URLs to the Exception List and prevents these objects from being added to the Suspicious Object List

#### Base Command

`trendmicro-visionone-add-objects-to-exception-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                              | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress" or "url". Possible values are: domain, ip, fileSha1, fileSha256, senderMailAddress, url.                                                                                                                                                                                                                                                                          | Required     |
| value             | The object value. Full and partial matches supported. Domain partial match, (with a wildcard as the subdomain, example, .example.com) IP partial match, (IP range example, 192.168.35.1-192.168.35.254, cidr example, 192.168.35.1/24) URL Partial match, (Supports wildcards 'http://.'', 'https://.'' at beginning, or ''' at the end. Multiple wild cards also supported, such as , <https://.example.com/path1/>) SHA1 Only full match". | Required     |
| description       | Exception description.                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional     |

#### Context Output

| **Path**                             | **Type** | **Description**                         |
| ------------------------------------ | -------- | --------------------------------------- |
| VisionOne.Exception_List.status_code | number   | status code of response                 |
| VisionOne.Exception_List.total_items | number   | count of item present in exception list |

### trendmicro-visionone-delete-objects-from-exception-list

***
Deletes domains, file SHA-1 values, IP addresses, or URLs from the Exception List.

#### Base Command

`trendmicro-visionone-delete-objects-from-exception-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress" or "url". Possible values are: domain, ip, fileSha1, fileSha256, senderMailAddress, url. | Required     |
| value             | The object value.                                                                                                                                                   | Required     |

#### Context Output

| **Path**                             | **Type** | **Description**                         |
| ------------------------------------ | -------- | --------------------------------------- |
| VisionOne.Exception_List.status_code | number   | status code of response                 |
| VisionOne.Exception_List.total_items | number   | count of item present in exception list |

### trendmicro-visionone-add-objects-to-suspicious-list

***
Adds domains, file SHA-1/SHA-256 values, IP addresses, senderMailAddress, or URLs to the Suspicious Object List.

#### Base Command

`trendmicro-visionone-add-objects-to-suspicious-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress" or "url". Possible values are: domain, ip, fileSha1, fileSha256, senderMailAddress, url.                                           | Required     |
| value             | The object value.                                                                                                                                                                                             | Required     |
| description       | Description.                                                                                                                                                                                                  | Optional     |
| scan_action       | The action to take if object is found. If you don't use this parameter, the scan action specified in default_settings.riskLevel.type will be used instead. "block" or "log". Possible values are: block, log. | Optional     |
| risk_level        | The Suspicious Object risk level. If you don't use this parameter, high will be used instead. "high", "medium" or "low". Possible values are: high, medium, low.                                              | Optional     |
| expiry_days       | The number of days to keep the object in the Suspicious Object List. If you don't use this parameter, the default_settings.expiredDay scan action will be used instead.                                       | Optional     |

#### Context Output

| **Path**                              | **Type** | **Description**                                        |
| ------------------------------------- | -------- | ------------------------------------------------------ |
| VisionOne.Suspicious_List.status_code | number   | Response code of adding item to suspicious object list |
| VisionOne.Suspicious_List.total_items | number   | Number of items present in suspicious object list      |

### trendmicro-visionone-delete-objects-from-suspicious-list

***
Deletes domains, file SHA-1 values, IP addresses, or URLs from the Suspicious Object List

#### Base Command

`trendmicro-visionone-delete-objects-from-suspicious-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| type              | Object type: "domain", "ip", "fileSha1", "fileSha256", "senderMailAddress" or "url". Possible values are: domain, ip, fileSha1, fileSha256, senderMailAddress, url. | Required     |
| value             | The object value.                                                                                                                                                   | Required     |

#### Context Output

| **Path**                              | **Type** | **Description**                                            |
| ------------------------------------- | -------- | ---------------------------------------------------------- |
| VisionOne.Suspicious_List.status_code | number   | Response code of removing item from suspicious object list |
| VisionOne.Suspicious_List.total_items | number   | Number of items present in suspicious object list          |

### trendmicro-visionone-get-endpoint-info

***
Retrieves information about a specific endpoint

#### Base Command

`trendmicro-visionone-get-endpoint-info`

#### Input

| **Argument Name** | **Description**                                                         | **Required** |
| ----------------- | ----------------------------------------------------------------------- | ------------ |
| endpoint          | "hostname", "macAddress", "agentGuid" or "ip" of the endpoint to query. | Required     |

#### Context Output

| **Path**                                      | **Type** | **Description**                                                   |
| --------------------------------------------- | -------- | ----------------------------------------------------------------- |
| VisionOne.Endpoint_Info.status                | string   | Status of the request                                             |
| VisionOne.Endpoint_Info.logonAccount          | string   | Account currently logged on to the endpoint                       |
| VisionOne.Endpoint_Info.hostname              | string   | Hostname                                                          |
| VisionOne.Endpoint_Info.macAddr               | string   | MAC address                                                       |
| VisionOne.Endpoint_Info.ip                    | string   | IP address                                                        |
| VisionOne.Endpoint_Info.osName                | string   | Operating System name                                             |
| VisionOne.Endpoint_Info.osVersion             | string   | Operating System version                                          |
| VisionOne.Endpoint_Info.osDescription         | string   | Description of the Operating System                               |
| VisionOne.Endpoint_Info.productCode           | string   | Product code of the Trend Micro product running on the endpoint   |
| VisionOne.Endpoint_Info.agentGuid             | string   | AgentGuid of the endpoint                                         |
| VisionOne.Endpoint_Info.installedProductCodes | string   | Product code of the Trend Micro product installed on the endpoint |

### trendmicro-visionone-terminate-process

***
Terminates a process that is running on an endpoint

#### Base Command

`trendmicro-visionone-terminate-process`

#### Input

| **Argument Name** | **Description**                                                    | **Required** |
| ----------------- | ------------------------------------------------------------------ | ------------ |
| endpoint          | "hostname" or "agentGuid" of the endpoint to terminate process on. | Required     |
| file_sha1         | SHA1 hash of the process to terminate.                             | Required     |
| description       | Description.                                                       | Optional     |
| filename          | Optional file name list for log.                                   | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**                     |
| -------------------------------------- | -------- | ----------------------------------- |
| VisionOne.Terminate_Process.taskId     | string   | Task Id of the current running task |
| VisionOne.Terminate_Process.taskStatus | number   | Status of current running task      |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout is ``20 minutes``.

### trendmicro-visionone-get-file-analysis-status

***
Retrieves the status of a sandbox analysis submission

#### Base Command

`trendmicro-visionone-get-file-analysis-status`

#### Input

| **Argument Name** | **Description**                                                                                                                   | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| task_id           | task_id from the trendmicro-visionone-submit-file-to-sandbox or trendmicro-visionone-submit-file-entry-to-sandbox command output. | Required     |

#### Context Output

| **Path**                                          | **Type** | **Description**                                           |
| ------------------------------------------------- | -------- | --------------------------------------------------------- |
| VisionOne.File_Analysis_Status.id                 | string   | Submission ID of the file submitted for sandbox analysis  |
| VisionOne.File_Analysis_Status.status             | string   | Response code for the action call                         |
| VisionOne.File_Analysis_Status.action             | string   | Action performed on the submitted file                    |
| VisionOne.File_Analysis_Status.error              | string   | Error code and message for the submission                 |
| VisionOne.File_Analysis_Status.digest             | string   | The hash values of file analyzed                          |
| VisionOne.File_Analysis_Status.createdDateTime    | string   | Create date time for the sandbox analysis                 |
| VisionOne.File_Analysis_Status.lastActionDateTime | string   | Date and time for last action performed on the submission |
| VisionOne.File_Analysis_Status.resourceLocation   | string   | Location of the submitted file                            |
| VisionOne.File_Analysis_Status.isCached           | string   | Is the file cached or not \(True or False\)               |
| VisionOne.File_Analysis_Status.arguments          | string   | Arguments for the file submitted                          |

### trendmicro-visionone-get-file-analysis-result

***
Retrieves the sandbox submission analysis result

#### Base Command

`trendmicro-visionone-get-file-analysis-result`

#### Input

| **Argument Name** | **Description**                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------- | ------------ |
| report_id         | report_id of the sandbox submission retrieved from the trendmicro-visionone-get-file-analysis-status command. | Required     |

#### Context Output

| **Path**                                                  | **Type** | **Description**                                 |
| --------------------------------------------------------- | -------- | ----------------------------------------------- |
| VisionOne.File_Analysis_Result.status_code                | string   | status code of file report                      |
| VisionOne.File_Analysis_Result.type                       | string   | Suspicious object type                          |
| VisionOne.File_Analysis_Result.digest                     | string   | The hash values of file analyzed                |
| VisionOne.File_Analysis_Result.risk_level                 | string   | Risk Level of suspicious object                 |
| VisionOne.File_Analysis_Result.analysisCompletionDateTime | string   | Analyze time of suspicious object               |
| VisionOne.File_Analysis_Result.arguments                  | string   | Arguments for the suspicious object             |
| VisionOne.File_Analysis_Result.detectionNames             | string   | Detection name for the suspicious object        |
| VisionOne.File_Analysis_Result.threatTypes                | string   | Threat type of the suspicious object            |
| VisionOne.File_Analysis_Result.trueFileType               | string   | File type for the suspicious object.            |
| VisionOne.File_Analysis_Result.DBotScore.Score            | number   | The DBot score.                                 |
| VisionOne.File_Analysis_Result.DBotScore.Vendor           | string   | The Vendor name.                                |
| VisionOne.File_Analysis_Result.DBotScore.Reliability      | string   | The Reliability of an intelligence-data source. |

### trendmicro-visionone-collect-forensic-file

***
Compresses a file on an endpoint in a password-protected archive and then sends the archive to the XDR service platform

#### Base Command

`trendmicro-visionone-collect-forensic-file`

#### Input

| **Argument Name** | **Description**                                               | **Required** |
| ----------------- | ------------------------------------------------------------- | ------------ |
| endpoint          | "hostname" or "macaddr" of the endpoint to collect file from. | Required     |
| file_path         | Path to the file to collect.                                  | Required     |
| description       | Description of the file.                                      | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**                 |
| ------------------------------------------ | -------- | ------------------------------- |
| VisionOne.Collect_Forensic_File.taskId     | string   | Task ID of the particular file. |
| VisionOne.Collect_Forensic_File.taskStatus | number   | Task status of collected file   |

Note: To get the complete task status run polling command `trendmicro-visionone-check-task-status` giving `taskId` as input parameter.
Note: The above command should be added with execution timeout in the advanced field of playbook execution. The recommended timeout be ``20 minutes``.

### trendmicro-visionone-download-information-for-collected-forensic-file

***
Retrieves a URL and other information required to download a collected file via the trendmicro-visionone-collect-forensic-file command

#### Base Command

`trendmicro-visionone-download-information-for-collected-forensic-file`

#### Input

| **Argument Name** | **Description**                                                  | **Required** |
| ----------------- | ---------------------------------------------------------------- | ------------ |
| task_id           | taskId output from the collect command used to collect the file. | Required     |

#### Context Output

| **Path**                                                                      | **Type** | **Description**                                                 |
| ----------------------------------------------------------------------------- | -------- | --------------------------------------------------------------- |
| VisionOne.Download_Information_For_Collected_Forensic_File.status             | string   | Status of action performed \(succeeded, running or failed\)     |
| VisionOne.Download_Information_For_Collected_Forensic_File.createdDateTime    | string   | The create date time for the file                               |
| VisionOne.Download_Information_For_Collected_Forensic_File.taskId             | string   | The task ID for the response of collect file                    |
| VisionOne.Download_Information_For_Collected_Forensic_File.lastActionDateTime | string   | Time and date of last action on file                            |
| VisionOne.Download_Information_For_Collected_Forensic_File.description        | string   | Task description                                                |
| VisionOne.Download_Information_For_Collected_Forensic_File.action             | string   | Action performed on file                                        |
| VisionOne.Download_Information_For_Collected_Forensic_File.account            | string   | The account associated with the request                         |
| VisionOne.Download_Information_For_Collected_Forensic_File.agentGuid          | string   | AgentGuid of the endpoint used to collect file                  |
| VisionOne.Download_Information_For_Collected_Forensic_File.endpointName       | string   | hostname of the endpoint used to collect file                   |
| VisionOne.Download_Information_For_Collected_Forensic_File.filePath           | string   | File path for the file that was collected                       |
| VisionOne.Download_Information_For_Collected_Forensic_File.fileSha1           | string   | The fileSha1 for the collected file                             |
| VisionOne.Download_Information_For_Collected_Forensic_File.fileSha256         | string   | The fileSha256 for the collected file                           |
| VisionOne.Download_Information_For_Collected_Forensic_File.fileSize           | number   | The file size of the file collected                             |
| VisionOne.Download_Information_For_Collected_Forensic_File.resourceLocation   | string   | URL location of the file collected that can be used to download |
| VisionOne.Download_Information_For_Collected_Forensic_File.expiredDateTime    | string   | The expiration date and time of the file                        |
| VisionOne.Download_Information_For_Collected_Forensic_File.password           | string   | The password for the file collected                             |

Note: The URL received from the `trendmicro-visionone-download-information-for-collected-forensic-file` will be valid for only ``60 seconds``

### trendmicro-visionone-download-investigation-package

***
Downloads the investigation package based on submission ID.

#### Base Command

`trendmicro-visionone-download-investigation-package`

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| submission_id     | The submission ID for the object submitted to sandbox for analysis. | Required     |
| filename          | Optional name for the package to be downloaded.                     | Optional     |

#### Context Output

| **Path**                                              | **Type** | **Description**                      |
| ----------------------------------------------------- | -------- | ------------------------------------ |
| VisionOne.Download_Investigation_Package.submissionId | string   | The submission for the file          |
| VisionOne.Download_Investigation_Package.code         | number   | Response status code for the command |

### trendmicro-visionone-download-suspicious-object-list

***
Downloads the suspicious object list associated to the specified object. Note ~ Suspicious Object Lists are only available for objects with a high risk level.

#### Base Command

`trendmicro-visionone-download-suspicious-object-list`

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| submission_id     | The submission ID for the object submitted to sandbox for analysis. | Required     |

#### Context Output

| **Path**                                                             | **Type** | **Description**                                        |
| -------------------------------------------------------------------- | -------- | ------------------------------------------------------ |
| VisionOne.Download_Suspicious_Object_list.code                       | number   | status code for the command                            |
| VisionOne.Download_Suspicious_Object_list.riskLevel                  | string   | Risk level of the analyzed object                      |
| VisionOne.Download_Suspicious_Object_list.analysisCompletionDateTime | string   | The analysis completion date and time                  |
| VisionOne.Download_Suspicious_Object_list.expiredDateTime            | string   | The expiration date and time for the suspicious object |
| VisionOne.Download_Suspicious_Object_list.rootSha1                   | string   | The rootSha1 value for the object                      |
| VisionOne.Download_Suspicious_Object_list.ip                         | string   | The endpoint ip associated with the submission         |

### trendmicro-visionone-download-analysis-report

***
Downloads the analysis report for an object submitted to sandbox for analysis based on the submission ID.

#### Base Command

`trendmicro-visionone-download-analysis-report`

#### Input

| **Argument Name** | **Description**                                                     | **Required** |
| ----------------- | ------------------------------------------------------------------- | ------------ |
| submission_id     | The submission ID for the object submitted to sandbox for analysis. | Required     |
| filename          | Optional name for the package to be downloaded.                     | Optional     |

#### Context Output

| **Path**                                        | **Type** | **Description**                      |
| ----------------------------------------------- | -------- | ------------------------------------ |
| VisionOne.Download_Analysis_Report.submissionId | string   | The submission for the file          |
| VisionOne.Download_Analysis_Report.code         | number   | Response status code for the command |

### trendmicro-visionone-submit-file-to-sandbox

***
Submits a file to the sandbox for analysis (Note. For more information about the supported file types, see [the Trend Micro Vision One Online Help](https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx). Submissions require credits. Does not require credits in regions where Sandbox Analysis has not been officially released.)

#### Base Command

`trendmicro-visionone-submit-file-to-sandbox`

#### Input

| **Argument Name** | **Description**                                                                                       | **Required** |
| ----------------- | ----------------------------------------------------------------------------------------------------- | ------------ |
| file_path         | URL pointing to the location of the file to be submitted.                                             | Required     |
| filename          | Name of the file to be analyzed.                                                                      | Optional     |
| document_password | The Base64 encoded password for decrypting the submitted document. sample.                            | Optional     |
| archive_password  | The Base64 encoded password for decrypting the submitted archive.                                     | Optional     |
| arguments         | Parameter that allows you to specify Base64-encoded command line arguments to run the submitted file. | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**                                  |
| ------------------------------------------ | -------- | ------------------------------------------------ |
| VisionOne.Submit_File_to_Sandbox.code      | number   | status code of the file submitted to sandbox     |
| VisionOne.Submit_File_to_Sandbox.task_id   | string   | Task ID of the submitted file                    |
| VisionOne.Submit_File_to_Sandbox.digest    | string   | The hash value of the file                       |
| VisionOne.Submit_File_to_Sandbox.arguments | string   | Command line arguments to run the submitted file |

### trendmicro-visionone-submit-file-entry-to-sandbox

***
Submits a file to the sandbox for analysis (Note. For more information about the supported file types, see [the Trend Micro Vision One Online Help](https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/threat-intelligence-/sandbox-analysis/sandbox-supported-fi.aspx). Submissions require credits. Does not require credits in regions where Sandbox Analysis has not been officially released.)

#### Base Command

`trendmicro-visionone-submit-file-entry-to-sandbox`

####

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

`trendmicro-visionone-run-sandbox-submission-polling`

#### Input

| **Argument Name** | **Description**                                                                                                                   | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| polling           | polling the task for 30 seconds interval. Default is true.                                                                        | Optional     |
| task_id           | task_id from the trendmicro-visionone-submit-file-to-sandbox or trendmicro-visionone-submit-file-entry-to-sandbox command output. | Required     |

#### Context Output

| **Path**                                                      | **Type** | **Description**                                                         |
| ------------------------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| VisionOne.Sandbox_Submission_Polling.message                  | string   | Status of the sandbox analysis                                          |
| VisionOne.Sandbox_Submission_Polling.status_code              | string   | Response code                                                           |
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
| VisionOne.Sandbox_Submission_Polling.message                  | string   | Error message for failed call.                                          |
| VisionOne.Sandbox_Submission_Polling.code                     | string   | Error code for failed call.                                             |
| VisionOne.Sandbox_Submission_Polling.DBotScore.Score          | number   | The DBot score.                                                         |
| VisionOne.Sandbox_Submission_Polling.DBotScore.Vendor         | string   | The Vendor name.                                                        |
| VisionOne.Sandbox_Submission_Polling.DBotScore.Reliability    | string   | The Reliability of an intelligence-data source.                         |

### trendmicro-visionone-check-task-status

***
Command gives the status of the running task based on the task id.

#### Base Command

`trendmicro-visionone-check-task-status`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| polling           | polling the task for 30 seconds interval. Default is true. | Optional     |
| task_id           | Task id of the task you would like to check.               | Required     |

#### Context Output

| **Path**                         | **Type** | **Description**              |
| -------------------------------- | -------- | ---------------------------- |
| VisionOne.Task_Status.taskId     | string   | Task ID of the task queried. |
| VisionOne.Task_Status.taskStatus | string   | Status of the task.          |

### trendmicro-visionone-add-note

***
Attaches a note to a workbench alert

#### Base Command

`trendmicro-visionone-add-note`

#### Input

| **Argument Name** | **Description**                                           | **Required** |
| ----------------- | --------------------------------------------------------- | ------------ |
| workbench_id      | ID of the workbench you would like to attach the note to. | Required     |
| content           | Contents of the note to be attached.                      | Required     |

#### Context Output

| **Path**                        | **Type** | **Description**                                     |
| ------------------------------- | -------- | --------------------------------------------------- |
| VisionOne.Add_Note.Workbench_Id | string   | The ID of the workbench that the note was added to. |
| VisionOne.Add_Note.note_id      | string   | The ID of the note that was added.                  |
| VisionOne.Add_Note.code         | string   | The response code from the command                  |

### trendmicro-visionone-update-status

***
Updates the status of a workbench alert

#### Base Command

`trendmicro-visionone-update-status`

#### Input

| **Argument Name** | **Description**                                                                                                | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------- | ------------ |
| workbench_id      | ID of the workbench you would like to update the status for.                                                   | Required     |
| status            | Status to assign to the workbench alert. Possible values are: new, in progress, true positive, false positive. | Required     |

#### Context Output

| **Path**                             | **Type** | **Description**                                      |
| ------------------------------------ | -------- | ---------------------------------------------------- |
| VisionOne.Update_Status.Workbench_Id | string   | The ID of the workbench that had the status updated. |
| VisionOne.Update_Status.code         | string   | The response code from the command                   |
