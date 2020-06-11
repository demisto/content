Infocyte can pivot off incidents to automate triage, validate events with forensic data and enabling dynamic response actions against any or all host using both agentless or agented endpoint access.
This integration was integrated and tested with version xx of Infocyte
## Configure Infocyte on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Infocyte.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| InstanceName | Instance Name \(e.g., https://&lt;cname&gt;.infocyte.com\) | True |
| APIKey | API Key | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | Initial fetch time \(days\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### infocyte-scan-host
***
Kicks off a Scan (forensic collection) against an endpoint


#### Base Command

`infocyte-scan-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-isolate-host
***
Isolates a host to only communicate to Infocyte and other security tools


#### Base Command

`infocyte-isolate-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with taskstatus | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 
| Infocyte.Task.extensionName | string | Name of extension ran | 


#### Command Example
```!infocyte-isolate-host target="pegasusactual"```

#### Context Example
```
{}
```

#### Human Readable Output

>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

### infocyte-restore-host
***
Restore an isolated host


#### Base Command

`infocyte-restore-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 
| Infocyte.Task.extensionName | string | Name of extension ran | 


#### Command Example
```!infocyte-restore-host target="pegasusactual"```

#### Context Example
```
{}
```

#### Human Readable Output

>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

### infocyte-collect-evidence
***
Collects Forensic Evidence to S3 bucket (Dat files, eventlogs, etc.)


#### Base Command

`infocyte-collect-evidence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 
| Infocyte.Task.extensionName | string | Name of extension ran | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-kill-process
***
Kills a process on target endpoint


#### Base Command

`infocyte-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 
| processName | Name of process to search for and kill on target endpoint | Optional | 
| sha1 | SHA1 of process image to search for and kill | Optional | 
| processId | Pid of process to search for and kill on target endpoint | Optional | 
| processPath | Path of of process to search for and kill on target endpoint | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!infocyte-kill-process target="pegasusactual"```

#### Context Example
```
{}
```

#### Human Readable Output

>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

### infocyte-recover-file
***
Recovers a file on an endpoint to your defined recovery point (S3, ftp, share)


#### Base Command

`infocyte-recover-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 
| paths | Paths of the files to recover from the target endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 
| Infocyte.Task.extensionName | string | Name of extension ran | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-run-response
***
Runs the named Infocyte extension on target host


#### Base Command

`infocyte-run-response`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Hostname or ip address of target endpoint | Required | 
| extensionName | Name of extension loaded in Infocyte to run on target host | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.target | string | Hostname or ip of target provided | 
| Infocyte.Task.extensionName | string | Name of extension ran | 


#### Command Example
```!infocyte-run-response target="pegasusactual" extensionName="Yara Scanner"```

#### Context Example
```
{}
```

#### Human Readable Output

>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                

### infocyte-get-taskstatus
***
Gets status of an Infocyte task (scan, response action, etc.)


#### Base Command

`infocyte-get-taskstatus`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userTaskId | Task id used with infocyte-get-taskstatus. This id is returned from any async command/task. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Task.userTaskId | string | Task id used with infocyte\-get\-taskstatus. This id is returned from any async command/task. | 
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas. | 
| Infocyte.Task.type | string | Task type \(SCAN or RESPONSE\) | 
| Infocyte.Task.progress | number | Percent completed | 
| Infocyte.Task.message | string | Message regarding the current status | 
| Infocyte.Task.status | string | Current status of task \(created, active, completed, cancelled, failed\) | 
| Infocyte.Task.timeElapsed | number | Seconds since task created | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-get-scanresult
***
Retrieve metadata and results for a scan against multiple hosts


#### Base Command

`infocyte-get-scanresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Scan.completedOn | date | Time scan was completed on target | 
| Infocyte.Scan.alerts | array | List of alerts associated with scan of host | 
| Infocyte.Scan.alertCount | number | number of alerts associated with scan of host | 
| Infocyte.Scan.compromisedObjects | number | Bad files, artifacts, and events found | 
| Infocyte.Scan.objectCount | number | Total files, artifacts, and events collected | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-get-hostscanresult
***
Retrieve results for a scan on a target host


#### Base Command

`infocyte-get-hostscanresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 
| target | Hostname or ip address of target endpoint | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Scan.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Scan.hostId | string | Infocyte Id assigned to the target host | 
| Infocyte.Scan.os | string | Operating system of the target host | 
| Infocyte.Scan.compromised | boolean | Flagged if system has a malicious item found | 
| Infocyte.Scan.alerts | array | List of alerts associated with scan of host | 
| Infocyte.Scan.alertCount | number | number of alerts associated with scan of host | 
| Infocyte.Scan.hostname | string | Hostname of target host | 
| Infocyte.Scan.ip | string | Ip of target host | 
| Infocyte.Scan.compromisedObjects | number | Bad files, artifacts, and events found | 
| Infocyte.Scan.objectCount | number | Total number of files, artifacts, and events inspected or retrieved | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-get-responseresult
***
Gets the results of a response action.


#### Base Command

`infocyte-get-responseresult`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte-get-taskstatus and is present in all job-based data schemas | Required | 
| target | Hostname or ip address of target endpoint | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Response.scanId | string | Infocyte id used to look up the data associated with a specific scan, collection, or action. scanIds are returned by infocyte\-get\-taskstatus and is present in all job\-based data schemas | 
| Infocyte.Response.hostId | string | Infocyte Id assigned to the target host | 
| Infocyte.Response.os | string | Operating system of the target host | 
| Infocyte.Response.success | boolean | Flag if extention successfully ran and completed \(not necessarily if it performed everything correctly\) | 
| Infocyte.Response.threatStatus | string | Threat category assigned by extension logic \(Good, Low risk, Unknown, Suspicious, Bad\) | 
| Infocyte.Response.compromised | boolean | Flagged if system has a malicious item found | 
| Infocyte.Response.completedOn | date | Datetime stamp that action completed | 
| Infocyte.Response.messages | string | Logs of the response action taking place on the target endpoint | 
| Infocyte.Response.hostname | string | Hostname of target host | 
| Infocyte.Response.ip | string | Ip of target host | 
| Infocyte.Response.extensionId | string | Id of Infocyte extension being run | 
| Infocyte.Response.extensionName | string | Name of Infocyte extension being run | 


#### Command Example
``` ```

#### Human Readable Output



### infocyte-get-alerts
***
Retrieve alerts since last alert pulled


#### Base Command

`infocyte-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Infocyte alertId to look up | Optional | 
| lastAlertId | Last alertId to start fetching from | Optional | 
| max | Number of alerts to fetch | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infocyte.Alert.id | string | Infocyte alertId | 
| Infocyte.Alert.scanId | string | Infocyte scanId the alert originated from | 
| Infocyte.Alert.name | string | Name of alerted file or alert | 
| Infocyte.Alert.type | string | Type of object or artifact | 
| Infocyte.Alert.threatName | string | Threat category assigned by extension logic \(Good, Low risk, Unknown, Suspicious, Bad\) | 
| Infocyte.Alert.hasAvScan | boolean | True if it has been scanned by AV engines | 
| Infocyte.Alert.threatScore | number | 0\-10 confidence score. Higher = more confident. | 
| Infocyte.Alert.avPositive | number | Number of engines and threat intel sources flagging the object as bad | 
| Infocyte.Alert.avTotal | number | Number of engines and threat intel sources that analyzed the object | 
| Infocyte.Alert.synapse | number | Infocyte proprietary machine learning based score on maliciousness. Negative \(especially below \-1\) is bad, positive is good | 
| Infocyte.Alert.size | number | Size of object in bytes | 
| Infocyte.Alert.flagname | string | Name of user assigned flag in Infocyte on this artifact | 
| Infocyte.Alert.flagWeight | number | 0\-10 score assigned to the flag. Higher = more critical | 
| Infocyte.Alert.createdOn | date | Datetime stamp the alert | 
| Infocyte.Alert.hostname | string | Hostname of target host | 
| Infocyte.Alert.sha1 | string | Sha1 \(fileRepId\) of file | 
| Infocyte.Alert.signed | boolean | Valid digital signature on file | 
| Infocyte.Alert.managed | boolean | File is validated as part of linux package | 


#### Command Example
``` ```

#### Human Readable Output


