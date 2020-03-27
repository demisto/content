<<<<<<< HEAD
## Overview
---
Use the Accessdata integration to protect against and provide additional visibility into phishing and other malicious email attacks.
This integration was integrated and tested with version 20190926 of QuinC
## Accessdata Playbook
---
For example, you can look at "Accessdata: Dump memory for malicious process" playbook to understand how to use this integration.
## Configure Accessdata on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Accessdata.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL with scheme (FQDN or IP address in X.X.X.X format with scheme specified)__
    * __The token is required to connect to QuinC.__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. accessdata-legacyagent-get-processlist
2. accessdata-legacyagent-get-memorydump
3. accessdata-read-casefile
4. accessdata-jobstatus-scan
5. accessdata-get-jobstatus-processlist
6. accessdata-get-jobstatus-memorydump
7. accessdata-get-processing-case-id
### accessdata-legacyagent-get-processlist
---
Return list of process from legacy agent
##### Base Command

`accessdata-legacyagent-get-processlist`
=======
Use the Quin-C AccessData integration to protect against and provide additional visibility into phishing and other malicious email attacks. This integration was integrated and tested with version 20190926 of Quin-C Accessdata. 

Documentation for the integration was provided by Quin-C.

## AccessData Playbook

For example, you can look at “Accessdata: Dump memory for malicious process” playbook to understand how to use this integration.

## Configure AccessData on Demisto

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Accessdata.
3.  Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Example** |
    | --------- | ----------- | ------- |
    | Name | A meaningful name for the integration instance. | Quin-C Instance Alpha |
    | Server URL | The URL to the AccessData server, including the scheme. | FQDN or IP address in X.X.X.X format with scheme specified. |
    | Token | A piece of data that servers use to verify for authenticity | eea810f5-a6f6 |
    | Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
    | Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | https://proxyserver.com |
    
4.  Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.


### Get a process list

* * *

Returns a list of processes from the legacy agent.

##### Base Command

`accessdata-legacyagent-get-processlist`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| caseid | ID of case | Optional | 
| target_ip | IP address of agent | Required | 

=======
| caseid | The ID of the case. | Optional |
| target_ip | The IP address of the agent. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.Type | string | Job type | 
| Accessdata.Job.State | string | Job execution state | 


##### Command Example
`accessdata-legacyagent-get-processlist caseid=2 target_ip=X.X.X.X`
=======
| Accessdata.Job.ID | string | The ID of the job. |
| Accessdata.Job.CaseID | string | The ID of the case. |
| Accessdata.Job.CaseJobID | string | The concatenated CaseID and JobID, for example, like “1_800”. |
| Accessdata.Job.Type | string | The job type. |
| Accessdata.Job.State | string | The execution state of the job. |

##### Command Example
```
accessdata-legacyagent-get-processlist caseid=2 target_ip=X.X.X.X
```
>>>>>>> upstream/master

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 157, 
        "Type": "Volatile", 
        "CaseID": "2", 
        "State": "Unknown", 
        "CaseJobID": "2_157"
    }
}
```

##### Human Readable Output
<<<<<<< HEAD
JobID: 157

### accessdata-legacyagent-get-memorydump
---
Creates legacy agent memory dump
##### Base Command

`accessdata-legacyagent-get-memorydump`
=======

JobID: 157

### Create a legacy agent memory dump

* * *

Creates a legacy agent memory dump.

##### Base Command

`accessdata-legacyagent-get-memorydump`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| caseid | ID of case | Optional | 
| target_ip | IP address of agent | Required | 

=======
| caseid | The ID of the case. | Optional |
| target_ip | The IP address of the agent. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.Type | string | Job type | 
| Accessdata.Job.State | string | Job execution state | 


##### Command Example
`accessdata-legacyagent-get-memorydump caseid=2 target_ip=X.X.X.X`

=======
| Accessdata.Job.ID | string | The ID of the job. |
| Accessdata.Job.CaseID | string | The ID of the case. |
| Accessdata.Job.CaseJobID | string | The concatenated CaseID and JobID, for example, like “1_800”. |
| Accessdata.Job.Type | string | The job type. |
| Accessdata.Job.State | string | The execution state of the job. |

##### Command Example
```
accessdata-legacyagent-get-memorydump caseid=2 target_ip=X.X.X.X
```
>>>>>>> upstream/master
##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 158, 
        "Type": "LegacyMemoryDump", 
        "CaseID": "2", 
        "State": "Unknown", 
        "CaseJobID": "2_158"
    }
}
```

##### Human Readable Output
<<<<<<< HEAD
JobID: 158

### accessdata-read-casefile
---
Reads file from case folder and puts its contents to current context
##### Base Command

`accessdata-read-casefile`
=======

JobID: 158

### Read a file from a case folder

* * *

Reads a file from a case folder and puts the contents into the context output.

##### Base Command

`accessdata-read-casefile`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| filepath | Path to case file | Required | 

=======
| filepath | The path to the case file. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.File.Contents | string | Contents of the file | 


##### Command Example
`accessdata-read-casefile filepath="\\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml"`
=======
| Accessdata.File.Contents | string | The contents of the file. |

##### Command Example
```
accessdata-read-casefile filepath="\\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml"
```
>>>>>>> upstream/master

##### Context Example
```
{
    "Accessdata.File.Contents": "<?xml version=\"1.0\"?>\r\n<root>\r\n<Process resultitemtype=\"15\"><Name>addm.exe</Name><Path/><StartTi ... ress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>\r\n</root>\r\n"
}
```

##### Human Readable Output
<<<<<<< HEAD
<?xml version="1.0"?>
<root>
<Process resultitemtype="15"><Name>addm.exe</Name><Path/><StartTi ... ress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>
</root>


### accessdata-jobstatus-scan
---
Checks status of the job
##### Base Command

`accessdata-jobstatus-scan`
=======
```
<?xml version="1.0"?>
<root>
<Process resultitemtype="15">\<Name>addm.exe</Name>\<Path/>\<StartTi ... ress>0</baseAddress>\<ImageSize>0</ImageSize>\<ProcessName/>\<FromAgent/>\</DLL>
</root>
```
### Check the status of a job

* * *

Checks the status of a job.

##### Base Command

`accessdata-jobstatus-scan`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| caseJobID | Concatenated CaseID and JobID (like "1_800") | Required | 

=======
| caseJobID | The concatenated CaseID and JobID, for example, “1_800”. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.ID | string | Job ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.State | string | State of job's execution | 


##### Command Example
`accessdata-jobstatus-scan caseJobID=2_153`
=======
| Accessdata.Job.CaseID | string | The ID of the case. |
| Accessdata.Job.ID | string | The ID of the job. |
| Accessdata.Job.CaseJobID | string | The concatenated CaseID and JobID, for example, like “1_800”. |
| Accessdata.Job.State | string | The execution state of the job. |

##### Command Example
```
accessdata-jobstatus-scan caseJobID=2_153
```
>>>>>>> upstream/master

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "153", 
        "CaseID": "2", 
        "State": "Success", 
        "CaseJobID": "2_153"
    }
}
```

##### Human Readable Output
<<<<<<< HEAD
Current job state: Success

### accessdata-get-jobstatus-processlist
---
Get snapshot path from result of the process list job
##### Base Command

`accessdata-get-jobstatus-processlist`
=======

Current job state: Success

### Get a snapshot of a path

* * *

Gets a snapshot of the path from the results of the process list job.

##### Base Command

`accessdata-get-jobstatus-processlist`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 

=======
| caseID | The ID of the case. | Required |
| jobID | The ID of the job. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.Job.State | string | Job state | 
| Accessdata.Job.Result | string | Path to snapshot with processes list | 
| Accessdata.Job.ID | number | ID of the job | 
| Accessdata.Job.CaseID | number | Case ID of the job | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-get-jobstatus-processlist caseID=2 jobID=153`
=======
| Accessdata.Job.State | string | The state of the job. |
| Accessdata.Job.Result | string | The snapshot of the path with the processes list. |
| Accessdata.Job.ID | number | The ID of the job. |
| Accessdata.Job.CaseID | number | The case ID of the job. |
| Accessdata.Job.CaseJobID | string | The concatenated CaseID and JobID, for example, like “1_800”. |

##### Command Example
```
accessdata-get-jobstatus-processlist caseID=2 jobID=153
```
>>>>>>> upstream/master

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "153", 
        "Result": "\\\\X.X.X.X\\D$\\paths\\cases\\ProcessingHelperCase\\b389a8e9-4ce4-473d-8d2e-9026f53f925c\\Jobs\\job_153\\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\\1\\snapshot.xml", 
        "CaseID": "2", 
        "State": "Success", 
        "CaseJobID": "2_153"
    }
}
```

##### Human Readable Output
<<<<<<< HEAD
\\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml

### accessdata-get-jobstatus-memorydump
---
Get memory dump path from result of the memory dump job
##### Base Command

`accessdata-get-jobstatus-memorydump`
=======

\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml

### Get a memory dump

* * *

Gets a memory dump path from the results of a memory dump job.

##### Base Command

`accessdata-get-jobstatus-memorydump`

>>>>>>> upstream/master
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
<<<<<<< HEAD
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 

=======
| caseID | The ID of the case. | Required |
| jobID | The ID of the job. | Required |
>>>>>>> upstream/master

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.Job.State | string | Job state | 
| Accessdata.Job.Result | string | Path to memory dump | 
| Accessdata.Job.ID | number | ID of the job | 
| Accessdata.Job.CaseID | number | Case ID of the job | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-get-jobstatus-memorydump caseID=2 jobID=154`

=======
| Accessdata.Job.State | string | The state of the job. |
| Accessdata.Job.Result | string | The path of the memory dump. |
| Accessdata.Job.ID | number | The ID of the job. |
| Accessdata.Job.CaseID | number | The case ID of the job. |
| Accessdata.Job.CaseJobID | string | The concatenated CaseID and JobID, for example, like “1_800”. |

##### Command Example
```
accessdata-get-jobstatus-memorydump caseID=2 jobID=154
```
>>>>>>> upstream/master
##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "154", 
        "Result": "\\\\X.X.X.X\\data\\SiteServer\\storage\\60564598-ca55-475c-9f27-ab4992e8ff46\\1\\memdump.mem", 
        "CaseID": "2", 
        "State": "Success", 
        "CaseJobID": "2_154"
    }
}
```

##### Human Readable Output
<<<<<<< HEAD
\\X.X.X.X\data\SiteServer\storage\60564598-ca55-475c-9f27-ab4992e8ff46\1\memdump.mem

### accessdata-get-processing-case-id
---
Getting ID of Quin-C processing case
##### Base Command

`accessdata-get-processing-case-id`
=======

\X.X.X.X\data\SiteServer\storage\60564598-ca55-475c-9f27-ab4992e8ff46\1\memdump.mem

### Get an ID

* * *

Returns the ID of the processing case.

##### Base Command

`accessdata-get-processing-case-id`

>>>>>>> upstream/master
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
<<<<<<< HEAD
| Accessdata.ProcessingCaseId | string | ID of Quin-C processing case | 


##### Command Example
`accessdata-get-processing-case-id`
=======
| Accessdata.ProcessingCaseId | string | The ID of the processing case. |

##### Command Example
```
accessdata-get-processing-case-id
```
>>>>>>> upstream/master

##### Context Example
```
{
    "Accessdata.ProcessingCaseId": 2
}
```

##### Human Readable Output
<<<<<<< HEAD
=======

>>>>>>> upstream/master
2
