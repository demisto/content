## Overview
---
Use the QuinC integration to protect against and provide additional visibility into phishing and other malicious email attacks.
This integration was integrated and tested with version 20190926 of QuinC
## QuinC Playbook
---
For example, you can look at "Accessdata: Dump memory for malicious process" playbook to understand how to use this integration.
## Configure QuinC on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for QuinC.
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
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Optional | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.Type | string | Job type | 
| Accessdata.Job.State | string | Job execution state | 


##### Command Example
`accessdata-legacyagent-get-processlist caseid=2 target_ip=X.X.X.X`

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
JobID: 157

### accessdata-legacyagent-get-memorydump
---
Creates legacy agent memory dump
##### Base Command

`accessdata-legacyagent-get-memorydump`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Optional | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.Type | string | Job type | 
| Accessdata.Job.State | string | Job execution state | 


##### Command Example
`accessdata-legacyagent-get-memorydump caseid=2 target_ip=X.X.X.X`

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
JobID: 158

### accessdata-read-casefile
---
Reads file from case folder and puts its contents to current context
##### Base Command

`accessdata-read-casefile`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filepath | Path to case file | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.File.Contents | string | Contents of the file | 


##### Command Example
`accessdata-read-casefile filepath="\\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml"`

##### Context Example
```
{
    "Accessdata.File.Contents": "<?xml version=\"1.0\"?>\r\n<root>\r\n<Process resultitemtype=\"15\"><Name>addm.exe</Name><Path/><StartTi ... ress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>\r\n</root>\r\n"
}
```

##### Human Readable Output
<?xml version="1.0"?>
<root>
<Process resultitemtype="15"><Name>addm.exe</Name><Path/><StartTi ... ress>0</baseAddress><ImageSize>0</ImageSize><ProcessName/><FromAgent/></DLL>
</root>


### accessdata-jobstatus-scan
---
Checks status of the job
##### Base Command

`accessdata-jobstatus-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseJobID | Concatenated CaseID and JobID (like "1_800") | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.ID | string | Job ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| Accessdata.Job.State | string | State of job's execution | 


##### Command Example
`accessdata-jobstatus-scan caseJobID=2_153`

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
Current job state: Success

### accessdata-get-jobstatus-processlist
---
Get snapshot path from result of the process list job
##### Base Command

`accessdata-get-jobstatus-processlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.State | string | Job state | 
| Accessdata.Job.Result | string | Path to snapshot with processes list | 
| Accessdata.Job.ID | number | ID of the job | 
| Accessdata.Job.CaseID | number | Case ID of the job | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-get-jobstatus-processlist caseID=2 jobID=153`

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
\\X.X.X.X\D$\paths\cases\ProcessingHelperCase\b389a8e9-4ce4-473d-8d2e-9026f53f925c\Jobs\job_153\fa9787a3-49a1-4d73-a194-7c944eb9a3bf\1\snapshot.xml

### accessdata-get-jobstatus-memorydump
---
Get memory dump path from result of the memory dump job
##### Base Command

`accessdata-get-jobstatus-memorydump`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseID | ID of the case | Required | 
| jobID | ID of the job | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.State | string | Job state | 
| Accessdata.Job.Result | string | Path to memory dump | 
| Accessdata.Job.ID | number | ID of the job | 
| Accessdata.Job.CaseID | number | Case ID of the job | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-get-jobstatus-memorydump caseID=2 jobID=154`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "154", 
        "Result": "\\\\10.10.0.135\\data\\SiteServer\\storage\\60564598-ca55-475c-9f27-ab4992e8ff46\\1\\memdump.mem", 
        "CaseID": "2", 
        "State": "Success", 
        "CaseJobID": "2_154"
    }
}
```

##### Human Readable Output
\\10.10.0.135\data\SiteServer\storage\60564598-ca55-475c-9f27-ab4992e8ff46\1\memdump.mem

### accessdata-get-processing-case-id
---
Getting ID of Quin-C processing case
##### Base Command

`accessdata-get-processing-case-id`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.ProcessingCaseId | string | ID of Quin-C processing case | 


##### Command Example
`accessdata-get-processing-case-id`

##### Context Example
```
{
    "Accessdata.ProcessingCaseId": 2
}
```

##### Human Readable Output
2
