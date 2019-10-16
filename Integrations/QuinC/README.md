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
### accessdata-legacyagent-get-processlist
---
Return list of process from legacy agent
##### Base Command

`accessdata-legacyagent-get-processlist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Required | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-legacyagent-get-processlist caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 992, 
        "Type": "Volatile", 
        "CaseID": "1", 
        "State": "Unknown", 
        "CaseJobID": "1_992"
    }
}
```

##### Human Readable Output
JobID: 992

### accessdata-legacyagent-get-memorydump
---
Creates legacy agent memory dump
##### Base Command

`accessdata-legacyagent-get-memorydump`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseid | ID of case | Required | 
| target_ip | IP address of agent | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Accessdata.Job.ID | string | ID of job | 
| Accessdata.Job.CaseID | string | Case ID | 
| Accessdata.Job.CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 


##### Command Example
`accessdata-legacyagent-get-memorydump caseid=1 target_ip=X.X.X.X`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": 993, 
        "Type": "LegacyMemoryDump", 
        "CaseID": "1", 
        "State": "Unknown", 
        "CaseJobID": "1_993"
    }
}
```

##### Human Readable Output
JobID: 993

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
`accessdata-read-casefile filepath="\\X.X.X.X\D$\Program Files\AccessData\QuinC\app\demo\Demo Case\c00a2abf-1076-412b-8dea-67305fb8015f\Jobs\job_987\f6fac193-89ff-4f3f-92ac-0871c30621c0\1\snapshot.xml"`

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
| CaseID | string | Case ID | 
| ID | string | Job ID | 
| CaseJobID | string | Concatenated CaseID and JobID (like "1_800") | 
| State | string | State of job's execution | 


##### Command Example
`accessdata-jobstatus-scan caseJobID=1_987`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "987", 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_987"
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
| State | string | Job state | 
| Result | string | Job result | 


##### Command Example
`accessdata-get-jobstatus-processlist caseID=1 jobID=987`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "987", 
        "Result": {
            "SnapshotDetails": {
                "File": "\\\\X.X.X.X\\D$\\Program Files\\AccessData\\QuinC\\app\\demo\\Demo Case\\c00a2abf-1076-412b-8dea-67305fb8015f\\Jobs\\job_987\\f6fac193-89ff-4f3f-92ac-0871c30621c0\\1\\snapshot.xml"
            }
        }, 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_987"
    }
}
```

##### Human Readable Output
\\X.X.X.X\D$\Program Files\AccessData\QuinC\app\demo\Demo Case\c00a2abf-1076-412b-8dea-67305fb8015f\Jobs\job_987\f6fac193-89ff-4f3f-92ac-0871c30621c0\1\snapshot.xml

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
| State | string | Job state | 
| Result | string | Job result | 


##### Command Example
`accessdata-get-jobstatus-memorydump caseID=1 jobID=989`

##### Context Example
```
{
    "Accessdata.Job": {
        "ID": "989", 
        "Result": "\\\\X.X.X.X\\data\\SiteServer\\storage\\8ffafb2e-d077-4165-9aa7-f00cda29cce2\\1\\memdump.mem", 
        "CaseID": "1", 
        "State": "Success", 
        "CaseJobID": "1_989"
    }
}
```

##### Human Readable Output
\\X.X.X.X\data\SiteServer\storage\8ffafb2e-d077-4165-9aa7-f00cda29cce2\1\memdump.mem
