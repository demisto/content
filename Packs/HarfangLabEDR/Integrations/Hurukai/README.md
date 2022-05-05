HarfangLab EDR Connector,
Compatible version 2.13.7+
This integration was integrated and tested with version 2.13.7+ of Hurukai

## Configure HarfangLab EDR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HarfangLab EDR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API URL |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | API Key |  | False |
    | Long running instance |  | False |
    | Incidents Fetch Interval |  | False |
    | Fetch alerts with type | Comma-separated list of types of alerts to fetch \(sigma, yara, hlai, vt, ransom, ioc, glimps, orion...\). | False |
    | Minimum severity of alerts to fetch |  | True |
    | Fetch alerts with status (ACTIVE, CLOSED) |  | False |
    | First fetch time | Start fetching alerts whose creation date is higher than now minus &amp;lt;first_fetch&amp;gt; days. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### test-module
***
Allows to test that the HarfangLab EDR API is reachable


#### Base Command

`test-module`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### fetch-incidents
***
Allows to retrieve incidents from the HarfangLab EDR API


#### Base Command

`fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### harfanglab-get-endpoint-info
***
Get endpoint information from agent_id


#### Base Command

`harfanglab-get-endpoint-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Agent | unknown | Agent information | 

### harfanglab-endpoint-search
***
Search for endpoint information from a hostname


#### Base Command

`harfanglab-endpoint-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Agent.id | string | agent id | 
| Harfanglab.status | string | Status | 

### harfanglab-telemetry-processes
***
Search processes on a specific hostname


#### Base Command

`harfanglab-telemetry-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (md5, sha1, sha256). | Optional | 
| hostname | Endpoint hostname. | Required | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| agent.agentid | string | An agent's identifier | 
| current_directory | string |  | 
| hashes.sha256 | string |  | 

### harfanglab-job-pipelist
***
Start a job to get the list of pipes from a host (Windows)


#### Base Command

`harfanglab-job-pipelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-artifact-downloadfile
***
Start a job to download a file from a host (Windows / Linux)


#### Base Command

`harfanglab-job-artifact-downloadfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 
| filename | Path of the file to download. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-prefetchlist
***
Start a job to get the list of prefetches from a host (Windows)


#### Base Command

`harfanglab-job-prefetchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-runkeylist
***
Start a job to get the list of run keys from a host (Windows)


#### Base Command

`harfanglab-job-runkeylist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-scheduledtasklist
***
Start a job to get the list of scheduled tasks from a host (Windows)


#### Base Command

`harfanglab-job-scheduledtasklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-driverlist
***
Start a job to get the list of drivers from a host (Windows)


#### Base Command

`harfanglab-job-driverlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-servicelist
***
Start a job to get the list of services from a host (Windows)


#### Base Command

`harfanglab-job-servicelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-processlist
***
Start a job to get the list of processes from a host (Windows / Linux)


#### Base Command

`harfanglab-job-processlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-networkconnectionlist
***
Start a job to get the list of network connections from a host (Windows / Linux)


#### Base Command

`harfanglab-job-networkconnectionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-networksharelist
***
Start a job to get the list of network shares from a host (Windows)


#### Base Command

`harfanglab-job-networksharelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-sessionlist
***
Start a job to get the list of sessions from a host (Windows)


#### Base Command

`harfanglab-job-sessionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-persistencelist
***
Start a job to get the list of persistence items from a host (Linux)


#### Base Command

`harfanglab-job-persistencelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-ioc
***
Start a job to search for IOCs on a host (Windows / Linux)


#### Base Command

`harfanglab-job-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 
| filename | exact filename to search. | Optional | 
| filepath | exact filepath to search. | Optional | 
| hash | filehash to search (md5, sha1, sha256). | Optional | 
| search_in_path | restrict searchs for filename or filepath or filepath_regex to a given path. | Optional | 
| hash_filesize | size of the file associated to the 'hash' parameters. If known, it will speed up the search process. | Optional | 
| registry | regex to search in registry (key or value). | Optional | 
| filepath_regex | search a regex on a filepath . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-startuplist
***
Start a job to get the list of startup items from a host (Windows)


#### Base Command

`harfanglab-job-startuplist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-wmilist
***
Start a job to get the list of WMI items from a host (Windows)


#### Base Command

`harfanglab-job-wmilist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

### harfanglab-job-artifact-mft
***
Start a job to download the MFT from a host (Windows)


#### Base Command

`harfanglab-job-artifact-mft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-hives
***
Start a job to download the hives from a host (Windows)


#### Base Command

`harfanglab-job-artifact-hives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-evtx
***
Start a job to download the event logs from a host (Windows)


#### Base Command

`harfanglab-job-artifact-evtx`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-logs
***
Start a job to download Linux log files from a host (Linux)


#### Base Command

`harfanglab-job-artifact-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-filesystem
***
Start a job to download Linux filesystem entries from a host (Linux)


#### Base Command

`harfanglab-job-artifact-filesystem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-all
***
Start a job to download all artifacts from a host (Windows MFT, Hives, evt/evtx, Prefetch, USN, Linux logs and file list)


#### Base Command

`harfanglab-job-artifact-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-job-artifact-ramdump
***
Start a job to get the entine RAM from a host (Windows / Linux)


#### Base Command

`harfanglab-job-artifact-ramdump`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

### harfanglab-telemetry-network
***
Search network connections from a specific hostname


#### Base Command

`harfanglab-telemetry-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| source_address | Source IP address. | Optional | 
| source_port | Source port. | Optional | 
| destination_address | Destination IP address. | Optional | 
| destination_port | Destination port. | Optional | 


#### Context Output

There is no context output for this command.
### harfanglab-telemetry-eventlog
***
Search event logs from a specific hostname


#### Base Command

`harfanglab-telemetry-eventlog`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 


#### Context Output

There is no context output for this command.
### harfanglab-telemetry-binary
***
Search for binaries


#### Base Command

`harfanglab-telemetry-binary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| hash | filehash to search (md5, sha1, sha256). | Optional | 


#### Context Output

There is no context output for this command.
### harfanglab-job-info
***
Get job status information


#### Base Command

`harfanglab-job-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Coma-separated list of job ids. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.Status | string | Job Status | 

### harfanglab-result-pipelist
***
Get a hostname's list of pipes from job results


#### Base Command

`harfanglab-result-pipelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Pipe.data | unknown | Provides a list of named pipes | 

### harfanglab-result-prefetchlist
***
Get a hostname's list of prefetches from job results


#### Base Command

`harfanglab-result-prefetchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Prefetch.data | unknown | Provides a list of prefetch files | 

### harfanglab-result-runkeylist
***
Get a hostname's list of run keys from job results


#### Base Command

`harfanglab-result-runkeylist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.RunKey.data | unknown | Provides a list of Run Keys | 

### harfanglab-result-scheduledtasklist
***
Get a hostname's list of scheduled tasks from job results


#### Base Command

`harfanglab-result-scheduledtasklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.ScheduledTask.data | unknown | Provides a list of scheduled tasks | 

### harfanglab-result-driverlist
***
Get a hostname's loaded drivers from job results


#### Base Command

`harfanglab-result-driverlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Driver.data | unknown | Provides a list of loaded drivers | 

### harfanglab-result-servicelist
***
Get a hostname's list of services from job results


#### Base Command

`harfanglab-result-servicelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Service.data | unknown | Provides a list of services | 

### harfanglab-result-processlist
***
Get a hostname's list of processes from job results


#### Base Command

`harfanglab-result-processlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Process.data | unknown | Provides a list of processes | 

### harfanglab-result-networkconnectionlist
***
Get a hostname's network connections from job results


#### Base Command

`harfanglab-result-networkconnectionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.NetworkConnection.data | unknown | Provides a list of active network connections | 

### harfanglab-result-networksharelist
***
Get a hostname's network shares from job results


#### Base Command

`harfanglab-result-networksharelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.NetworkShare.data | unknown | Provides a list of network shares | 

### harfanglab-result-sessionlist
***
Get a hostname's sessions from job results


#### Base Command

`harfanglab-result-sessionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Session.data | unknown | Provides a list of active sessions | 

### harfanglab-result-persistencelist
***
Get a hostname's persistence items from job results


#### Base Command

`harfanglab-result-persistencelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.PersistenceList.data | unknown | Provides a list of persistence means | 

### harfanglab-result-ioc
***
Get the list of items matching IOCs searched in an IOC job


#### Base Command

`harfanglab-result-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.IOC.data | unknown | Provides a list of matching elements | 

### harfanglab-result-startuplist
***
Get a hostname's startup items from job results


#### Base Command

`harfanglab-result-startuplist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Startup.data | unknown | Provides a list of startup files | 

### harfanglab-result-wmilist
***
Get a hostname's WMI items from job results


#### Base Command

`harfanglab-result-wmilist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Wmi.data | unknown | Provides a list of WMI items | 

### harfanglab-result-artifact-mft
***
Get a hostname's MFT from job results


#### Base Command

`harfanglab-result-artifact-mft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the raw MFT | 

### harfanglab-result-artifact-hives
***
Get a hostname's hives from job results


#### Base Command

`harfanglab-result-artifact-hives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the raw hives | 

### harfanglab-result-artifact-evtx
***
Get a hostname's log files from job results


#### Base Command

`harfanglab-result-artifact-evtx`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the evt/evtx files | 

### harfanglab-result-artifact-logs
***
Get a hostname's log files from job results


#### Base Command

`harfanglab-result-artifact-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the log files | 

### harfanglab-result-artifact-filesystem
***
Get a hostname's filesystem entries from job results


#### Base Command

`harfanglab-result-artifact-filesystem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the CSV file with filesystem entries | 

### harfanglab-result-artifact-all
***
Get all artifacts from a hostname from job results


#### Base Command

`harfanglab-result-artifact-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download an archive with all raw artifacts | 

### harfanglab-result-artifact-downloadfile
***
Get a hostname's file from job results


#### Base Command

`harfanglab-result-artifact-downloadfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.DownloadFile.data | unknown | Provides a link to download the file | 

### harfanglab-result-artifact-ramdump
***
Get a hostname's RAM dump from job results


#### Base Command

`harfanglab-result-artifact-ramdump`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Ramdump.data | unknown | Provides a link to download the raw RAM dump | 

### harfanglab-hunt-search-hash
***
Command used to search a hash IOC in database


#### Base Command

`harfanglab-hunt-search-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (md5, sha1, sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Hash | unknown | Provides statistics associated to currently running processes and previously executed processes associated to hash | 

### harfanglab-hunt-search-running-process-hash
***
Command used to search running process associated with Hash


#### Base Command

`harfanglab-hunt-search-running-process-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.HuntRunningProcessSearch.data | unknown | List of all systems where processes associated to hash are running | 

### harfanglab-hunt-search-runned-process-hash
***
Command used to search runned process associated with Hash


#### Base Command

`harfanglab-hunt-search-runned-process-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.HuntRunnedProcessSearch.data | unknown | List of all systems where processes associated to hash have been previously running | 

### harfanglab-isolate-endpoint
***
Command used to isolate an endpoint from the network while remaining connected to the EDR manager


#### Base Command

`harfanglab-isolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

There is no context output for this command.
### harfanglab-deisolate-endpoint
***
Command used to deisolate an endpoint and reconnect it to the network


#### Base Command

`harfanglab-deisolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

There is no context output for this command.
### harfanglab-change-security-event-status
***
Command used to change the status of a security event


#### Base Command

`harfanglab-change-security-event-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_event_id | Security event id. | Required | 
| status | New status of the security event id (New, Investigating, False Positive, Closed). | Required | 


#### Context Output

There is no context output for this command.
### harfanglab-assign-policy-to-agent
***
Assign a policy to an agent


#### Base Command

`harfanglab-assign-policy-to-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentid | Agent identifier. | Required | 
| policy | Policy name. | Required | 


#### Context Output

There is no context output for this command.
### harfanglab-add-ioc-to-source
***
Add an IOC to a Threat Intelligence source


#### Base Command

`harfanglab-add-ioc-to-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | IOC value. | Required | 
| ioc_type | IOC type (hash, filename, filepath). | Required | 
| ioc_comment | Comment associated to IOC. | Optional | 
| ioc_status | IOC status (stable, testing). | Required | 
| source_name | IOC Source Name. | Required | 


#### Context Output

There is no context output for this command.
### harfanglab-delete-ioc-from-source
***
Delete an IOC from a Threat Intelligence source


#### Base Command

`harfanglab-delete-ioc-from-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | IOC value. | Required | 
| source_name | IOC Source Name. | Required | 


#### Context Output

There is no context output for this command.
