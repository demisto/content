When working with certain 3rd party products (detonation, scan, search, etc.) occasionally we'll find ourselves having to wait for a process to finish on the remote host before we can continue. In those cases the playbook should stop and wait for the process to complete on the 3rd party product, and continue once it's done.

This is impossible to achieve via integrations or automations due to hardware limitations. One of the ways to achieve this feat is via the `GenericPolling` playbook.

## What it does
Periodically polls the status of a process being executed on a remote host, and once the host returns that the process execution is done, the playbooks finishes execution.

## How to use
### Prerequisites:
* **Start command** - Command that'll fetch the initial state of the process and save it to the context. This command will usually start the process that should be polled. For example:
  * Detonation - `joe-analysis-submit-sample` - Submit a sample for analysis (will be detonated as part of the analysis).
  * Scan - `nexpose-start-assets-scan` - Starts a scan for specified asset IP addresses and host names.
  * Search - `qradar-searches` - Searches in QRadar using AQL.
* **Polling command** - Command that will poll the status of the process and save it to the context. The input of this command **must be checked** as **Is array** - this will allow the playbook to poll at once more than a single process being executed. For example:
  * Detonation - `joe-analysis-info` - Returns the status of the analysis execution.
  * Scan - `nexpose-get-scan` - Returns the specified scan.
  * Search - `qradar-get-search` - Gets a specific search id and status.

### Inputs
* **Ids** - list of process IDs to poll (usually will be a previous task output).
* **PollingCommandName** - Name of the polling command to run.
* **PollingCommandArgName** - Argument name of the polling command. The argument should be the name of the process identifier (usually will be an ID).
* **dt** - [Demisto Transform Language](https://support.demisto.com/hc/en-us/articles/115005666907-Demisto-Transform-Language-DT-) filter to be checked against the polling command result. Polling will stop when no results are returned from the DT filter.
* **Interval** - Interval between each poll (default is 1 minute).
* **Timeout** - The amount of time that'll pass until the playbook will stop waiting for the process to finish. After this time has passed the playbook will finish running, even if it didn't get a satisfactory result (the action is done executing).
* **Additional polling command arguments** - If the polling command has more than a single argument you can add their names via this input, for example: `arg1,arg2,...`. 
* **AdditionalPollingCommandArgValues** -  If the polling command has more than a single argument you can add their values via this input for example: `value1,value2,...`. 

## Example
### [Detonate File – JoeSecurity](https://github.com/demisto/content/blob/master/Playbooks/playbook-Detonate_File_-_JoeSecurity.yml)
![image](https://user-images.githubusercontent.com/20818773/66270734-7ee53b00-e85f-11e9-8566-e0118774070e.png)

* **Start command** - `joe-analysis-submit-sample` - Starts a new analysis of a file in Joe Security.
* **Polling command** - `joe-analysis-info` - Returns the status of the analysis execution.
* **Argument name** - `webid` - argument name of the polling command. 
* **Context path to store poll results** - `Joe.Analysis`
  * **ID context path** - `WebID` - Stores the ID of the process to be polled.
  * **Status context path** - `Status` - Stores the status of the process. 
* **Possible values returned from polling command**: `starting, running, finished`. 
* **DT** - We want a list of IDs of the processes that are still running. Let's explain how it's built:
`Path.To.Object(val.Status !== ‘finished’).ID`
Get the object that has a status other than ‘running’, then get its ID field.
The polling is done only once the result is `finished`. The dt filter will return an empty result in that case - which triggers the playbook to stop running. 

## Limitations
* **Global context** is not supported.
* Does not run from **playground**.
* Polling command must support list argument.
![image](https://user-images.githubusercontent.com/20818773/66293071-7d168880-e8ee-11e9-9d55-e8ae1e09fe0e.png)
