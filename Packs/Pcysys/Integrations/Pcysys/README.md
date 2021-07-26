## Overview

Integration with Pentera. 
This integration was integrated and tested with version 4.5.2 of Pentera
## Pentera Playbook

## Use Cases

Integration Use Cases:
1. Integrate PenTera’s Automated Penetration Testing findings within Cortex XSOAR for playbook-driven enrichment and response
2. Address penetration testing findings, prioritize, and automate response tasks
3. Leverage Cortex XSOAR’s third-party product integrations 

Use Case #1: Automate Dynamic Vulnerability Alerts - Password Policy 
Challenge: Password policies are a continuous undertaking that organizations need to review regularly. 
Solution: With the Cortex XSOAR-PenTera integration, PenTera can continuously validate the effectiveness of enterprise passwords and take action on easily crackable passwords with focus on high privileged accounts. Once PenTera flags a password that doesn’t meet the standard, automated playbooks through Cortex XSOAR take action and remediate the vulnerability based on corporate policy.

Use Case #2: Automated real-time validation for critical vulnerabilities
Challenge: Continuous security validation is critical for the ongoing cyber hygiene of an organization’s network. However, critical vulnerabilities require on-demand testing as they influence many components of the network. Security teams struggle with prioritizing remediation and understanding the true impact vulnerabilities have on their specific network.
Solution: After running automated single-action tests for critical vulnerabilities, the Cortex XSOAR integration allows security teams to automate the response process based on the findings. For example, PenTera discovers the vulnerability of different components of the network, e.g a server or an endpoint. The latter is a simpler fix that should go through one workflow, perhaps even be automatically remediated, while the first, a much more complex process, will create a high-risk task in the relevant workflow, automatically prioritizing the response tasks based on business impact severity.

## Configure Pentera on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Pentera.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://192.168.64.128)__
    * __Pentera API port__
    * __TGT (The token from Pentera UI in Administration -> API Clients)__
    * __Client Id__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. pentera-run-template-by-name
2. pentera-get-task-run-status
3. pentera-get-task-run-full-action-report
### 1. pentera-run-template-by-name
Run a specific template by its name. Please add the template name in the parameters
##### Required Permissions
Operator and admin users
##### Base Command

`pentera-run-template-by-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_name | The name of the template that you want to run | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Pentera.TaskRun.TemplateName | String | Returns the name of the template | 
| Pentera.TaskRun.ID | String | The task run id | 
| Pentera.TaskRun.StartTime | Date | The date when the task run started | 
| Pentera.TaskRun.EndTime | Date | The date when the task run ended | 
| Pentera.TaskRun.Status | String | The status of the task run; e.g.: 'Running', 'Pending', 'Failed', 'Cleaning up', 'Canceled', 'Done', 'Warning', 'Aborted (exceeded max hosts limit)'. | 


##### Command Example
```!pentera-run-template-by-name template_name="Test Template for Playbook"```

##### Context Example
```
{
    "Pentera.TaskRun": {
        "Status": "Running", 
        "TemplateName": "Test Template for Playbook", 
        "StartTime": 2020-02-13T19:32:45Z, 
        "EndTime": null, 
        "ID": "5e45883d1deb8eda82b1eed5"
    }
}
```

##### Human Readable Output
### Test Template for Playbook
|ID|StartTime|Status|TemplateName|
|---|---|---|---|
| 2020-02-13 17:32:45Z | 5e45883d1deb8eda82b1eed5 | '2020-02-13T17:32:45Z' | Running | Test Template for Playbook |
Integration log: Full Integration Log:
Got command: pentera-run-template-by-name
result is JSON
Parsed JSON Response: {'ID': '5e45883d1deb8eda82b1eed5', 'TemplateName': 'Test Template for Playbook', 'StartTime': '2020-02-13T17:32:45Z', 'EndTime': None, 'Status': 'Running'}
Parsed JSON Response: {'ID': '5e45883d1deb8eda82b1eed5', 'TemplateName': 'Test Template for Playbook', 'StartTime': '2020-02-13T17:32:45Z', 'EndTime': None, 'Status': 'Running'}

### 2. pentera-get-task-run-status
Get the status of a task run by its task run id
##### Required Permissions
Operator and admin users
##### Base Command

`pentera-get-task-run-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_run_id | The ID of the task run | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Pentera.TaskRun.ID | String | The task run id | 
| Pentera.TaskRun.TemplateName | String | Returns the name of the template | 
| Pentera.TaskRun.StartTime | Date | The date when the task run started | 
| Pentera.TaskRun.EndTime | Date | The date when the task run ended | 
| Pentera.TaskRun.Status | String | The status of the task run; e.g.: 'Running', 'Pending', 'Failed', 'Cleaning up', 'Canceled', 'Done', 'Warning', 'Aborted (exceeded max hosts limit)'. | 


##### Command Example
```!pentera-get-task-run-status task_run_id="5e4583221deb8eda82b195c5"
```

##### Context Example
```
{
    "Pentera.TaskRun": {
        "Status": "Done", 
        "TemplateName": "Test Template for Playbook", 
        "StartTime": "2020-02-13T17:10:58Z", 
        "EndTime": "2020-02-13T19:14:12Z", 
        "ID": "5e4583221deb8eda82b195c5"
    }
}
```

##### Human Readable Output
### Test Template for Playbook
|EndTime|ID|StartTime|Status|TemplateName|
|---|---|---|---|---|
| 2020-02-13 17:10:58Z | 1581614052321.0 | 5e4583221deb8eda82b195c5 | 1581613858961.0 | Done | Test Template for Playbook |
Integration log: Full Integration Log:
Got command: pentera-get-task-run-status
result is JSON
Parsed JSON Response: {'ID': '5e4583221deb8eda82b195c5', 'TemplateName': 'Test Template for Playbook', 'StartTime': '2020-02-13T17:10:58Z', 'EndTime': '2020-02-13T19:14:12Z', 'Status': 'Done'}

### 3. pentera-get-task-run-full-action-report
Get the full action report of a task run
###### Fieldnames: 'Severity', 'Time', 'Duration', 'Operation Type', 'Techniques', 'Parameters', 'Status'
#### Severity:
* Low: [0: 2.5)
* Medium: [2.5: 5)
* High: [5: 7.5)
* Critical: [7.5: 10]
#### Duration:
In milliseconds
#### Status:
'Running', 'Pending', 'Failed', 'Cleaning up', 'Canceled', 'Done', 'Warning', 'Aborted (exceeded max hosts limit)'.
##### Required Permissions
User view, operator and admin users
##### Base Command

`pentera-get-task-run-full-action-report`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_run_id | The ID of the task run | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Pentera.TaskRun.ID | String | The task run id | 
| Pentera.TaskRun.TemplateName | String | Returns the name of the template | 
| Pentera.TaskRun.StartTime | Date | The date when the task run started | 
| Pentera.TaskRun.EndTime | Date | The date when the task run ended | 
| Pentera.TaskRun.Status | String | The status of the task run; e.g.: 'Running', 'Pending', 'Failed', 'Cleaning up', 'Canceled', 'Done', 'Warning', 'Aborted (exceeded max hosts limit)'. | 
| Pentera.TaskRun.FullActionReport | String | The full action report of the task run | 


##### Command Example
```!pentera-get-task-run-full-action-report task_run_id="5e4583221deb8eda82b195c5"
```

##### Context Example
```
{
    "Pentera.TaskRun": {
        "FullActionReport": [
            {
                "Status": "no results", 
                "Severity": "", 
                "Parameters": "Host: 192.168.1.2", 
                "Time": "13/02/2020, 17:11:59", 
                "Duration": "31578", 
                "Operation Type": "BlueKeep (CVE-2019-0708) Vulnerability Discovery", 
                "Techniques": "Network Service Scanning(T1046)"
            }, 
            {
                "Status": "no results", 
                "Severity": "", 
                "Parameters": "Host: 192.168.1.1", 
                "Time": "13/02/2020, 17:12:01", 
                "Duration": "31618", 
                "Operation Type": "BlueKeep (CVE-2019-0708) Vulnerability Discovery", 
                "Techniques": "Network Service Scanning(T1046)"
            }
        ], 
        "ID": "5e4583221deb8eda82b195c5"
    }
}
```

##### Human Readable Output
### Pentera Report for TaskRun ID
|Agent Name|Categories|Duration|Operation Type|Parameters|Severity|Status|Techniques|Time|
|---|---|---|---|---|---|---|---|---|
| default-node | Discovery, Reconnaissance | 31578 | BlueKeep (CVE-2019-0708) Vulnerability Discovery | Host: 192.168.1.2 | | no results | Network Service Scanning(T1046) | 13/02/2020, 17:11:59 |
| default-node | Discovery, Reconnaissance | 31618 | BlueKeep (CVE-2019-0708) Vulnerability Discovery | Host: 192.168.1.1 | | no results | Network Service Scanning(T1046) | 13/02/2020, 17:12:01 |
Integration log: Full Integration Log:
Got command: pentera-get-task-run-full-action-report
result is TEXT
