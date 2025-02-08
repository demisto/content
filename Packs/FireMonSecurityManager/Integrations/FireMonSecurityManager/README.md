FireMon Security Manager delivers comprehensive rule lifecycle management to help you manage and automate every stage of the change management process. Workflows can be customized and automated to conform to your security goals and standards, with tools at your disposal to evolve policy and protection over time.

## Configure FireMon Security Manager in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://example.net) | True |
| Username | True |
| Password | True |
| Fetch incidents | False |
| Incident type | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Incidents Fetch Interval | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### firemon-user-authentication
***
Returns authentication token


#### Base Command

`firemon-user-authentication`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.Authentication.token | String | Authentication token | 

### firemon-create-pp-ticket
***
Creates a ticket in policy planner application


#### Base Command

`firemon-create-pp-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Domain Id. | Required | 
| workflow_name | Workflow Name. Default is Access Req WF. | Optional | 
| requirement | Add requirement. | Optional | 
| priority | Priority of Policy Planner Ticket. Default is LOW. | Required | 
| due_date | Due Date of Policy Planner Ticket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.CreatePPTicket.pp_ticket | Unknown | Response for Policy Planner Ticket | 

### firemon-pca
***
PCA- Pre-Change Assessment is process of showing impact of created devices changes in early stages before implementing changes to devices. 
We can check the PCA table in Review stage of Policy planner ticket.


#### Base Command

`firemon-pca`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Domain ID. | Optional | 
| device_group_id | DeviceGroup ID. | Optional | 
| destinations | Enter comma seperated destination values. | Optional | 
| sources | Enter comma seperated source values. | Optional | 
| services | Enter comma seperated service values. | Optional | 
| action | PCA. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.PCA.pca | Unknown | Response for PCA | 

### firemon-secmgr-secrule-search
***
Searches for security rules using the SIQL language query (limit to 10k)


#### Base Command

`firemon-secmgr-secrule-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | SIQL query to search for security rules. | Required | 
| pageSize | Number of results in the page. Default is 10. | Optional | 
| page | Page in which to retrieve results. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.SIQL.matchId | Unknown | Resposne for the SIQL query | 


#### Base Command

`firemon-collector-get-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pageSize | Number of results in the page. | Optional | 
| page | Page in which to retrieve results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.Collector | Unknown | Firemon Collector Infomation. | 


#### Base Command

`firemon-collector-get-status-byid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Collector id. | true | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireMonSecurityManager.CollectorStatus | Unknown | Firemon Collector Status. | 