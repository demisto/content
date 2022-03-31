Use FireMon Security Manager to create a Policy Planner Ticket and Verify Pre Changes Assessment for Rule Requirement
## Configure FireMon SecurityManager on Cortex XSOAR
 
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireMon Security Manager.
3. Click **Add instance** to create and configure a new integration instance.
 
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://www.test.com\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
 
4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### firemon-create-pp-ticket
***
Creates a new Policy Planner Ticket for PolicyPlanner in FMOS box.
 
#### Base Command
 
`firemon-create-pp-ticket`
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Domain Id is required | Required | 
| workflow_name | WorkFlow Name is required | Required | 
| requirement | List of comma seperated requirements with [List of comma seperated Sources, List of comma seperated Destinations, List of comma seperated Services, Action] | Required | 
| priority | Priority for the ticket,e.g., LOW, MEDIUM, HIGH | Required | 
| due_date | Due Date is required | Required | 
 
#### Command Example
```!firemon-create-pp-ticket domain_id=1 worflow_name="test WF" priority="LOW" due_date="2021-08-01T04:15-00:00" requirement=[{​​​​​​​​"sources":"1.1.1.1", "destinations":"2.2.2.2", "services":"http, tcp", "action":"ACCEPT"}​​​​​​​​]```
 

### firemon-pca
***
Validates and Return Pre Changes Assessment on Rules added as Requirement.
 
#### Base Command
 
`firemon-pca`
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Domain Id is required | Required | 
| device_group_id | Device Group Id is required | Required | 
| sources | List of comma seperated sources | Required | 
| destinations| List of comma seperated destinations | Required | 
| services | List of comma seperated services | Required | 
| action | Action is required | Required | 


 
#### Command Example
```!firemon-pca domain_id=1 device_group_id=1 sources="1.1.1.1" destinations="2.2.2.2" services="http" action="ACCEPT"```
 


