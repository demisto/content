# HYAS Insight

Integration with Hudsonrock OSINT tools to check IP, Email or username usage.

## Configure HYASInsight in Cortex


| **Parameter** | **Required** |
| --- |--------------|
| url | True         |
| Trust any certificate (not secure) | False        |
| Use system proxy settings | False        |
| integrationReliability | True         |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Send IP reputation query.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description**                          | **Required** |
|-------------------|------------------------------------------| --- |
| ip                | ip.                                      | Required | 



### email

***
Send Email reputation query.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------| --- |
| email             | email.          | Required | 



### hudsonrock-get-username

***
Send username reputation query.

#### Base Command

`hudsonrock-get-username`

#### Input

| **Argument Name** | **Description**                          | **Required** |
|-------------------|------------------------------------------| --- |
| username          | username.                                | Required | 


