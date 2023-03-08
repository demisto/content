This example integration randomly enriches file, ip, url, and domain indictors.  Useful for demos, DO NOT use this in any production environment.

Basically any of these indicators types could come back as good, suspicious, or bad.   
This integration was integrated and tested with version xx of RandomThreatIntel (XSOAR Engineer)

## Configure RandomThreatIntel (XSOAR Engineer) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RandomThreatIntel (XSOAR Engineer).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    |  |  | False |
    | Source Reliability | The reliability of this integration, remember everything is made up, so definitely not to be trusted, great for training though\! | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### url

***
URL to check

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 

#### Context Output

There is no context output for this command.
### domain

***
Domain to check 

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to check . | Required | 

#### Context Output

There is no context output for this command.
### ip

***
IP to check

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to check. | Required | 

#### Context Output

There is no context output for this command.
### file

***
File to check

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File to check. | Required | 

#### Context Output

There is no context output for this command.
### private-ip

***
IP to check 

#### Base Command

`private-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to check. | Required | 

#### Context Output

There is no context output for this command.
### cxhost

***
Host to check

#### Base Command

`cxhost`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cxhost | Host to check. | Required | 

#### Context Output

There is no context output for this command.
