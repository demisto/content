## Overview
---

Integrate with Prisma Access to monitor the status of the service, alert and take actions.

The integration uses both the Panorama XML API and SSH into the PAN-OS CLI. SSH is based on the netmiko library and will use the netmiko docker image.

## Use Cases
---

## Configure Prisma Access on XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Prisma Access.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server Host or IP (e.g.,  10.1.1.9 or panorama.mydomain)__
    * __API Port (e.g 443)__
    * __API Key__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Device group - Panorama instances only (write shared for Shared location)__
    * __Vsys - Firewall instances only__
    * __SSH Port__
    * __SSH Credentials for CLI__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. prisma-access-logout-user
2. prisma-access-query
3. prisma-access-cli-command
4. prisma-access-active-users
### 1. prisma-access-logout-user
---
Force logout a specific user from Prisma Access

##### Base Command

`prisma-access-logout-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Username to logout. (Without domain name - e.g. jsmith) | Required | 
| domain | Domain name of the user to logout. | Required | 
| computer | Computer name to logout. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.LogoutUser | unknown | LogoutUser command results | 


##### Command Example
```!prisma-access-logout-user user="JSmith" domain="mydomain" computer="PC3"```

##### Human Readable Output
```
Result from Prisma Access:
{
"result": {
"status": "pass",
"msg": ""success""
}
}
```

### 2. prisma-access-query
---
Run a query via the Prisma Access CLI
##### Required Permissions
Permissions to connect to CLI via SSH and run a debug command.
##### Base Command

`prisma-access-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query to run. Example input: querystring limit=2000 action getGPaaSLast90DaysUniqueUsers | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.QueryResults | unknown | Query results | 


##### Command Example
```!prisma-access-query query="querystring limit=5 action getGPaaSLast90DaysUniqueUsers"```



### 3. prisma-access-cli-command
---
Run a custom CLI command on Prisma Access
##### Required Permissions
Permissions to connect to CLI via SSH and run a debug command.
##### Base Command

`prisma-access-cli-command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cmd | CLI command to run (e.g. debug plugins cloud_services gpcs query querystring limit=9000 action getGPaaSLast90DaysUniqueUsers) | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 4. prisma-access-active-users
---
Query currently active users.
##### Required Permissions
Permissions to connect to CLI via SSH and run a debug command.
##### Base Command

`prisma-access-active-users`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of entries to return. Default is 20. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ActiveUsers | unknown | Active Users on Prisma Access | 


##### Command Example
```!prisma-access-active-users limit="2"```
