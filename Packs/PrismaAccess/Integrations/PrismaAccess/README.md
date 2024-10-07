## Prisma Access Integration
Integrate with Prisma Access to monitor the status of the Service, alert and take actions.
The integration uses both the Panorama XML API and SSH into the PAN-OS CLI.

### Common parameters
The **Server Host or IP** parameter is required by both.

### SSH connection

The following commands require the SSH access to be configured:
 - prisma-access-active-users
 - prisma-access-cli-command
 - prisma-access-query

The SSH connection requires the **SSH Credentials for CLI**, **Password** and **SSH Port**  are provided.

SSH credentials should be your username and password for the PAN-OS CLI - they can be tested using a standalone SSH client to verify that you are able to connect to the CLI on the SSH port.


###  API connection

The following commands require the API access to be configured:
 - prisma-access-logout-user

The API connection requires the **API Port** and **API Key** parameters as well as a **Device Group** or **Vsys**.





This integration was integrated and tested with version 9.0.7 of Prisma Access

## Configure Prisma Access in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server Host or IP \(e.g.,  10.1.1.9 or panorama.my.domain\) | True |
| port | API Port \(e.g 443\) | False |
| key | API Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| device_group | Device group \- Panorama instances only \(write shared for Shared location\) | False |
| vsys | Vsys \- Firewall instances only | False |
| sshport | SSH Port | False |
| Username | SSH Credentials for CLI | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### prisma-access-logout-user
***
Force logout a specific user from Prisma Access


##### Base Command

`prisma-access-logout-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | Username to logout. (Without domain name - e.g. jsmith) | Required | 
| domain | Domain name of the user to logout. | Required | 
| computer | Computer name to logout. | Required | 
| tenant_name | The tenant name. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.LogoutUser | unknown | LogoutUser command results | 


##### Command Example
```!prisma-access-logout-user user="jsmith" domain="acme" computer="jsmithPC"```


### prisma-access-query
***
Run a query via the Prisma Access CLI


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
```!prisma-access-query query="querystring limit=2 action getGPaaSActiveUsers"```


### prisma-access-cli-command (deprecated)
***
Run a custom CLI command on Prisma Access


##### Base Command

`prisma-access-cli-command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cmd | CLI command to run (e.g. debug plugins cloud_services gpcs query querystring limit=9000 action getGPaaSLast90DaysUniqueUsers) | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!prisma-access-cli-command cmd="show system info | match hostname"```


### prisma-access-active-users (deprecated)
***
Query currently active users.


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
```!prisma-access-active-users limit=10```
