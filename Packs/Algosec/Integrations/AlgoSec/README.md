Algosec AppViz, Firewall Analyzer (AFA) and FireFlow(AFF).

## Configure AlgoSec on XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for AlgoSec.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://192.168.0.1)__
    * __Credentials__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. algosec-get-ticket
2. algosec-create-ticket
3. algosec-get-applications
4. algosec-get-network-object
5. algosec-query
### 1. algosec-get-ticket
---
Retrieves a FireFlow change request by its ID

##### Base Command

`algosec-get-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | ID of requested change request | Required | 


##### Context Output

There is no context output for this command.


### 2. algosec-create-ticket
---
Creates a new FireFlow change request
##### Base Command

`algosec-create-ticket`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A free text description of the issue | Optional | 
| devices | A list of device names, on which the change should be made | Optional | 
| action | The device action to perform for the traffic. This can be either<br>of the following: \U0010FC00 1 - Allow the traffic \U0010FC00 0 - Block the<br>traffic<br> | Required | 
| destAddress | The destination address to perform the action on | Required | 
| sourceAddress | The source address to perform the action on | Required | 
| requestor | The email address of the requestor | Required | 
| subject | The change request's title | Required | 
| service | The device service or port for the connection, for example, "http" or ￼￼￼￼￼￼￼￼Mandatory "tcp/123" | Required | 
| user | The user for the connection | Required | 
| application | The application for the connection | Required | 


##### Context Output

There is no context output for this command.


### 3. algosec-get-applications
---
Find applications containing network objects related to IP address using AppViz

##### Base Command

`algosec-get-applications`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The IP/Subnet to search | Required | 
| type | The search method for the address | Optional | 


##### Context Output

There is no context output for this command.

### 4. algosec-get-network-object
---
Find network objects related to IP address

##### Base Command

`algosec-get-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The IP/Subnet to search | Required | 
| type | The search method for the address (default is INTERSECT) | Optional | 


##### Context Output

There is no context output for this command.

### 5. algosec-query
---
Performs a batch traffic simulation query using Firewall Analyzer

##### Base Command

`algosec-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | source(s) for the query. Multiple values are separated by commas (,) | Required | 
| destination | destination(s) for the query. Multiple values are separated by commas (,) | Required | 
| service | service(s) for the query. Multiple values are separated by commas (,) | Required | 
| user | user for the query | Optional | 
| application | application for the query | Optional | 


##### Context Output

There is no context output for this command.
