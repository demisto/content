Cynet XDR prevents and detects threats on endpoints, networks, and users and triggers for each identified threat an
automated investigation flow that reveals the attack’s scope and root cause and applies automated remediation.
The 24×7 MDR team continuously monitors and optimizes this process to maintain top quality and precision.
This integration was integrated and tested with version 4.2.12.11749 of Cynet XDR Platform
## Configure Cynet XDR Platform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cynet XDR Platform.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Cynet server URL (e.g., https://192.168.0.1) | True |
    | Cynet server port (e.g., 6443) | True |
    | API Username  | True |
    | Password | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cynet-get-hosts
***
List hosts from Cynet XDR


#### Base Command

`cynet-get-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| LastSeen | Format: mm-dd-yyyy. Default is 01-01-2010. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-host-details
***
Host details from Cynet XDR


#### Base Command

`cynet-get-host-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-host-full-details
***
Host full details from Cynet XDR


#### Base Command

`cynet-get-host-full-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-missing-windows-patches-details
***
Missing windows patches details from Cynet XDR


#### Base Command

`cynet-get-missing-windows-patches-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-existing-windows-patches-details
***
Existing windows patches details from Cynet XDR


#### Base Command

`cynet-get-existing-windows-patches-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-risky-application-details
***
Risky Application details from Cynet XDR


#### Base Command

`cynet-get-risky-application-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-installed-softwares-details
***
 Installed Softwares details from Cynet XDR


#### Base Command

`cynet-get-installed-softwares-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-outdates-application-details
***
 Outdates applications details from Cynet XDR


#### Base Command

`cynet-get-outdates-application-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cynet-get-agent-validation-details
***
Agent validation details from Cynet XDR


#### Base Command

`cynet-get-agent-validation-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Format: mm-dd-yyyy. Default is 01-01-2010. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


