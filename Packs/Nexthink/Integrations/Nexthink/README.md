Nexthink helps IT teams deliver on the promise of the modern digital workplace. Nexthink is the only solution to provide enterprises with a way to visualize, act and engage across the entire IT ecosystem to lower IT cost and improve digital employee experience.
This integration was integrated and tested with version xx of Nexthink

## Configure Nexthink on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nexthink.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Engine Host (e.g. connector.nexthink.com) | True |
    | Nexthink Connector Port | False |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nt_compliance_check
***
Verify antivirus/antispyware status


#### Base Command

`nt_compliance_check`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | Endpoint IP Address. | Optional | 
| hostname | Endpoint Hostname. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### nt_installed_packages
***
Verify software installed in endpoint


#### Base Command

`nt_installed_packages`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. | Optional | 
| package | Installed Software Name. Default is agent. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### nt_endpoint_details
***
Get endpoint details


#### Base Command

`nt_endpoint_details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint Hostname. | Optional | 
| ipaddress | Endpoint IP Address. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


