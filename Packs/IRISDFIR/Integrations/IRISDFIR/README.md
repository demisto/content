IRIS is a collaborative platform aiming to help incident responders to share technical details during investigations. It's free and open-source.
## Configure IRIS DFIR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IRIS DFIR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server IP or Host Name (e.g., https://192.168.0.1) | True |
    | API Key for authentication | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### iris-get-last-case-id

***
IRIS Command to get the last case information

#### Base Command

`iris-get-last-case-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_soc_id | unknown |  | 
| IRIS.case_id | number |  | 
| IRIS.case_description | unknown |  | 
| IRIS.opened_by | unknown |  | 
| IRIS.owner | unknown |  | 
| IRIS.classification_id | number |  | 
| IRIS.state_name | unknown |  | 
| IRIS.case_open_date | unknown |  | 
| IRIS.case_name | unknown |  | 
| IRIS.client_name | unknown |  | 
| IRIS.classification | unknown |  | 
| IRIS.case_uuid | unknown |  | 
| IRIS.state_id | unknown |  | 
| IRIS.access_level | unknown |  | 

### iris-get-all-cases

***
Return a list of all IRIS DFIR cases

#### Base Command

`iris-get-all-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
