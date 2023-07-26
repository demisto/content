IRIS is a collaborative platform aiming to help incident responders to share technical details during investigations. It's free and open-source.
This integration was integrated and tested with version 1.0.0 of IRIS DFIR

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
| IRIS.case_soc_id | unknown | SOC ID ticket case | 
| IRIS.case_id | number | case ID ticket number | 
| IRIS.case_description | unknown | case description | 
| IRIS.opened_by | unknown | case opened by | 
| IRIS.owner | unknown | case owner | 
| IRIS.classification_id | number | case classification ID | 
| IRIS.state_name | unknown | case state name | 
| IRIS.case_open_date | unknown | case open date | 
| IRIS.case_name | unknown | case name | 
| IRIS.client_name | unknown | case client name | 
| IRIS.classification | unknown | case classification | 
| IRIS.case_uuid | unknown | case uuid | 
| IRIS.state_id | unknown | case state ID | 
| IRIS.access_level | unknown | case access level | 

### iris-get-all-cases

***
Return a list of all IRIS DFIR cases

#### Base Command

`iris-get-all-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_soc_id | unknown | SOC ID ticket case | 
| IRIS.case_id | number | case ID ticket number | 
| IRIS.case_description | unknown | case description | 
| IRIS.opened_by | unknown | case opened by | 
| IRIS.owner | unknown | case owner | 
| IRIS.classification_id | number | case classification ID | 
| IRIS.state_name | unknown | case state name | 
| IRIS.case_open_date | unknown | case open date | 
| IRIS.case_name | unknown | case name | 
| IRIS.client_name | unknown | case client name | 
| IRIS.classification | unknown | case classification | 
| IRIS.case_uuid | unknown | case uuid | 
| IRIS.state_id | unknown | case state ID | 
| IRIS.access_level | unknown | case access level | 
