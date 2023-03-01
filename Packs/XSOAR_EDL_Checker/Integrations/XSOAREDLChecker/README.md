Checks an XSOAR EDL to make sure it's returning a valid response.
This integration was integrated and tested with version 6.8+ of Cortex XSOAR.

## Configure XSOAR EDL Checker on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR EDL Checker.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | EDL Name | The name of the edl from the generic indicator export service | True |
    | Username |  | False |
    | Password |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoaredlchecker-get-edl
***
Checks the EDL and returns the response. 


#### Base Command

`xsoaredlchecker-get-edl`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLChecker.Name | unknown | The Name of the EDL from the Generic Indicators Export Service instance | 
| EDLChecker.Status | unknown | The HTTP Status Code returned by the EDL | 
| EDLChecker.Response | unknown | The Response or Error from the check. | 
| EDLChecker.ItemsOnList | unknown | The number of indicators on the list, assuming a successful response\! | 
