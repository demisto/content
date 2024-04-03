Palo Alto Networks Best Practice Assessment (BPA) analyzes NGFW and Panorama configurations and compares them to the best practices.
This integration was integrated and tested with the March 2024 version of PaloAltoNetworksAIOps.

## Configure Palo Alto Networks AIOps on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks AIOps.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Pan-OS/Panorama Server URL | True |
    | Trust any certificate (not secure) | False |
    | Pan-OS/Panorama API Key | True |
    | TSG ID | True |
    | Client ID | True |
    | Client Secret | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pan-aiops-bpa-report-generate

***
Generates a bpa

#### Base Command

`pan-aiops-bpa-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry_id from Cortex XSOAR War Room after uploading a file. | Optional | 
| requester_email | Enter the requester email. | Required | 
| requester_name | Enter the requester name. | Required | 
| interval_in_seconds | Enter the interval for polling mechanism. Default is 30. | Optional | 
| timeout | Enter the timeout for downloading the file. Default is 600. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!pan-aiops-bpa-report-generate requester_email=tal@gmail.com requester_name=tall```
#### Human Readable Output

>None

