Query the Symantec Endpoint Security Cloud Portal (ICDM).
This integration was integrated and tested with the SES Incidents API.

## Configure Symantec Endpoint Security (ICDM) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Endpoint Security (ICDM).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Server URL (e.g. <https://api.sep.securitycloud.symantec.com>) |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Maximum number of incidents per fetch |  | False |
    | API Key |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Fetch Events related to Incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### icdm-fetch-incidents

***
Get EDR incidents from ICDM.

#### Base Command

`icdm-fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first | The start date from when to fetch incidents (max. 30 days ago). | Optional | 
| last | The last date from when to fetch incidents. | Optional | 

#### Context Output

There is no context output for this command.
