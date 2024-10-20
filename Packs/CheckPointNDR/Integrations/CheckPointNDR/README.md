Collect network security events from Check Point Infinity NDR for your secured SaaS periodically
This integration was integrated and tested with version 1.1.0 of CheckPointNDR

## Configure Check Point Network Detection and Response (Infinity NDR) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Check Point Infinity NDR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Infinity NDR API URL (e.g. <https://api.now.checkpoint.com>) | True |
    | Client ID | True |
    | Access Key | True |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### check-point-ndr-fetch-insights

***
Retrieve all NDR Insights

#### Base Command

`check-point-ndr-fetch-insights`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
