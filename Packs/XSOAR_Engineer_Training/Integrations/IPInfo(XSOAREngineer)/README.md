Queries IpInfo.io for information about an IP.   Use for training how to write simple integrations.
This integration was integrated and tested with version 1 of IP Info (XSOAR Engineer)

## Configure IP Info (XSOAR Engineer) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IP Info (XSOAR Engineer).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Token | The API token from ipinfo.io | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoar-engineer-ipinfo

***
Lookup an IP

#### Base Command

`xsoar-engineer-ipinfo`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to lookup! (e.g. 8.8.8.8). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IpInfo.ip | unknown | The IP Address | 
| IpInfo.hostname | unknown | Hostname | 
| IpInfo.org | unknown | Owner | 
