Check Android app samples (APK) against Koodous API.

## Configure Koodous on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Koodous.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | False |
    | API Key | False |

4. Click **Test** to validate the URL and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### k-check-hash

***
Check APK sample.

#### Base Command

`k-check-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash of the sample (MD5, SHA1 or SHA256). | Required | 
