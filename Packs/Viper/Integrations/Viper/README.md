Viper is a binary analysis and management framework.

## Configure Viper on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Viper.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Viper Project | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### viper-download

***
Download a sample with file hash

#### Base Command

`viper-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | SHA256 Value. | Required | 

#### Context Output

There is no context output for this command.
### viper-search

***
Search for sample with file hash

#### Base Command

`viper-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | SHA256 Value. | Required | 

#### Context Output

There is no context output for this command.
