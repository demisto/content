Cortex XSOAR integration with FullHunt.io API
## Configure FullHunt on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FullHunt.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://soar.monstersofhack.com) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fullhunt-get-account-status

***
Get information about the user account such as credit and usage

#### Base Command

`fullhunt-get-account-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Status.accountmsg | unknown |  | 

### fullhunt-get-host

***
Get host details

#### Base Command

`fullhunt-get-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | List of hosts. | Required | 

#### Context Output

There is no context output for this command.
### domain

***
Get details about one specified domain

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | One domain to check. | Optional | 

#### Context Output

There is no context output for this command.
### fullhunt-get-subdomain

***
Get all subdomains from a given domain

#### Base Command

`fullhunt-get-subdomain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Enter the domain from which you want to enumerate subdomains. | Required | 

#### Context Output

There is no context output for this command.