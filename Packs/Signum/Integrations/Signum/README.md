Signum password expiry notification.
## Configure Signum on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Signum.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Signum URL, in the format https://signmum.keyfactorsaas.com | True |
    | Username | True |
    | Password | True |
    | verify certificate | False |
    | Use system proxy | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### signum-list-domain-users

***
    List domain users by domain_id.
#### Base Command

`signum-list-domain-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Identification of the Domain to be listed the users. . Default is 1. | Required | 
| simple_view | if "True", strip off prefixes, such as "{urn:.*}" and "{http://.*}", from each dictionary Key name. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Signum.ListDomainUsers | unknown | The result of List Domain Users command. | 
