CyberArk EPM Event Collector fetches events.
This integration was integrated and tested with version 23.12.0 of CyberArk EPM.

## Configure CyberArk EPM Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Automation & Feed Integrations**.
2. Search for CyberArk EPM Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | SAML/EPM Logon URL | SAML example: https://login.epm.cyberark.com/SAML/Logon. | True |
    | Username |  | True |
    | Password |  | True |
    | Set name | A comma-separated list of set names. | True |
    | Application ID | Required for local\(EPM\) authentication only. | False |
    | Authentication URL | Required for SAML authentication only, Example for PAN OKTA: https://paloaltonetworks.okta.com/api/v1/authn. | False |
    | Application URL | Required for SAML authentication only, Example for PAN OKTA: https://paloaltonetworks.okta.com/home/\[APP_NAME\]/\[APP_ID\]. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Maximum number of events per fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberarkepm-get-events

***
Gets events from Cyber Ark EPM.

#### Base Command

`cyberarkepm-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

There is no context output for this command.
