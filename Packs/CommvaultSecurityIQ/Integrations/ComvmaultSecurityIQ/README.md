Commvault Security IQ provides pre-built integrations, automation workflows, and playbooks to streamline operations, enhance threat intelligence integration, and gain actionable insights through advanced reporting and analytics.
## Configure Commvault Security IQ on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Commvault Security IQ.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Long running instance | False |
    | Commvault Webservice Url | True |
    | Commvault API Token | True |
    | Azure KeyVault Url | False |
    | Azure KeyVault Tenant ID | False |
    | Azure KeyVault Client ID | False |
    | Azure KeyVault Client Secret | False |
    | Port mapping (&lt;port&gt; or &lt;host port&gt;:&lt;docker port&gt;) | False |
    | Incident type | False |
    | Fetch incidents | False |
    | Incidents Fetch Interval | False |
    | Forwarding Rule | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### disable-data-aging

***
Disables data aging on CS

#### Base Command

`disable-data-aging`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### generate_token

***
Generate Token

#### Base Command

`generate_token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### disable-saml-provider

***
Disable SAML provider

#### Base Command

`disable-saml-provider`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### copy-files-list-to-war-room

***
Copy the list of affected files list to war room

#### Base Command

`copy-files-list-to-war-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.