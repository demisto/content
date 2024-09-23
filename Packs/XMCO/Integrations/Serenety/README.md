XMCO Serenety


## Configure XMCO Serenety on Cortex XSOAR
To configure an instance of XMCO Serenety integration in Cortex XSOAR:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Abnormal Security.
3. Click **Add instance** to create and configure a new integration instance.


| **Parameter**                               | **Required** |
    |---------------------------------------------| ------------ |
| Server URL (e.g. https://leportail.xmco.fr) | True         |
| API Key                                     | True         |
| Trust any certificate (not secure)          | False        |
| Use system proxy settings                   | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### fetch-incidents

---

Fetch the Serenety lerts from XMCO LePortail

#### Base Command

`fetch-incidents`

#### Input

| **Argument Name** | **Description**                                 | **Required** |
|-------------------|-------------------------------------------------| ------------ |
| scope             | A string representing the scope id to filter on | Optional     |

#### Command Example

`!fetch-incidents`
`!fetch-incidents scope=123456789`