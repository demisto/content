A Syslog server provides the ability to automatically open incidents from Syslog clients. This integration provides the ability to filter which logs are to be converted to incidents (or choose to convert all logs).

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-syslog-v2).

## Configure Syslog v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Syslog v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Certificate (Required for HTTPS) | Required for HTTPS, if not using server rerouting | False |
    | Private Key (Required for HTTPS) | Required for HTTPS, if not using server rerouting | False |
    | Incoming Log Format | The format of the received logs from Syslog server | True |
    | Message Regex Filter For Incidents Creation. | Will create an incident in Cortex XSOAR for every received log message that matches this regex. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
