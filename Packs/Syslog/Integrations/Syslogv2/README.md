A Syslog server provides the ability to automatically open incidents from Syslog clients. This integration provides the ability to filter which logs are to be converted to incidents (or choose to convert all logs).
This integration was integrated and tested with RFC3164 and RFC5424 formats of Syslog.
## Notes
- **Important**: Make sure not to use an engine group for this integration, as it can cause the integration to run on a different engine, meaning the Syslog server might send logs to an IP at which Syslog is not configured.
- The integration **does not support** encrypted private keys.
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

4. Click **Test** to validate the connection.