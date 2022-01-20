A Syslog server enables automatically opening incidents from Syslog clients. This integration supports filtering logs to convert to incidents, or alternately converting all logs.
This integration was integrated and tested with RFC3164 and RFC5424 formats of Syslog.
## Notes
- **Important**: Supported log formats: RFC3164, RFC5424, RFC6587 (with RFC3164 or RFC5424)
- **Important**: Make sure not to use an engine group for this integration. It can cause the integration to run on a different engine, and the Syslog server may send logs to an IP for which Syslog is not configured.
- The integration **does not support** encrypted private keys.
## Configure Syslog v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Syslog v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Certificate (Required for HTTPS) | Required for HTTPS if not using server rerouting | False |
    | Private Key (Required for HTTPS) | Required for HTTPS if not using server rerouting | False |
    | Message Regex Filter For Incidents Creation | Creates an incident in Cortex XSOAR for every received log message that matches this regex. | False |

4. Click **Test** to validate the connection.
