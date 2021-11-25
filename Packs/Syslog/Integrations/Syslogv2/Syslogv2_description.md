## Configure Syslog in Cortex XSOAR
- Configure a Syslog server to send its logs to the Cortex XSOAR machine that runs Syslog v2 integration.
- To create incidents from specific messages, use the **Message Regex** parameter to create incidents only for logs match the given regex. If no message regex is given, an incident will be created for each received Syslog message.
## Notes
- **Important**: Make sure not to use an engine group for this integration, as it can cause the integration to run on a different engine, meaning the Syslog server might send logs to an IP at which Syslog is not configured.
- **Important**: Only TCP/TLS is supported. UDP is not supported.
- **Important**: Supported log formats: RFC3164, RFC5424, RFC6587 (with RFC3164 or RFC5424)
- The integration **does not support** encrypted private keys.