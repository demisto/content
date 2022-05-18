## Configure Syslog in Cortex XSOAR
- Configure a Syslog server to send its logs to the Cortex XSOAR machine running the Syslog v2 integration.
- To create incidents from specific messages, use the **Message Regex** parameter to create incidents only for logs matching the given regex. If no message regex is specified, an incident is created for each received Syslog message.
## Notes
- **Important**: Do not use an engine group for this integration. It can cause the integration to run on a different engine, and the Syslog server may send logs to an IP for which Syslog is not configured.
- **Important**: Only TCP/TLS is supported. UDP is not supported.
- **Important**: Supported log formats: RFC3164, RFC5424, RFC6587 (with RFC3164 or RFC5424)
- The integration **does not support** encrypted private keys.
