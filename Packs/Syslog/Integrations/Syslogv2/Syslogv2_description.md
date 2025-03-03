## Configure Syslog in Cortex XSOAR
- Configure a Syslog server to send its logs to the Cortex XSOAR machine running the Syslog v2 integration.
- To create incidents from specific messages, use the **Message Regex** parameter to create incidents only for logs matching the given regex. If no message regex is specified, an incident is created for each received Syslog message.
## Notes
- **Important**: Do not use an engine group for this integration. It can cause the integration to run on a different engine, and the Syslog server may send logs to an IP for which Syslog is not configured.
- **Important**: Only TCP/TLS is supported. UDP is not supported.
- **Important**: Supported log formats: RFC3164, RFC5424, RFC6587 (with RFC3164 or RFC5424)
- The integration **does not support** encrypted private keys.

For more information about long-running integrations, check out the <~XSIAM>[Forward requests to long-running integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) article.</~XSIAM> <~XSOAR_SAAS>Forward Requests to Long-Running Integrations article: [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations) or [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) documentation.</~XSOAR_SAAS>
