# Configure Syslog in Cortex XSOAR
- **Important**: Make sure to not use engine group for this integration. As it can cause the integration to run on different engine, meaning the Syslog server might send logs to an IP whom Syslog might not be configured at.
- Configure a Syslog server to send it's logs to the Cortex XSOAR machine running the Syslog V2 integration.
- Configure the Syslog format sent from Syslog server in Syslog v2 integration.
 
