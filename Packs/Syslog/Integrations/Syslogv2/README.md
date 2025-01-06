A Syslog server enables opening incidents automatically from Syslog clients. This integration supports converting to incidents, filtered logs or all logs.

This integration is a long-running integration. For more information about long-running integrations, see the [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations), [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) or [Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) documentation.

This integration was integrated and tested with RFC3164 and RFC5424 formats of Syslog.

## Notes
- **Important**: Supported log formats: RFC3164, RFC5424, RFC6587 (with RFC3164 or RFC5424)
- **Important**: Do not use an engine group for this integration. It can cause the integration to run on a different engine, and the Syslog server may send logs to an IP for which Syslog is not configured.
- The integration **does not support** encrypted private keys.
## Configure Syslog v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Port mapping | The listening port to receive Syslog message on (`<port> or <host port>:<docker port>`). Port 6514 is the default when using TLS. | True |
| Certificate | Required for TLS | False |
| Private Key | Required for TLS | False |
| Message Regex Filter For Incidents Creation | Creates an incident in Cortex XSOAR for every received log message that matches this regex. | False |


## Troubleshooting
To receive incidents, the Syslog engine listens on a configured port that needs to be available for external in-coming traffic. There may be cases that docker is configured not to expose the port for external in-comming traffic. In this case, you can use host networking and not the docker based networking. Enable host networking usage by adding the following server configuration (Settings > About > Troubleshooting > Add Server Configuration):
* Key: `python.pass.extra.keys.demisto/syslog`
* Value: `--network=host`

If listening on a port less than 1024 and running with the Docker Hardening configuration, you may need to disable the "run with non-root internal user" setting for the Syslog integration to listen on the host networking on a lower port. From more information, see: [Run Docker with Non Root Internal Users (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users) or [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) You can disable this setting by adding the following server configuration:
* Key: `docker.run.internal.asuser.ignore`
* Value: `demisto/syslog`

If the integration is running via an engine, you need to add this setting to the engine configuration either via the `d1.conf` file or in the Server `Settings->Engines-> Edit Configuration`.