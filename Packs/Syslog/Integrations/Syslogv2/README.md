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
    | Port mapping | The listening port to receive Syslog message on (`<port> or <host port>:<docker port>`) | True |
    | Certificate (Required for HTTPS) | Required for HTTPS if not using server rerouting | False |
    | Private Key (Required for HTTPS) | Required for HTTPS if not using server rerouting | False |
    | Message Regex Filter For Incidents Creation | Creates an incident in Cortex XSOAR for every received log message that matches this regex. | False |

4. Click **Test** to validate the connection.

## Troubleshooting
To receive incidents, the Syslog engine listens on a configured port that needs to be available for outside in-coming traffic. There may be cases that docker is configured not to expose the port for outside in-comming traffic. In this case, you can choose to use the host networking and not the docker based networking. Enable host networking usage by adding the following advanced Server configuration:
* Name: `python.pass.extra.keys.demisto/syslog`
* Value: `--network=host`

If listening on a port less than 1024 and running with the Docker Hardening configuration, you may need to disable the "run with non-root internal user" setting for the Syslog integration, inorder to listen on the host networking on a lower port. From more info see: [Run Docker with Non-Root Internal User](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-6/cortex-xsoar-admin/docker/docker-hardening-guide/run-docker-with-non-root-internal-users) and the [Docker Hardening Guide](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-6/cortex-xsoar-admin/docker/docker-hardening-guide.html). You can disable this setting by adding the following advanced Server settings:
* Name: `docker.run.internal.asuser.ignore`
* Value: `demisto/syslog`

If the integration is running via an Engine, you will need to add this settings to the Engine configuration either via the `d1.conf` file or in the Server Ui at `Settings->Engines->Configuration`.
