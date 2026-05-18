## Contrast Security Help

To use this integration, webhook integration credentials from Contrast Security are required when the integration is configured as a long-running instance. Also, an event type needs to be selected to fetch from Contrast Security.

### Authorization

The Contrast Security username, API key, service key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon.

### Instance Configuration

1. Configure a Contrast Security integration instance with valid credentials.
2. Click **Test** to validate the connection between XSOAR and the Contrast Security platform.
3. To fetch events from Contrast Security, select the event type from the dropdown and configure the parameters below. Note: The following parameters are required after enabling **Long Running Instance**: Listening Port, Webhook Username, Webhook Password, and Event Type.
4. The Contrast Security username, service key, API key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon. These credentials are used to establish connectivity between the Contrast Security REST API and XSOAR.

### Contrast Security Webhook configuration

1. To configure a Contrast Security webhook integration, go to **Administration** > **Integrations** > **Palo Alto Networks Cortex XSOAR** in the Contrast Security platform.
2. Enter the webhook URL provided by XSOAR. For XSOAR 8, use the result link URL displayed in the integration instance.
3. Enter the username and password credentials.
4. Click **Test** to validate the connection between XSOAR and the Contrast Security platform.

The following table provides detailed information about each configuration parameter of the integration instance:

| **Parameter** | **Description** |
| --- | --- |
| Long running instance | Enable the integration to run as a long-running service for webhook events. Default: false. |
| Listening Port | The port on which the integration listens for incoming webhook events. Note: This field only appears in Cortex XSOAR 8 and Cortex XSIAM if you are using an engine. It always appears in Cortex 6.x.|
| Webhook Username | The username for authenticating webhook requests. |
| Webhook Password | The password for authenticating webhook requests. |
| Event Type | Select event type to fetch from Contrast Security platform. Contrast Security recommends selecting "Contrast Incident" as the event type to fetch via webhook. <br/>Supported values: Contrast Incident, Contrast Issue. |
| Contrast Security Server URL | Server URL of the Contrast Security platform. Required. |
| Contrast Security Username (Email) | Username used for Contrast Security platform. Email address is used as the username. |
| Contrast Security Service Key | Service key used for Contrast Security platform authentication. |
| Contrast Security API Key | API key used for secure communication with Contrast Security platform. |
| Contrast Security Organization ID | The organization ID used for the Contrast Security platform. |
| Certificate (Required for HTTPS) | (For Cortex XSOAR 6.x) For use with HTTPS - the certificate that the service should use. (For Cortex XSOAR 8 and Cortex XSIAM) Custom certificates are not supported. |
| Private Key (Required for HTTPS) | (For Cortex XSOAR 6.x) For use with HTTPS - the private key that the service should use. (For Cortex XSOAR 8 and Cortex XSIAM) When using an engine, configure a private API key. Not supported on the Cortex XSOAR or Cortex XSIAM server. |
| Incident Mirroring Direction | The mirroring direction in which to mirror the incident details. |
| Issue Mirroring Direction | The mirroring direction in which to mirror the Issue details. |
| Mirror Tag for Notes | Tag value used to mirror XSOAR notes back to Contrast Security as issue or incident comments. |
| Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident | If selected, closed incidents will be reopened in XSOAR when the incident status in Contrast Security incident changes to 'Open'.<br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. |
| Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident | If selected, active incidents will be closed in XSOAR when the incident status in Contrast Security incident changes to 'Closed'.<br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. |
| Store sample events for mapping | Store sample events for mapping. |
| Trust any certificate (not secure) | Trust any certificate, including self-signed certificates. Not recommended for production environments. |
| Use system proxy settings | Use system proxy settings for network communication. |

### Contrast Security Long Running Instance Configuration

To configure the Contrast Security long running instance:

#### Cortex XSOAR 6.x

To configure a long running integration instance:

- **HTTP Configuration:** Configure a long running port for the long running server.

- **HTTPS Configuration:** In addition to HTTP, configure a certificate and private key for secure communication.

- **Server Configuration Verification:**
  - Navigate to **Settings > About > Troubleshooting**.
  - In the Server Configuration section, verify that `instance.execute.external.<INTEGRATION-INSTANCE-NAME>` is set to `true`.
  - If this key does not exist, click **+ Add Server Configuration** and:
    - Add the key: `instance.execute.external.<INTEGRATION-INSTANCE-NAME>`
    - Set the value to: `true`

**Webhook URL Options:**

- Direct port-based access: `https://<CORTEX-XSOAR-URL>:<LISTEN_PORT>/`

- Instance execution endpoint: `https://<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`

For more general information on long running integrations on XSOAR6:
[XSOAR 6 Long Running Integrations](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke)

#### Cortex XSOAR 8/XSIAM

To configure a long running integration instance:

- The instance should be configured to run over **HTTP internally**.  
- HTTPS is automatically handled using the server’s certificate in XSOAR 8 / XSIAM.  
- Configure authentication using a **webhook username and webhook password**.  
- The **Long Running Port** field appears in Cortex XSOAR 8 and XSIAM only when using an engine.  

**Webhook URL:**

`https://ext-<CORTEX-TENANT-URL>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`

For more general information on long running integrations on XSOAR8:
[XSOAR 8 / XSIAM Long Running Integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations)

#### Notes

- The integration instance name must not contain special characters.    
