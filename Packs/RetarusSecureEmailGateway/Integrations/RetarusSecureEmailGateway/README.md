Integrate Retarus Secure Email Gateway to seamlessly fetch events and enhance email security.

## Configure RetarusSecureEmailGateway Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Retarus.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** | **Description** |
    | --- | --- | --- |
    | Server URL | True | |
    | Token ID | True | |
    | Channel name | False | The channel to fetch events from. In Retarus, a channel name represents a specific configuration or processing pipeline used to manage email traffic based on criteria like sender, recipient, domain, or metadata, enabling tailored routing, filtering, compliance, and logging rules.|
    | Fetch interval in seconds | True | |
    | Trust any certificate (not secure) | False | |

### Troubleshooting

If you encounter any issues with this integration, follow these steps to troubleshoot:
Run the retarus-get-last-run-results command to obtain detailed information about the errors and problems you are facing. This command provides insights into the last execution of the integration and helps you understand the root cause of the issues.
If you receive an HTTP 400 or HTTP 401 status code when running the command, verify the token provided in the instance configuration.

When opening a support case, include the results you obtained from running the retarus-get-last-run-results command.

Note, due to the Retarus API limitation, only one instance can be configured for each token and channel. It is important to note that while two instances with the same token but different channels are allowed, configuring two instances with the same token and channel may result in errors and/or missing events. 
