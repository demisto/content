Integrate Retarus Secure Email Gateway to seamlessly fetch events and enhance email security.

## Configure RetarusSecureEmailGateway Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RetarusSecureEmailGateway.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** | **Description** |
    | --- | --- | --- |
    | Server URL | True | |
    | Token ID | True | |
    | Channel name | False | The channel to fetch events from |
    | Fetch interval in seconds | True | |
    | Trust any certificate (not secure) | False | |

5. No test button option available due to API limitation. Save the configured instance to test the connection. If you encounter an 'Authentication failed' error, check your configuration.

### Troubleshooting

## Integration issues
If you encounter any issues with this integration, follow these steps to troubleshoot:

Run the retarus-get-last-run-results command to obtain detailed information about the errors and problems you are facing. This command provides insights into the last execution of the integration and helps you understand the root cause of the issues.

If you receive an HTTP 400 or HTTP 401 status code when running the command, verify the token provided in the instance configuration.

When opening a support case, include the results you obtained from running the retarus-get-last-run-results command.

## Only one instance can be configured on the same token and channel
Due to the Retarus API limitation, only one instance can be configured for each token and channel. It is important to note that while two instances with the same token but different channels are allowed, configuring two instances with the same token and channel may result in encountering errors and/or missing events. 