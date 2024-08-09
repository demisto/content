_____
## Jamf Protect Event Collector
_____
Use this integration to fetch audit logs, alerts and computer events from Jamf Protect as events in Cortex XSIAM.
_____
## Creating an API Client in Jamf Protect
Before you configure the integration, retrieve the API Client and Password from your Jamf Protect environment:
1. In Jamf Protect, click **Administrative** > **API Clients**.
2. Click **Create API Client**.
3. Enter a name for your API client.
4. Assign the Full Access role to the API client.
5. Copy the API client password for later use.
    Your API client configuration and endpoint information displays.
6. Copy the API client and password into the integration configuration.

# Notes:
    You can assign a custom role that limits permissions by editing the API client.
    The minimum required permissions are:
    - Read access Computers.
    - Read access Alert endpoints.    
    - Read access Audit Logs.
For more information refer to Jamf Protect [Documentation](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Jamf_Protect_API.html).