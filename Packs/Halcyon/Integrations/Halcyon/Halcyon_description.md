## Halcyon

Use this integration to fetch alerts and events from the Halcyon device management platform.

### Authentication

To configure this integration, you need:
1. **Username**: Your Halcyon account username
2. **Password**: Your Halcyon account password

The integration uses the Halcyon Login API to authenticate and automatically handles token refresh when needed.

### Configuration Steps

1. Obtain your Halcyon account credentials from your Halcyon administrator.
2. In Cortex XSIAM, navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
3. Search for **Halcyon** and click **Add instance**.
4. Enter the Server URL (default: https://api.halcyon.ai).
5. Enter your Username and Password.
6. Select the log types you want to fetch (Alerts, Events, or both).
7. Configure the maximum number of events per fetch for each log type.
8. Click **Test** to verify the connection.
9. Enable **Fetch events** to start collecting data.

### Log Types

- **Alerts**: Security alerts including threat detections and policy violations
- **Events**: General activity logs from the Halcyon platform
