## Jumpcloud

### Creating an API Key

1. **Log in to JumpCloud Admin Console**: Navigate to [https://console.jumpcloud.com](https://console.jumpcloud.com).
2. **Access API Settings**: Click on your user icon in the top-right corner and select **API Settings**.
3. **Generate API Key**: Click **Generate New API Key** and copy the key securely.
4. **Configure the Integration**: Paste the API key into the **API Key** field in the integration configuration.

### Event Types

The integration supports fetching the following event types from JumpCloud Directory Insights:

- **Directory Events**: User, group, and directory-related events.
- **System Events**: System and device-related events.
- **Alert Events**: Security alert events.
- **Object Storage Events**: Object storage access and modification events.

### Fetch Event Filter

Use the **Fetch event filter** parameter to select which event types to fetch. If set to "all" or left empty, all event types will be fetched.
