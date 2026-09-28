## Akamai Event Viewer

Collects Control Center portal-visible events from the Akamai Event Logger system.

### Authentication

The integration uses Akamai EdgeGrid authentication. To create API credentials:

1. In Akamai Control Center, go to **Identity & Access Management** > **API clients**.
2. Create an API client with access to the **Event Viewer** API.
3. Copy the **host**, **client token**, **access token**, and **client secret** into the integration instance.

### Notes

- Enter only the host in **Server URL**. The `/event-viewer-api/v1` base path is appended automatically.
- The first fetch collects events from the last minute.
- Event times are sent to the API in UTC.

For more information, see the [Akamai Event Viewer API documentation](https://techdocs.akamai.com/event-viewer/reference/api-get-started).