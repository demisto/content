## KELA Brand Control

### How to get your API token

1. Log in to the KELA platform.
2. Open the **system menu** and go to the API token section to generate a token.
3. Paste it in the **API Token** field of this instance (the Username field is not used).

The token is sent to the API as the `apiToken` URL parameter and is never logged by this integration.

### Workspace ID

Enter the ID of the Brand Control workspace to connect to. It is mandatory. You can enter several workspaces separated by commas. You can only access workspaces owned by, or shared with, your group.

### Limits

The API allows 1 request per second. Going over it returns HTTP 429; the integration spaces its requests and retries automatically.
