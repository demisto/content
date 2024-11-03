Palo Alto Networks Symantec Endpoint Security Event Collector integration for Cortex XSIAM.

## Configure Symantec Endpoint Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Endpoint Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Token | True |
    | Stream ID | True |
    | Channel ID | True |
    | Fetch interval in seconds | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.


### To generate a token for the ***Token*** parameter:

1. Login to your Symantec Endpoint Security console.
2. Press Integration > Client Applications.
3. Choose `Add Client Application`.
4. Choose a name for the application, then click `Add`. The client application details screen will show.
5. Select any privileges for your client application. Press Save.
6. Press the ellipsis and select Client Secret.
7. Click the `copy` icon next to `OAuth Credentials`.
8. Paste the OAuth Credentials value into the `Token` field.
