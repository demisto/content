Sends a Duo push notification with additional context via the pushinfo parameter. Must have access to the auth api in order to use this.
## Configure DuoAuth (Community Contribution) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DuoAuth (Community Contribution).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | API Hostname | True |
    | Integration Key | True |
    | Secret Key | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### duoauth-push-notification

***
Send push message to Duo user.

#### Base Command

`duoauth-push-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Insert username. | Required | 
| pushinfo | A set of URL-encoded key/value pairs with additional contextual information associated with this authentication attempt. The Duo Mobile app will display this information to the user. For example: from=login%20portal&amp;domain=example.com, The URL-encoded string's total length must be less than 20,000 bytes. | Optional | 
| type | This string is displayed in the Duo Mobile app push notification and UI. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAuth.Status | String | Status of a Push message | 
| DuoAuth.Message | String | E.g. if approved, "Success. Logging you in…" | 
| DuoAuth.User | String | Username receiving Push message | 
