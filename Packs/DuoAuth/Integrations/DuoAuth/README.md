The Duo Auth API lets developers integrate with Duo Security's platform at a low level.

## Configure DuoAuth in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| API Hostname | True |
| Integration Key | True |
| Secret Key | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| DuoAuth.PushNotification.Status | String | Status of a Push message. | 
| DuoAuth.PushNotification.Message | String | E.g. if approved, "Success. Logging you in…". | 
| DuoAuth.PushNotification.User | String | Username receiving Push message. | 
