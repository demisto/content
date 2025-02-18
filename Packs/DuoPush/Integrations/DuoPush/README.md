Sends a Duo push notification with additional context via the pushinfo parameter. Must have access to the auth api in order to use this.
This integration was integrated and tested with version xx of DuoAuth.

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

### duo-auth

***
Send push message to Duo user.

#### Base Command

`duo-auth`

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

#### Command example
```!duo-auth username=xsoartest pushinfo=Message=Confirm!```
#### Context Example
```json
{
    "DuoAuth": {
        "Message": "Success. Logging you in...",
        "Status": "allow",
        "User": "xsoartest"
    }
}
```

#### Human Readable Output

>### Duo Push Result
>**User**: xsoartest
>**Status**: allow
>**Message**: Success. Logging you in...
