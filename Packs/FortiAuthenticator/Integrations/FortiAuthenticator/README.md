
FortiAuthenticator provides centralized authentication services. 
Seamless secure two-factor/OTP authentication across the organization in conjunction with FortiToken.

This integration was integrated and tested with versions 4.0 - 6.3.0 of FortiAuthenticator.

## Enable API Access for admin user on FortiAuthenticator
### Steps to get the ***Access Key*** for the API authentication
** Note: Ensure email routing is working (i.e. the FortiAuthenticator is able to send mail) beforehand as the API Key will be delivered by email.
#### On the FortiAuthenticator WebUI, create a new user for API or edit an existing one. 
Under the **Authentication** > **User Management**, edit the user: 
1. Under **User Role**, select **Administrator**.
2. Enable **Web service access**.
3. Under **User Information**, please ensure there's  a valid **email** address.
4. Click **OK** to save the details.
5. The **Web Service Access Secret Key** used to authenticate to the API is emailed to the user.


## Supported user types:
- Local Users
- LDAP Users



## Configure FortiAuthenticator on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FortiAuthenticator.
3. Click **Add instance** to create and configure a new integration instance.
    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | server_url | Server URL | True |
    | credentials | Username | True |
    | credentials | Access Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
4. Click **Test** to validate the URLs, credentials, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fortiauthenticator-get-user

#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_type | The user type:  localusers (Local Users), ldapuser (Remote Users) | Required | 
| email | The user's email that is defined in the User Information on FortiAuthenticator | Optional | 
| username | The username that is defined in the User Information on FortiAuthenticator | Optional | 
| token_serial | The serial no. of the assigned Token on FortiAuthenticator | Optional | 
- Note: You need either an email, username, or token_serial input in order for the command to work.

#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiAuthenticator.user | Unknown | The user information | 
| FortiAuthenticator.user.id | Unknown | The user's id on FortiAuthenticator | 
| FortiAuthenticator.user.username | Unknown | The user's username | 
| FortiAuthenticator.user.email | Unknown | The user's email address | 
| FortiAuthenticator.user.active | Unknown | The user's active status (true = enabled, false = disabled) | 
| FortiAuthenticator.user.token_auth | Unknown | The token auth status | 
| FortiAuthenticator.user.token_type | Unknown | The token type | 
| FortiAuthenticator.user.token_serial | Unknown | The token serial number | 


#### Command Example
```!fortiauthenticator-get-user user_type=localusers email=test_user@example.com```

#### Context Example
```json
{
    "FortiAuthenticator": {
        "user": {
            "active": "true",
            "email": "test_user@example.com",
            "id": "7",
            "username": "test_user",
            "token_auth": "true",
            "token_type": "ftm",
            "token_serial": "FTKMOB123456789A"

        }
    }
}
```

#### Human Readable Output

### FortiAuthenticator User Info
|id|username|email|active|token_auth|token_type|token_serial|
|---|---|---|---|---|---|---|
| 7 | test_user | test_user@example.com | true | true | ftm | FTKMOB123456789A |

### fortiauthenticator-update-user
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_type | The user type:  localusers (Local Users), ldapuser (Remote Users) | Required | 
| email | The user's email that is defined in the User Information on FortiAuthenticator | Optional | 
| username | The username that is defined in the User Information on FortiAuthenticator | Optional | 
| active | Define user's active status:  false = Disabled, true = enabled | Required | 
- Note: You need either an email or username input in order for the command to work.

#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiAuthenticator.user | Unknown | The user information | 
| FortiAuthenticator.user.id | Unknown | The user's id on FortiAuthenticator | 
| FortiAuthenticator.user.username | Unknown | The user's username | 
| FortiAuthenticator.user.email | Unknown | The user's email address | 
| FortiAuthenticator.user.active | Unknown | The user's active status (true = enabled, false = disabled) | 
| FortiAuthenticator.user.token_auth | Unknown | The token auth status | 
| FortiAuthenticator.user.token_type | Unknown | The token type | 
| FortiAuthenticator.user.token_serial | Unknown | The token serial number | 

#### Command Example
```!fortiauthenticator-update-user active=false user_type=localusers email=test_user@example.com```

#### Context Example
```json
{
    "FortiAuthenticator": {
        "user": {
            "active": "false",
            "email": "test_user@example.com",
            "id": "7",
            "username": "test_user",
            "token_auth": "true",
            "token_type": "ftm",
            "token_auth": "FTKMOB123456789A"
        }
    }
}
```

#### Human Readable Output

### Updated FortiAuthenticator User Info
|id|username|email|active|token_auth|token_type|token_serial|
|---|---|---|---|---|---|---|
| 7 | test_user | test_user@example.com | false | true | ftm | FTKMOB123456789A |





