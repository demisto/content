
FortiAuthenticator provides centralized authentication services. 
Seamless secure two-factor/OTP authentication across the organization in conjunction with FortiToken.

## Enable API Access for admin user on FortiAuthenticator
### Steps to get the ***Access Key*** for the API authentication
#### On the FortiAuthenticator WebUI, create a new user for API or edit an existing one. 
Under the **Authentication** > **User Management**, edit the user: 
1. Under **User Role**, select **Administrator**.
2. Enable **Web service access**.
3. Under **User Information**, please ensure there's  a valid **email** address.
4. Click **OK** to save the details.
5. The **Web Service Access Secret Key** used to authenticate to the API is emailed to the user.
#### Note
Ensure email routing is working (i.e. the FortiAuthenticator is able to send mail) beforehand as the API Key will be delivered by email.

![Setup Account](./fauthenableapiaccess.png)
![Setup Account](./fauthaccesskeyemail.png)



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

### FortiAuthenticator-get-user
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The user's email that defined in the User Information on FortiAuthenticator | Required | 
| user_type | The user type:  localusers (Local Users), ldapuser (Remote Users) | Required | 

### FortiAuthenticator-update-user
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The user's email that defined in the User Information on FortiAuthenticator | Required | 
| user_type | The user type:  localusers (Local Users), ldapuser (Remote Users) | Required | 
| active | Define user's active status:  false = Disabled, true = enabled | Required | 

#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiAuthenticator.user | Unknown | The user information | 
| FortiAuthenticator.user.active | Unknown | The user's active status (true = enabled, false = disabled) | 
| FortiAuthenticator.user.email | Unknown | The user's email address | 
| FortiAuthenticator.user.id | Unknown | The user's id on FortiAuthenticator | 
| FortiAuthenticator.user.username | Unknown | The user's username | 


#### Command Example
```!FortiAuthenticator-get-user user_type=localusers email=jasonlo@jasonlo.net```

#### Context Example
```json
{
    "FortiAuthenticator": {
        "user": {
            "active": "true",
            "email": "test_user@example.com",
            "id": "7",
            "username: "test_user"
        }
    }
}
```

#### Human Readable Output

### FortiAuthenticator User Info
|id|username|email|active|
|---|---|---|---|
| 7 | test_user | test_user@example.com | true |



#### Command Example
```!FortiAuthenticator-update-user active=false user_type=localusers email=jasonlo@jasonlo.net```

#### Context Example
```json
{
    "FortiAuthenticator": {
        "user": {
            "active": "false",
            "email": "test_user@example.com",
            "id": "7",
            "username: "test_user"
        }
    }
}
```

#### Human Readable Output

### FortiAuthenticator User Info
|id|username|email|active|
|---|---|---|---|
| 7 | test_user | test_user@example.com | false |





